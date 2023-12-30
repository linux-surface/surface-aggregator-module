// SPDX-License-Identifier: GPL-2.0+
/*
 * Thermal sensor subsystem driver for Surface System Aggregator Module (SSAM).
 *
 * Copyright (C) 2022-2023 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/bitops.h>
#include <linux/hwmon.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include "../../include/linux/surface_aggregator/controller.h"
#include "../../include/linux/surface_aggregator/device.h"


/* -- SAM interface. -------------------------------------------------------- */

SSAM_DEFINE_SYNC_REQUEST_R(__ssam_tmp_get_available_sensors, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.target_id       = SSAM_SSH_TID_SAM,
	.command_id      = 0x04,
	.instance_id     = 0x00,
});

SSAM_DEFINE_SYNC_REQUEST_MD_R(__ssam_tmp_get_temperature, __le16, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x01,
});

/*
 * Available sensors are indicated by a 16-bit bitfield, where a 1 marks the
 * presence of a sensor. So we have at most 16 possible sensors/channels.
 */
#define SSAM_TMP_SENSOR_MAX_COUNT 16

/*
 * All names observed so far are 6 characters long, but there's only
 * zeros after the name, so perhaps they can be longer. This number reflects
 * the maximum zero-padded space observed in the returned buffer.
 */
#define SSAM_TMP_SENSOR_NAME_LENGTH 18

struct ssam_tmp_get_name {
	__le16 unknown1;
	char unknown2;
	char name[SSAM_TMP_SENSOR_NAME_LENGTH];
} __packed;

SSAM_DEFINE_SYNC_REQUEST_MD_R(__ssam_tmp_get_name, struct ssam_tmp_get_name, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x0e,
});

static int ssam_tmp_get_available_sensors(struct ssam_device *sdev, s16 *sensors)
{
	__le16 sensors_le;
	int status;

	status = __ssam_tmp_get_available_sensors(sdev->ctrl, &sensors_le);
	if (status)
		return status;

	*sensors = le16_to_cpu(sensors_le);
	return 0;
}

static int ssam_tmp_get_temperature(struct ssam_device *sdev, u8 iid, long *temperature)
{
	__le16 temp_le;
	int status;

	status = __ssam_tmp_get_temperature(sdev->ctrl, sdev->uid.target, iid, &temp_le);
	if (status)
		return status;

	/* Convert 1/10 °K to 1/1000 °C */
	*temperature = (le16_to_cpu(temp_le) - 2731) * 100L;
	return 0;
}


/* -- Driver.---------------------------------------------------------------- */

struct ssam_temp {
	struct ssam_device *sdev;
	s16 sensors;
	char names[SSAM_TMP_SENSOR_MAX_COUNT][SSAM_TMP_SENSOR_NAME_LENGTH];
};

static umode_t ssam_temp_hwmon_is_visible(const void *data,
					  enum hwmon_sensor_types type,
					  u32 attr, int channel)
{
	const struct ssam_temp *ssam_temp = data;

	if (type != hwmon_temp)
		return 0;

	switch (attr) {
	case hwmon_temp_input:
	case hwmon_temp_label:
		if (ssam_temp->sensors & BIT(channel))
			return  0444;
		else
			return 0;
	default:
		return 0;
	}
}

static int ssam_temp_hwmon_read(struct device *dev,
				enum hwmon_sensor_types type,
				u32 attr, int channel, long *value)
{
	const struct ssam_temp *ssam_temp = dev_get_drvdata(dev);

	if (type != hwmon_temp)
		return -EOPNOTSUPP;

	if (!(ssam_temp->sensors & BIT(channel)))
		return -EOPNOTSUPP;

	if (attr != hwmon_temp_input)
		return -EOPNOTSUPP;

	return ssam_tmp_get_temperature(ssam_temp->sdev, channel + 1, value);
}

static int ssam_temp_hwmon_read_string(struct device *dev,
				       enum hwmon_sensor_types type,
				       u32 attr, int channel, const char **str)
{
	const struct ssam_temp *ssam_temp = dev_get_drvdata(dev);

	if (type != hwmon_temp)
		return -EOPNOTSUPP;

	if (!(ssam_temp->sensors & BIT(channel)))
		return -EOPNOTSUPP;

	if (attr != hwmon_temp_label)
		return -EOPNOTSUPP;

	*str = ssam_temp->names[channel];

	return 0;
}

static const struct hwmon_channel_info * const ssam_temp_hwmon_info[] = {
	HWMON_CHANNEL_INFO(chip,
			   HWMON_C_REGISTER_TZ),
	/* We have at most 16 thermal sensors. */
	HWMON_CHANNEL_INFO(temp,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL),
	NULL
};

static const struct hwmon_ops ssam_temp_hwmon_ops = {
	.is_visible = ssam_temp_hwmon_is_visible,
	.read = ssam_temp_hwmon_read,
	.read_string = ssam_temp_hwmon_read_string,
};

static const struct hwmon_chip_info ssam_temp_hwmon_chip_info = {
	.ops = &ssam_temp_hwmon_ops,
	.info = ssam_temp_hwmon_info,
};

static int ssam_temp_probe(struct ssam_device *sdev)
{
	struct ssam_temp *ssam_temp;
	struct device *hwmon_dev;
	s16 sensors;
	int channel;
	struct ssam_tmp_get_name name_resp;
	int status;

	status = ssam_tmp_get_available_sensors(sdev, &sensors);
	if (status)
		return status;

	ssam_temp = devm_kzalloc(&sdev->dev, sizeof(*ssam_temp), GFP_KERNEL);
	if (!ssam_temp)
		return -ENOMEM;

	// Retrieve the name for each sensor.
	for (channel = 0; channel < SSAM_TMP_SENSOR_MAX_COUNT; channel++)
	{
		if ((sensors & BIT(channel)) == 0)
			continue;

		status =  ssam_retry(__ssam_tmp_get_name, sdev->ctrl,
				     sdev->uid.target, channel + 1,
				     &name_resp);
		if (status < 0)
			return -EIO;

		// Copy the name in the internal buffer.
		status = strscpy(ssam_temp->names[channel], name_resp.name,
				 SSAM_TMP_SENSOR_NAME_LENGTH);
		WARN_ON(status < 0);
	}

	ssam_temp->sdev = sdev;
	ssam_temp->sensors = sensors;

	hwmon_dev = devm_hwmon_device_register_with_info(&sdev->dev,
			"ssam_temp", ssam_temp, &ssam_temp_hwmon_chip_info,
			NULL);
	if (IS_ERR(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	return 0;
}

static const struct ssam_device_id ssam_temp_match[] = {
	{ SSAM_SDEV(TMP, SAM, 0x00, 0x02) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, ssam_temp_match);

static struct ssam_device_driver ssam_temp = {
	.probe = ssam_temp_probe,
	.match_table = ssam_temp_match,
	.driver = {
		.name = "surface_temp",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(ssam_temp);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Thermal sensor subsystem driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");

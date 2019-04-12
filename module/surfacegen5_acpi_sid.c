#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>

#include "surfacegen5_acpi_ssh.h"


#define SG5_PARAM_PERM		(S_IRUGO | S_IWUSR)


enum sg5_perf_mode {
	SG5_PERF_MODE_NORMAL   = 1,
	SG5_PERF_MODE_BATTERY  = 2,
	SG5_PERF_MODE_PERF1    = 3,
	SG5_PERF_MODE_PERF2    = 4,

	__SG5_PERF_MODE__START = 1,
	__SG5_PERF_MODE__END   = 4,
};

enum sg5_param_perf_mode {
	SG5_PARAM_PERF_MODE_AS_IS    = 0,
	SG5_PARAM_PERF_MODE_NORMAL   = SG5_PERF_MODE_NORMAL,
	SG5_PARAM_PERF_MODE_BATTERY  = SG5_PERF_MODE_BATTERY,
	SG5_PARAM_PERF_MODE_PERF1    = SG5_PERF_MODE_PERF1,
	SG5_PARAM_PERF_MODE_PERF2    = SG5_PERF_MODE_PERF2,

	__SG5_PARAM_PERF_MODE__START = 0,
	__SG5_PARAM_PERF_MODE__END   = 4,
};

struct surface_sid_drvdata {
	struct device_link *ec_link;
};


static int sg5_ec_perf_mode_get(void)
{
	u8 result_buf[8] = { 0 };
	int status;

	struct surfacegen5_rqst rqst = {
		.tc  = 0x03,
		.iid = 0x00,
		.cid = 0x02,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surfacegen5_buf result = {
		.cap = ARRAY_SIZE(result_buf),
		.len = 0,
		.data = result_buf,
	};

	status = surfacegen5_ec_rqst(&rqst, &result);
	if (status) {
		return status;
	}

	if (result.len != 8) {
		return -EFAULT;
	}

	return get_unaligned_le32(&result.data[0]);
}

static int sg5_ec_perf_mode_set(int perf_mode)
{
	u8 payload[4] = { 0 };

	struct surfacegen5_rqst rqst = {
		.tc  = 0x03,
		.iid = 0x00,
		.cid = 0x03,
		.snc = 0x00,
		.cdl = ARRAY_SIZE(payload),
		.pld = payload,
	};

	if (perf_mode < __SG5_PERF_MODE__START || perf_mode > __SG5_PERF_MODE__END) {
		return -EINVAL;
	}

	put_unaligned_le32(perf_mode, &rqst.pld[0]);
	return surfacegen5_ec_rqst(&rqst, NULL);
}


static int param_perf_mode_set(const char *val, const struct kernel_param *kp)
{
	int perf_mode;
	int status;

	status = kstrtoint(val, 0, &perf_mode);
	if (status) {
		return status;
	}

	if (perf_mode < __SG5_PARAM_PERF_MODE__START || perf_mode > __SG5_PARAM_PERF_MODE__END) {
		return -EINVAL;
	}

	return param_set_int(val, kp);
}

static const struct kernel_param_ops param_perf_mode_ops = {
	.set = param_perf_mode_set,
	.get = param_get_int,
};

static int param_perf_mode_init = SG5_PARAM_PERF_MODE_AS_IS;
static int param_perf_mode_exit = SG5_PARAM_PERF_MODE_AS_IS;

module_param_cb(perf_mode_init, &param_perf_mode_ops, &param_perf_mode_init, SG5_PARAM_PERM);
module_param_cb(perf_mode_exit, &param_perf_mode_ops, &param_perf_mode_exit, SG5_PARAM_PERM);

MODULE_PARM_DESC(perf_mode_init, "Performance-mode to be set on module initialization");
MODULE_PARM_DESC(perf_mode_exit, "Performance-mode to be set on module exit");


static ssize_t perf_mode_show(struct device *dev, struct device_attribute *attr, char *data)
{
	int perf_mode;

	perf_mode = sg5_ec_perf_mode_get();
	if (perf_mode < 0) {
		dev_err(dev, "failed to get current performance mode: %d", perf_mode);
		return -EIO;
	}

	return sprintf(data, "%d\n", perf_mode);
}

static ssize_t perf_mode_store(struct device *dev, struct device_attribute *attr,
                               const char *data, size_t count)
{
	int perf_mode;
	int status;

	status = kstrtoint(data, 0, &perf_mode);
	if (status) {
		return status;
	}

	status = sg5_ec_perf_mode_set(perf_mode);
	if (status) {
		return status;
	}

	// TODO: Should we notify ACPI here?
	//
	//       There is a _DSM call described as
	//           WSID._DSM: Notify DPTF on Slider State change
	//       which calls
	//           ODV3 = ToInteger (Arg3)
	//           Notify(IETM, 0x88)
 	//       IETM is an INT3400 Intel Dynamic Power Performance Management
	//       device, part of the DPTF framework. From the corresponding
	//       kernel driver, it looks like event 0x88 is being ignored. Also
	//       it is currently unknown what the consequecnes of setting ODV3
	//       are.

	return count;
}

const static DEVICE_ATTR_RW(perf_mode);


static int surfacegen5_acpi_sid_probe(struct platform_device *pdev)
{
	struct surface_sid_drvdata *drvdata;
	struct device_link *ec_link;
	int status;

	// link to ec
	ec_link = surfacegen5_ec_consumer_add(&pdev->dev, DL_FLAG_PM_RUNTIME);
	if (IS_ERR_OR_NULL(ec_link)) {
		if (PTR_ERR(ec_link) == -ENXIO) {
			// Defer probe if the _SSH driver has not set up the controller yet.
			status = -EPROBE_DEFER;
		} else {
			status = -EFAULT;
		}

		goto err_probe_ec_link;
	}

	// set up driver data
	drvdata = kzalloc(sizeof(struct surface_sid_drvdata), GFP_KERNEL);
	if (!drvdata) {
		status = -ENOMEM;
		goto err_drvdata;
	}
	drvdata->ec_link = ec_link;
	platform_set_drvdata(pdev, drvdata);

	// set initial perf_mode
	if (param_perf_mode_init != SG5_PARAM_PERF_MODE_AS_IS) {
		status = sg5_ec_perf_mode_set(param_perf_mode_init);
		if (status) {
			goto err_set_perf;
		}
	}

	// register perf_mode attribute
	status = sysfs_create_file(&pdev->dev.kobj, &dev_attr_perf_mode.attr);
	if (status) {
		goto err_sysfs;
	}

	return 0;

err_sysfs:
	sg5_ec_perf_mode_set(param_perf_mode_exit);
err_set_perf:
	platform_set_drvdata(pdev, NULL);
	kfree(drvdata);
err_drvdata:
	surfacegen5_ec_consumer_remove(ec_link);
err_probe_ec_link:
	return status;
}

static int surfacegen5_acpi_sid_remove(struct platform_device *pdev)
{
	struct surface_sid_drvdata *drvdata = platform_get_drvdata(pdev);

	// remove perf_mode attribute
	sysfs_remove_file(&pdev->dev.kobj, &dev_attr_perf_mode.attr);

	// set exit perf_mode
	sg5_ec_perf_mode_set(param_perf_mode_exit);

	// remove consumer and clean up
	surfacegen5_ec_consumer_remove(drvdata->ec_link);
	platform_set_drvdata(pdev, NULL);
	kfree(drvdata);

	return 0;
}


static const struct acpi_device_id surfacegen5_acpi_sid_match[] = {
	{ "MSHW0107", 0 },	/* Surface Book 2 */
	{ },
};
MODULE_DEVICE_TABLE(acpi, surfacegen5_acpi_sid_match);

struct platform_driver surfacegen5_acpi_sid = {
	.probe = surfacegen5_acpi_sid_probe,
	.remove = surfacegen5_acpi_sid_remove,
	.driver = {
		.name = "surfacegen5_acpi_sid",
		.acpi_match_table = ACPI_PTR(surfacegen5_acpi_sid_match),
	},
};

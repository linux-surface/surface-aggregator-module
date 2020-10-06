// SPDX-License-Identifier: GPL-2.0+
/*
 * Surface System Aggregator Module (SSAM) HID device driver.
 *
 * Provides support for HID input devices connected via the Surface System
 * Aggregator Module.
 *
 * Copyright (C) 2019-2020 Blaž Hrastnik <blaz@mxxn.io>
 */

#include <asm/unaligned.h>
#include <linux/hid.h>
#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include "../../include/linux/surface_aggregator/controller.h"
#include "../../include/linux/surface_aggregator/device.h"

#define SHID_RETRY			3
#define shid_retry(fn, args...)		ssam_retry(fn, SHID_RETRY, args)


struct surface_hid_descriptor {
	__u8 desc_len;			// = 9
	__u8 desc_type;			// = HID_DT_HID
	__le16 hid_version;
	__u8 country_code;
	__u8 num_descriptors;		// = 1

	__u8 report_desc_type;		// = HID_DT_REPORT
	__le16 report_desc_len;
} __packed;

static_assert(sizeof(struct surface_hid_descriptor) == 9);

struct surface_hid_attributes {
	__le32 length;
	__le16 vendor;
	__le16 product;
	__le16 version;
	__u8 _unknown[22];
} __packed;

static_assert(sizeof(struct surface_hid_attributes) == 32);

struct surface_sam_sid_vhf_meta_rqst {
	u8 id;
	u32 offset;
	u32 length; // buffer limit on send, length of data received on receive
	u8 end; // 0x01 if end was reached
} __packed;

union vhf_buffer_data {
	struct surface_hid_descriptor hid_descriptor;
	struct surface_hid_attributes attributes;
	u8 pld[0x76];
};

struct surface_sam_sid_vhf_meta_resp {
	struct surface_sam_sid_vhf_meta_rqst rqst;
	union vhf_buffer_data data;
} __packed;


struct surface_hid_device {
	struct device *dev;
	struct ssam_controller *ctrl;
	struct ssam_device_uid uid;

	struct surface_hid_attributes attrs;

	struct ssam_event_notifier notif;
	struct hid_device *hid;
};


static int vhf_get_metadata(struct surface_hid_device *shid, struct surface_hid_attributes *attrs)
{
	struct surface_sam_sid_vhf_meta_resp data = {};
	struct ssam_request rqst;
	struct ssam_response rsp;
	int status;

	data.rqst.id = 2;
	data.rqst.offset = 0;
	data.rqst.length = 0x76;
	data.rqst.end = 0;

	rqst.target_category = shid->uid.category;
	rqst.target_id = shid->uid.target;
	rqst.command_id = 0x04;
	rqst.instance_id = shid->uid.instance;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(struct surface_sam_sid_vhf_meta_rqst);
	rqst.payload = (u8 *)&data.rqst;

	rsp.capacity = sizeof(struct surface_sam_sid_vhf_meta_resp);
	rsp.length = 0;
	rsp.pointer = (u8 *)&data;

	status = shid_retry(ssam_request_sync, shid->ctrl, &rqst, &rsp);
	if (status)
		return status;

	*attrs = data.data.attributes;
	return 0;
}

static int vhf_get_hid_descriptor(struct surface_hid_device *shid, u8 **desc, int *size)
{
	struct surface_sam_sid_vhf_meta_resp data = {};
	struct ssam_request rqst;
	struct ssam_response rsp;
	int status, len;
	u8 *buf;

	data.rqst.id = 0;
	data.rqst.offset = 0;
	data.rqst.length = 0x76;
	data.rqst.end = 0;

	rqst.target_category = shid->uid.category;
	rqst.target_id = shid->uid.target;;
	rqst.command_id = 0x04;
	rqst.instance_id = shid->uid.instance;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(struct surface_sam_sid_vhf_meta_rqst);
	rqst.payload = (u8 *)&data.rqst;

	rsp.capacity = sizeof(struct surface_sam_sid_vhf_meta_resp);
	rsp.length = 0;
	rsp.pointer = (u8 *)&data;

	// first fetch 00 to get the total length
	status = shid_retry(ssam_request_sync, shid->ctrl, &rqst, &rsp);
	if (status)
		return status;

	len = get_unaligned_le16(&data.data.hid_descriptor.report_desc_len);

	// allocate a buffer for the descriptor
	buf = kzalloc(len, GFP_KERNEL);

	// then, iterate and write into buffer, copying out bytes
	data.rqst.id = 1;
	data.rqst.offset = 0;
	data.rqst.length = 0x76;
	data.rqst.end = 0;

	while (!data.rqst.end && data.rqst.offset < len) {
		status = shid_retry(ssam_request_sync, shid->ctrl, &rqst, &rsp);
		if (status) {
			kfree(buf);
			return status;
		}
		memcpy(buf + data.rqst.offset, data.data.pld, data.rqst.length);

		data.rqst.offset += data.rqst.length;
	}

	*desc = buf;
	*size = len;

	return 0;
}


static int surface_hid_start(struct hid_device *hid)
{
	struct surface_hid_device *shid = hid->driver_data;

	return ssam_notifier_register(shid->ctrl, &shid->notif);
}

static void surface_hid_stop(struct hid_device *hid)
{
	struct surface_hid_device *shid = hid->driver_data;

	// Note: This call will log errors for us, so ignore them here.
	ssam_notifier_unregister(shid->ctrl, &shid->notif);
}

static int surface_hid_open(struct hid_device *hid)
{
	return 0;
}

static void surface_hid_close(struct hid_device *hid)
{
}

static int surface_hid_parse(struct hid_device *hid)
{
	struct surface_hid_device *shid = hid->driver_data;
	int ret = 0, size;
	u8 *buf;

	ret = vhf_get_hid_descriptor(shid, &buf, &size);
	if (ret != 0) {
		hid_err(hid, "Failed to read HID descriptor from device: %d\n", ret);
		return -EIO;
	}
	hid_dbg(hid, "HID descriptor of device:");
	print_hex_dump_debug("descriptor:", DUMP_PREFIX_OFFSET, 16, 1, buf, size, false);

	ret = hid_parse_report(hid, buf, size);
	kfree(buf);
	return ret;

}

static int surface_hid_raw_request(struct hid_device *hid, unsigned char
		reportnum, u8 *buf, size_t len, unsigned char rtype, int
		reqtype)
{
	struct surface_hid_device *shid = hid->driver_data;
	struct ssam_request rqst;
	struct ssam_response rsp;
	int status;
	u8 cid;

	hid_dbg(hid, "%s: reportnum=%#04x rtype=%i reqtype=%i\n", __func__, reportnum, rtype, reqtype);
	print_hex_dump_debug("report:", DUMP_PREFIX_OFFSET, 16, 1, buf, len, false);

	// Byte 0 is the report number. Report data starts at byte 1.
	buf[0] = reportnum;

	switch (rtype) {
	case HID_OUTPUT_REPORT:
		cid = 0x01;
		break;
	case HID_FEATURE_REPORT:
		switch (reqtype) {
		case HID_REQ_GET_REPORT:
			// The EC doesn't respond to GET FEATURE for these touchpad reports
			// we immediately discard to avoid waiting for a timeout.
			if (reportnum == 6 || reportnum == 7 || reportnum == 8 || reportnum == 9 || reportnum == 0x0b) {
				hid_dbg(hid, "%s: skipping get feature report for 0x%02x\n", __func__, reportnum);
				return 0;
			}

			cid = 0x02;
			break;
		case HID_REQ_SET_REPORT:
			cid = 0x03;
			break;
		default:
			hid_err(hid, "%s: unknown req type 0x%02x\n", __func__, rtype);
			return -EIO;
		}
		break;
	default:
		hid_err(hid, "%s: unknown report type 0x%02x\n", __func__, reportnum);
		return -EIO;
	}

	rqst.target_category = shid->uid.category;
	rqst.target_id = shid->uid.target;
	rqst.instance_id = shid->uid.instance;
	rqst.command_id = cid;
	rqst.flags = reqtype == HID_REQ_GET_REPORT ? SSAM_REQUEST_HAS_RESPONSE : 0;
	rqst.length = reqtype == HID_REQ_GET_REPORT ? 1 : len;
	rqst.payload = buf;

	rsp.capacity = len;
	rsp.length = 0;
	rsp.pointer = buf;

	hid_dbg(hid, "%s: sending to cid=%#04x snc=%#04x\n", __func__, cid, HID_REQ_GET_REPORT == reqtype);

	status = shid_retry(ssam_request_sync, shid->ctrl, &rqst, &rsp);
	hid_dbg(hid, "%s: status %i\n", __func__, status);

	if (status)
		return status;

	if (rsp.length > 0)
		print_hex_dump_debug("response:", DUMP_PREFIX_OFFSET, 16, 1, rsp.pointer, rsp.length, false);

	return rsp.length;
}

static struct hid_ll_driver surface_hid_ll_driver = {
	.start       = surface_hid_start,
	.stop        = surface_hid_stop,
	.open        = surface_hid_open,
	.close       = surface_hid_close,
	.parse       = surface_hid_parse,
	.raw_request = surface_hid_raw_request,
};


static u32 sid_vhf_event_handler(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	struct surface_hid_device *shid = container_of(nf, struct surface_hid_device, notif);
	int status;

	if (event->command_id != 0x00)
		return 0;

	status = hid_input_report(shid->hid, HID_INPUT_REPORT, (u8 *)&event->data[0], event->length, 0);
	return ssam_notifier_from_errno(status) | SSAM_NOTIF_HANDLED;
}


static int surface_hid_device_add(struct surface_hid_device *shid)
{
	int status;

	status = vhf_get_metadata(shid, &shid->attrs);
	if (status)
		return status;

	shid->hid = hid_allocate_device();
	if (IS_ERR(shid->hid))
		return PTR_ERR(shid->hid);

	shid->hid->dev.parent = shid->dev;

	shid->hid->bus     = BUS_VIRTUAL;
	shid->hid->vendor  = get_unaligned_le16(&shid->attrs.vendor);
	shid->hid->product = get_unaligned_le16(&shid->attrs.product);

	snprintf(shid->hid->name, sizeof(shid->hid->name),
		 "Microsoft Surface %04X:%04X",
		 shid->hid->vendor, shid->hid->product);

	strlcpy(shid->hid->phys, dev_name(shid->dev), sizeof(shid->hid->phys));

	shid->hid->driver_data = shid;
	shid->hid->ll_driver = &surface_hid_ll_driver;

	status = hid_add_device(shid->hid);
	if (status)
		hid_destroy_device(shid->hid);

	return 0;
}

static void surface_hid_device_destroy(struct surface_hid_device *shid)
{
	hid_destroy_device(shid->hid);
}


/* -- PM ops. --------------------------------------------------------------- */

#ifdef CONFIG_PM

static int surface_hid_suspend(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_SUSPEND);

	return 0;
}

static int surface_hid_resume(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->resume)
		return d->hid->driver->resume(d->hid);

	return 0;
}

static int surface_hid_freeze(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_FREEZE);

	return 0;
}

static int surface_hid_poweroff(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->suspend)
		return d->hid->driver->suspend(d->hid, PMSG_HIBERNATE);

	return 0;
}

static int surface_hid_restore(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hid->driver && d->hid->driver->reset_resume)
		return d->hid->driver->reset_resume(d->hid);

	return 0;
}

struct dev_pm_ops surface_hid_pm_ops = {
	.freeze   = surface_hid_freeze,
	.thaw     = surface_hid_resume,
	.suspend  = surface_hid_suspend,
	.resume   = surface_hid_resume,
	.poweroff = surface_hid_poweroff,
	.restore  = surface_hid_restore,
};

#else /* CONFIG_PM */

struct dev_pm_ops surface_hid_pm_ops = { };

#endif /* CONFIG_PM */


/* -- Driver setup. --------------------------------------------------------- */

static int surface_hid_probe(struct ssam_device *sdev)
{
	struct surface_hid_device *shid;

	shid = devm_kzalloc(&sdev->dev, sizeof(*shid), GFP_KERNEL);
	if (!shid)
		return -ENOMEM;

	shid->dev = &sdev->dev;
	shid->ctrl = sdev->ctrl;
	shid->uid = sdev->uid;

	shid->notif.base.priority = 1;
	shid->notif.base.fn = sid_vhf_event_handler;
	shid->notif.event.reg = SSAM_EVENT_REGISTRY_REG,
	shid->notif.event.id.target_category = sdev->uid.category;
	shid->notif.event.id.instance = sdev->uid.instance;
	shid->notif.event.mask = SSAM_EVENT_MASK_STRICT;
	shid->notif.event.flags = 0;

	ssam_device_set_drvdata(sdev, shid);
	return surface_hid_device_add(shid);
}

static void surface_hid_remove(struct ssam_device *sdev)
{
	surface_hid_device_destroy(ssam_device_get_drvdata(sdev));
}

static const struct ssam_device_id surface_hid_match[] = {
	{ SSAM_SDEV(HID, 0x02, SSAM_ANY_IID, 0x00) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, surface_hid_match);

static struct ssam_device_driver surface_hid_driver = {
	.probe = surface_hid_probe,
	.remove = surface_hid_remove,
	.match_table = surface_hid_match,
	.driver = {
		.name = "surface_hid",
		.pm = &surface_hid_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(surface_hid_driver);

MODULE_AUTHOR("Blaž Hrastnik <blaz@mxxn.io>");
MODULE_DESCRIPTION("HID transport-/device-driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");

#ifndef __KERNEL_HAS_SSAM_MODALIAS_SUPPORT__
MODULE_ALIAS("ssam:d01c15t*i*f00");
#endif /* __KERNEL_HAS_SSAM_MODALIAS_SUPPORT__ */

// SPDX-License-Identifier: GPL-2.0+
/*
 * Surface System Aggregator Module (SSAM) legacy HID input device driver.
 *
 * Provides support for the legacy HID keyboard device found on the Surface
 * Laptop 1 and 2.
 *
 * Copyright (C) 2019-2020 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/acpi.h>
#include <linux/hid.h>
#include <linux/input.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/types.h>

#include "../../include/linux/surface_aggregator/device.h"
#include "../../include/linux/surface_aggregator/controller.h"


#define USB_VENDOR_ID_MICROSOFT		0x045e
#define USB_DEVICE_ID_MS_VHF		0xf001

#define VHF_INPUT_NAME			"Microsoft Virtual HID Framework Device"


struct surface_hid_device {
	struct device *dev;
	struct ssam_controller *ctrl;
	struct ssam_device_uid uid;

	struct ssam_event_notifier notif;
	struct hid_device *dev_hid;
};


/*
 * These report descriptors have been extracted from a Surface Book 2.
 * They seems to be similar enough to be usable on the Surface Laptop.
 */
static const u8 vhf_hid_desc[] = {
	// keyboard descriptor (event command ID 0x03)
	0x05, 0x01,             /*  Usage Page (Desktop),                   */
	0x09, 0x06,             /*  Usage (Keyboard),                       */
	0xA1, 0x01,             /*  Collection (Application),               */
	0x85, 0x01,             /*      Report ID (1),                      */
	0x15, 0x00,             /*      Logical Minimum (0),                */
	0x25, 0x01,             /*      Logical Maximum (1),                */
	0x75, 0x01,             /*      Report Size (1),                    */
	0x95, 0x08,             /*      Report Count (8),                   */
	0x05, 0x07,             /*      Usage Page (Keyboard),              */
	0x19, 0xE0,             /*      Usage Minimum (KB Leftcontrol),     */
	0x29, 0xE7,             /*      Usage Maximum (KB Right GUI),       */
	0x81, 0x02,             /*      Input (Variable),                   */
	0x75, 0x08,             /*      Report Size (8),                    */
	0x95, 0x0A,             /*      Report Count (10),                  */
	0x19, 0x00,             /*      Usage Minimum (None),               */
	0x29, 0x91,             /*      Usage Maximum (KB LANG2),           */
	0x26, 0xFF, 0x00,       /*      Logical Maximum (255),              */
	0x81, 0x00,             /*      Input,                              */
	0x05, 0x0C,             /*      Usage Page (Consumer),              */
	0x0A, 0xC0, 0x02,       /*      Usage (02C0h),                      */
	0xA1, 0x02,             /*      Collection (Logical),               */
	0x1A, 0xC1, 0x02,       /*          Usage Minimum (02C1h),          */
	0x2A, 0xC6, 0x02,       /*          Usage Maximum (02C6h),          */
	0x95, 0x06,             /*          Report Count (6),               */
	0xB1, 0x03,             /*          Feature (Constant, Variable),   */
	0xC0,                   /*      End Collection,                     */
	0x05, 0x08,             /*      Usage Page (LED),                   */
	0x19, 0x01,             /*      Usage Minimum (01h),                */
	0x29, 0x03,             /*      Usage Maximum (03h),                */
	0x75, 0x01,             /*      Report Size (1),                    */
	0x95, 0x03,             /*      Report Count (3),                   */
	0x25, 0x01,             /*      Logical Maximum (1),                */
	0x91, 0x02,             /*      Output (Variable),                  */
	0x95, 0x05,             /*      Report Count (5),                   */
	0x91, 0x01,             /*      Output (Constant),                  */
	0xC0,                   /*  End Collection,                         */

	// media key descriptor (event command ID 0x04)
	0x05, 0x0C,             /*  Usage Page (Consumer),                  */
	0x09, 0x01,             /*  Usage (Consumer Control),               */
	0xA1, 0x01,             /*  Collection (Application),               */
	0x85, 0x03,             /*      Report ID (3),                      */
	0x75, 0x10,             /*      Report Size (16),                   */
	0x15, 0x00,             /*      Logical Minimum (0),                */
	0x26, 0xFF, 0x03,       /*      Logical Maximum (1023),             */
	0x19, 0x00,             /*      Usage Minimum (00h),                */
	0x2A, 0xFF, 0x03,       /*      Usage Maximum (03FFh),              */
	0x81, 0x00,             /*      Input,                              */
	0xC0,                   /*  End Collection,                         */
};


static int surface_hid_start(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
	return 0;
}

static void surface_hid_stop(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
}

static int surface_hid_open(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
	return 0;
}

static void surface_hid_close(struct hid_device *hid)
{
	hid_dbg(hid, "%s\n", __func__);
}

static int surface_hid_parse(struct hid_device *hid)
{
	return hid_parse_report(hid, (u8 *)vhf_hid_desc, ARRAY_SIZE(vhf_hid_desc));
}

static int surface_hid_raw_request(struct hid_device *hid,
		unsigned char reportnum, u8 *buf, size_t len,
		unsigned char rtype, int reqtype)
{
	hid_dbg(hid, "%s\n", __func__);
	return 0;
}

static struct hid_ll_driver surface_hid_ll_driver = {
	.start         = surface_hid_start,
	.stop          = surface_hid_stop,
	.open          = surface_hid_open,
	.close         = surface_hid_close,
	.parse         = surface_hid_parse,
	.raw_request   = surface_hid_raw_request,
};


static struct hid_device *vhf_create_hid_device(struct device *parent)
{
	struct hid_device *hid;

	hid = hid_allocate_device();
	if (IS_ERR(hid))
		return hid;

	hid->dev.parent = parent;

	hid->bus     = BUS_VIRTUAL;
	hid->vendor  = USB_VENDOR_ID_MICROSOFT;
	hid->product = USB_DEVICE_ID_MS_VHF;

	hid->ll_driver = &surface_hid_ll_driver;

	sprintf(hid->name, "%s", VHF_INPUT_NAME);

	return hid;
}

static u32 vhf_event_handler(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	struct surface_hid_device *dev;
	int status;

	dev = container_of(nf, struct surface_hid_device, notif);

	// Note: Command id 3 is regular input, command ID 4 is FN-key input.
	if (event->command_id == 0x03 || event->command_id == 0x04) {
		status = hid_input_report(dev->dev_hid, HID_INPUT_REPORT, (u8 *)&event->data[0], event->length, 1);
		return ssam_notifier_from_errno(status) | SSAM_NOTIF_HANDLED;
	}

	return 0;
}


static int surface_hid_device_add(struct surface_hid_device *hdev)
{
	struct hid_device *hid;
	int status;

	hid = vhf_create_hid_device(hdev->dev);
	if (IS_ERR(hid))
		return PTR_ERR(hid);

	status = hid_add_device(hid);
	if (status)
		goto err_add_hid;

	status = ssam_notifier_register(hdev->ctrl, &hdev->notif);
	if (status)
		goto err_add_hid;

	return 0;

err_add_hid:
	hid_destroy_device(hid);
	return status;

}

static void surface_hid_device_destroy(struct surface_hid_device *hdev)
{
	ssam_notifier_unregister(hdev->ctrl, &hdev->notif);
	hid_destroy_device(hdev->dev_hid);
}


#ifdef CONFIG_PM

static int surface_hid_suspend(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->dev_hid->driver && d->dev_hid->driver->suspend)
		return d->dev_hid->driver->suspend(d->dev_hid, PMSG_SUSPEND);

	return 0;
}

static int surface_hid_resume(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->dev_hid->driver && d->dev_hid->driver->resume)
		return d->dev_hid->driver->resume(d->dev_hid);

	return 0;
}

static int surface_hid_freeze(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->dev_hid->driver && d->dev_hid->driver->suspend)
		return d->dev_hid->driver->suspend(d->dev_hid, PMSG_FREEZE);

	return 0;
}

static int surface_hid_poweroff(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->dev_hid->driver && d->dev_hid->driver->suspend)
		return d->dev_hid->driver->suspend(d->dev_hid, PMSG_HIBERNATE);

	return 0;
}

static int surface_hid_restore(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->dev_hid->driver && d->dev_hid->driver->reset_resume)
		return d->dev_hid->driver->reset_resume(d->dev_hid);

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

static int surface_hid_probe(struct platform_device *pdev)
{
	struct ssam_controller *ctrl;
	struct surface_hid_device *hdev;
	int status;

	// add device link to EC
	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	hdev = devm_kzalloc(&pdev->dev, sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return -ENOMEM;

	hdev->dev = &pdev->dev;
	hdev->ctrl = ctrl;

	hdev->uid.domain = SSAM_DOMAIN_SERIALHUB;
	hdev->uid.category = SSAM_SSH_TC_KBD;
	hdev->uid.target = 2;
	hdev->uid.instance = 0;
	hdev->uid.function = 0;

	hdev->notif.base.priority = 1;
	hdev->notif.base.fn = vhf_event_handler;
	hdev->notif.event.reg = SSAM_EVENT_REGISTRY_SAM;
	hdev->notif.event.id.target_category = hdev->uid.category;
	hdev->notif.event.id.instance = hdev->uid.instance;
	hdev->notif.event.mask = SSAM_EVENT_MASK_NONE;
	hdev->notif.event.flags = 0;

	status = surface_hid_device_add(hdev);
	if (status)
		return status;

	platform_set_drvdata(pdev, hdev);
	return 0;
}

static int surface_hid_remove(struct platform_device *pdev)
{
	surface_hid_device_destroy(platform_get_drvdata(pdev));
	return 0;
}


static const struct acpi_device_id surface_sam_vhf_match[] = {
	{ "MSHW0096" },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_vhf_match);

static struct platform_driver surface_keyboard_driver = {
	.probe = surface_hid_probe,
	.remove = surface_hid_remove,
	.driver = {
		.name = "surface_keyboard",
		.acpi_match_table = surface_sam_vhf_match,
		.pm = &surface_hid_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_keyboard_driver);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Legacy HID keyboard driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");

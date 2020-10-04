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

#define SURFACE_HID_DEVICE_NAME		"Microsoft Surface Aggregator HID"


struct surface_hid_device {
	struct device *dev;
	struct ssam_controller *ctrl;
	struct ssam_device_uid uid;

	struct ssam_event_notifier notif;
	struct hid_device *hdev;
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


static u32 surface_keyboard_event_fn(struct ssam_event_notifier *nf,
				     const struct ssam_event *event)
{
	struct surface_hid_device *shid;
	int status;

	shid = container_of(nf, struct surface_hid_device, notif);

	/*
	 * Check against device UID manually, as registry and device target
	 * category doesn't line up.
	 */

	if (shid->uid.category != event->target_category)
		return 0;

	if (shid->uid.target != event->target_id)
		return 0;

	if (shid->uid.instance != event->instance_id)
		return 0;

	// Note: Command id 3 is regular input, command ID 4 is FN-key input.
	if (event->command_id != 0x03 && event->command_id != 0x04)
		return 0;

	status = hid_input_report(shid->hdev, HID_INPUT_REPORT,
				  (u8 *)&event->data[0], event->length, 0);

	return ssam_notifier_from_errno(status) | SSAM_NOTIF_HANDLED;
}


static int surface_hid_start(struct hid_device *hdev)
{
	struct surface_hid_device *shid = dev_get_drvdata(hdev->dev.parent);

	return ssam_notifier_register(shid->ctrl, &shid->notif);
}

static void surface_hid_stop(struct hid_device *hdev)
{
	struct surface_hid_device *shid = dev_get_drvdata(hdev->dev.parent);

	// Note: This call will log errors for us, so ignore them here.
	ssam_notifier_unregister(shid->ctrl, &shid->notif);
}

static int surface_hid_open(struct hid_device *hdev)
{
	return 0;
}

static void surface_hid_close(struct hid_device *hdev)
{
}

static int surface_hid_parse(struct hid_device *hdev)
{
	return hid_parse_report(hdev, (u8 *)vhf_hid_desc, ARRAY_SIZE(vhf_hid_desc));
}

static int surface_hid_raw_request(struct hid_device *hdev,
		unsigned char reportnum, u8 *buf, size_t len,
		unsigned char rtype, int reqtype)
{
	// TODO: implement feature + output reports

	hid_info(hdev, "%s: reportnum=%d, rtype=%d, reqtype=%d\n",
		 __func__, reportnum, rtype, reqtype);

	print_hex_dump(KERN_INFO, "report: ", DUMP_PREFIX_OFFSET, 16, 1,
		       buf, len, false);

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


static int surface_hid_device_add(struct surface_hid_device *shid)
{
	int status;

	shid->hdev = hid_allocate_device();
	if (IS_ERR(shid->hdev))
		return PTR_ERR(shid->hdev);

	shid->hdev->dev.parent = shid->dev;
	shid->hdev->bus = BUS_VIRTUAL;
	shid->hdev->vendor = USB_VENDOR_ID_MICROSOFT;
	shid->hdev->product = USB_DEVICE_ID_MS_VHF;

	strlcpy(shid->hdev->name, SURFACE_HID_DEVICE_NAME, sizeof(shid->hdev->name));
	strlcpy(shid->hdev->phys, dev_name(shid->dev), sizeof(shid->hdev->phys));

	shid->hdev->ll_driver = &surface_hid_ll_driver;

	status = hid_add_device(shid->hdev);
	if (status)
		hid_destroy_device(shid->hdev);

	return status;
}

static void surface_hid_device_destroy(struct surface_hid_device *shid)
{
	hid_destroy_device(shid->hdev);
}


/* -- PM ops. --------------------------------------------------------------- */

#ifdef CONFIG_PM

static int surface_hid_suspend(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hdev->driver && d->hdev->driver->suspend)
		return d->hdev->driver->suspend(d->hdev, PMSG_SUSPEND);

	return 0;
}

static int surface_hid_resume(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hdev->driver && d->hdev->driver->resume)
		return d->hdev->driver->resume(d->hdev);

	return 0;
}

static int surface_hid_freeze(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hdev->driver && d->hdev->driver->suspend)
		return d->hdev->driver->suspend(d->hdev, PMSG_FREEZE);

	return 0;
}

static int surface_hid_poweroff(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hdev->driver && d->hdev->driver->suspend)
		return d->hdev->driver->suspend(d->hdev, PMSG_HIBERNATE);

	return 0;
}

static int surface_hid_restore(struct device *dev)
{
	struct surface_hid_device *d = dev_get_drvdata(dev);

	if (d->hdev->driver && d->hdev->driver->reset_resume)
		return d->hdev->driver->reset_resume(d->hdev);

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

static int surface_hid_probe(struct platform_device *pdev)
{
	struct ssam_controller *ctrl;
	struct surface_hid_device *shid;
	int status;

	// add device link to EC
	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	shid = devm_kzalloc(&pdev->dev, sizeof(*shid), GFP_KERNEL);
	if (!shid)
		return -ENOMEM;

	platform_set_drvdata(pdev, shid);

	shid->dev = &pdev->dev;
	shid->ctrl = ctrl;

	shid->uid.domain = SSAM_DOMAIN_SERIALHUB;
	shid->uid.category = SSAM_SSH_TC_KBD;
	shid->uid.target = 2;
	shid->uid.instance = 0;
	shid->uid.function = 0;

	shid->notif.base.priority = 1;
	shid->notif.base.fn = surface_keyboard_event_fn;
	shid->notif.event.reg = SSAM_EVENT_REGISTRY_SAM;
	shid->notif.event.id.target_category = shid->uid.category;
	shid->notif.event.id.instance = shid->uid.instance;
	shid->notif.event.mask = SSAM_EVENT_MASK_NONE;
	shid->notif.event.flags = 0;

	return surface_hid_device_add(shid);
}

static int surface_hid_remove(struct platform_device *pdev)
{
	surface_hid_device_destroy(platform_get_drvdata(pdev));
	return 0;
}

static const struct acpi_device_id surface_keyboard_match[] = {
	{ "MSHW0096" },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_keyboard_match);

static struct platform_driver surface_keyboard_driver = {
	.probe = surface_hid_probe,
	.remove = surface_hid_remove,
	.driver = {
		.name = "surface_keyboard",
		.acpi_match_table = surface_keyboard_match,
		.pm = &surface_hid_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_keyboard_driver);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Legacy HID keyboard driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");

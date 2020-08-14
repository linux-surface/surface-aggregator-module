// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface Device Registry.
 */

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>

#include <linux/surface_aggregator_module.h>


/* -- Device registry structures. ------------------------------------------- */

struct ssam_hub_cell {
	struct ssam_device_uid uid;
	void *data;
};

struct ssam_hub_desc {
	const struct ssam_hub_cell *cells;
	unsigned int num_cells;
};

/*
 * This device target category is normally invalid. We use it here to describe
 * device hubs.
 */
#define SSAM_SSH_TC_HUB		0

#define SSAM_DUID_HUB_MAIN	SSAM_DUID(HUB, 0x01, 0x00, 0x00)
#define SSAM_DUID_HUB_BASE	SSAM_DUID(HUB, 0x02, 0x00, 0x00)

#define SSAM_DEFINE_HUB_DESC(__name, __cells)		\
	struct ssam_hub_desc __name = {			\
		.cells = __cells,			\
		.num_cells = ARRAY_SIZE(__cells),	\
	};

#define SSAM_DEFINE_PLATFORM_HUB(__suffix)					\
	static const SSAM_DEFINE_HUB_DESC(ssam_device_hub_##__suffix,		\
					  ssam_devices_##__suffix);		\
	static const struct ssam_hub_cell ssam_platform_hubs_##__suffix[] = {	\
		{ SSAM_DUID_HUB_MAIN, (void *)&ssam_device_hub_##__suffix },	\
	};									\
	static const SSAM_DEFINE_HUB_DESC(ssam_platform_hub_##__suffix,		\
					  ssam_platform_hubs_##__suffix);	\

#define SSAM_DEFINE_PLATFORM_HUB_WITH_BASE(__suffix)				\
	static const SSAM_DEFINE_HUB_DESC(ssam_device_hub_##__suffix,		\
					  ssam_devices_##__suffix);		\
	static const SSAM_DEFINE_HUB_DESC(ssam_device_hub_##__suffix##_base,	\
					  ssam_devices_##__suffix##_base);	\
	static const struct ssam_hub_cell ssam_platform_hubs_##__suffix[] = {	\
		{ SSAM_DUID_HUB_MAIN, (void *)&ssam_device_hub_##__suffix },	\
		{ SSAM_DUID_HUB_BASE, (void *)&ssam_device_hub_##__suffix##_base },\
	};									\
	static const SSAM_DEFINE_HUB_DESC(ssam_platform_hub_##__suffix,		\
					  ssam_platform_hubs_##__suffix);	\


/* -- Device registry. ------------------------------------------------------ */

#define SSAM_DUID_BAT_AC	SSAM_DUID(BAT, 0x01, 0x01, 0x01)
#define SSAM_DUID_BAT_MAIN	SSAM_DUID(BAT, 0x01, 0x01, 0x00)
#define SSAM_DUID_BAT_SB3BASE	SSAM_DUID(BAT, 0x02, 0x01, 0x00)

#define SSAM_DUID_TMP_PERF	SSAM_DUID(TMP, 0x01, 0x00, 0x02)

#define SSAM_DUID_HID_KEYBOARD	SSAM_DUID(HID, 0x02, 0x01, 0x00)
#define SSAM_DUID_HID_TOUCHPAD	SSAM_DUID(HID, 0x02, 0x03, 0x00)
#define SSAM_DUID_HID_IID5	SSAM_DUID(HID, 0x02, 0x05, 0x00)
#define SSAM_DUID_HID_IID6	SSAM_DUID(HID, 0x02, 0x06, 0x00)


static const struct ssam_hub_cell ssam_devices_sb2[] = {
	{ SSAM_DUID_TMP_PERF },
};

static const struct ssam_hub_cell ssam_devices_sb3[] = {
	{ SSAM_DUID_TMP_PERF },
	{ SSAM_DUID_BAT_AC   },
	{ SSAM_DUID_BAT_MAIN },
};

static const struct ssam_hub_cell ssam_devices_sb3_base[] = {
	{ SSAM_DUID_BAT_SB3BASE  },
	{ SSAM_DUID_HID_KEYBOARD },
	{ SSAM_DUID_HID_TOUCHPAD },
	{ SSAM_DUID_HID_IID5     },
	{ SSAM_DUID_HID_IID6     },
};

static const struct ssam_hub_cell ssam_devices_sl1[] = {
	{ SSAM_DUID_TMP_PERF },
};

static const struct ssam_hub_cell ssam_devices_sl2[] = {
	{ SSAM_DUID_TMP_PERF },
};

static const struct ssam_hub_cell ssam_devices_sl3[] = {
	{ SSAM_DUID_TMP_PERF     },
	{ SSAM_DUID_BAT_AC       },
	{ SSAM_DUID_BAT_MAIN     },
	{ SSAM_DUID_HID_KEYBOARD },
	{ SSAM_DUID_HID_TOUCHPAD },
	{ SSAM_DUID_HID_IID5     },
};

static const struct ssam_hub_cell ssam_devices_sp5[] = {
	{ SSAM_DUID_TMP_PERF },
};

static const struct ssam_hub_cell ssam_devices_sp6[] = {
	{ SSAM_DUID_TMP_PERF },
};

static const struct ssam_hub_cell ssam_devices_sp7[] = {
	{ SSAM_DUID_TMP_PERF },
	{ SSAM_DUID_BAT_AC   },
	{ SSAM_DUID_BAT_MAIN },
};

SSAM_DEFINE_PLATFORM_HUB(sb2);
SSAM_DEFINE_PLATFORM_HUB_WITH_BASE(sb3);
SSAM_DEFINE_PLATFORM_HUB(sl1);
SSAM_DEFINE_PLATFORM_HUB(sl2);
SSAM_DEFINE_PLATFORM_HUB(sl3);
SSAM_DEFINE_PLATFORM_HUB(sp5);
SSAM_DEFINE_PLATFORM_HUB(sp6);
SSAM_DEFINE_PLATFORM_HUB(sp7);


/* -- Device registry helper functions. ------------------------------------- */

static int ssam_hub_remove_devices_fn(struct device *dev, void *data)
{
	if (!is_ssam_device(dev))
		return 0;

	ssam_device_remove(to_ssam_device(dev));
	return 0;
}

static void ssam_hub_remove_devices(struct device *parent)
{
	device_for_each_child_reverse(parent, NULL, ssam_hub_remove_devices_fn);
}

static int ssam_hub_add_device(struct device *parent,
			       struct ssam_controller *ctrl,
			       const struct ssam_hub_cell *cell)
{
	struct ssam_device *sdev;
	int status;

	sdev = ssam_device_alloc(ctrl, cell->uid);
	if (!sdev)
		return -ENOMEM;

	sdev->dev.parent = parent;
	sdev->dev.platform_data = cell->data;

	status = ssam_device_add(sdev);
	if (status)
		ssam_device_put(sdev);

	return status;
}

static int ssam_hub_add_devices(struct device *parent,
				struct ssam_controller *ctrl,
				const struct ssam_hub_desc *desc)
{
	int status, i;

	for (i = 0; i < desc->num_cells; i++) {
		status = ssam_hub_add_device(parent, ctrl, &desc->cells[i]);
		if (status)
			goto err;
	}

	return 0;
err:
	ssam_hub_remove_devices(parent);
	return status;
}


/* -- SSAM main-hub driver. ------------------------------------------------- */

static int ssam_hub_probe(struct ssam_device *sdev)
{
	const struct ssam_hub_desc *desc = dev_get_platdata(&sdev->dev);

	if (!desc)
		return -ENODEV;

	return ssam_hub_add_devices(&sdev->dev, sdev->ctrl, desc);
}

static void ssam_hub_remove(struct ssam_device *sdev)
{
	ssam_hub_remove_devices(&sdev->dev);
}

static const struct ssam_device_id ssam_hub_match[] = {
	{ SSAM_DUID_HUB_MAIN },
	{ SSAM_DUID_HUB_BASE },	// TODO: implement driver supporting base-detach
	{ },
};

static struct ssam_device_driver ssam_hub_driver = {
	.probe = ssam_hub_probe,
	.remove = ssam_hub_remove,
	.match_table = ssam_hub_match,
	.driver = {
		.name = "surface_sam_hub",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


/* -- SSAM platform/meta-hub driver. ---------------------------------------- */

static const struct acpi_device_id ssam_platform_hub_match[] = {
	/* Surface Pro 4, 5, and 6 */
	{ "MSHW0081", (unsigned long)&ssam_platform_hub_sp5 },

	/* Surface Pro 6 (OMBR >= 0x10) */
	{ "MSHW0111", (unsigned long)&ssam_platform_hub_sp6 },

	/* Surface Pro 7 */
	{ "MSHW0116", (unsigned long)&ssam_platform_hub_sp7 },

	/* Surface Book 2 */
	{ "MSHW0107", (unsigned long)&ssam_platform_hub_sb2 },

	/* Surface Book 3 */
	{ "MSHW0117", (unsigned long)&ssam_platform_hub_sb3 },

	/* Surface Laptop 1 */
	{ "MSHW0086", (unsigned long)&ssam_platform_hub_sl1 },

	/* Surface Laptop 2 */
	{ "MSHW0112", (unsigned long)&ssam_platform_hub_sl2 },

	/* Surface Laptop 3 (13", Intel) */
	{ "MSHW0114", (unsigned long)&ssam_platform_hub_sl3 },

	/* Surface Laptop 3 (15", AMD) */
	{ "MSHW0110", (unsigned long)&ssam_platform_hub_sl3 },

	{ },
};
MODULE_DEVICE_TABLE(acpi, ssam_platform_hub_match);

static int ssam_platform_hub_probe(struct platform_device *pdev)
{
	const struct ssam_hub_desc *desc;
	struct ssam_controller *ctrl;
	int status;

	desc = acpi_device_get_match_data(&pdev->dev);
	if (!desc)
		return -ENODEV;

	/*
	 * As we're adding the SSAM client devices as children under this device
	 * and not the SSAM controller, we need to add a device link to the
	 * controller to ensure that we remove all of our devices before the
	 * controller is removed. This also guarantees proper ordering for
	 * suspend/resume of the devices on this hub.
	 */
	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	return ssam_hub_add_devices(&pdev->dev, ctrl, desc);
}

static int ssam_platform_hub_remove(struct platform_device *pdev)
{
	ssam_hub_remove_devices(&pdev->dev);
	return 0;
}

static struct platform_driver ssam_platform_hub_driver = {
	.probe = ssam_platform_hub_probe,
	.remove = ssam_platform_hub_remove,
	.driver = {
		.name = "surface_sam_platform_hub",
		.acpi_match_table = ssam_platform_hub_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


/* -- Module initialization. ------------------------------------------------ */

static int __init ssam_device_hub_init(void)
{
	int status;

	status = platform_driver_register(&ssam_platform_hub_driver);
	if (status)
		return status;

	status = ssam_device_driver_register(&ssam_hub_driver);
	if (status)
		platform_driver_unregister(&ssam_platform_hub_driver);

	return status;
}

static void __exit ssam_device_hub_exit(void)
{
	ssam_device_driver_unregister(&ssam_hub_driver);
	platform_driver_unregister(&ssam_platform_hub_driver);
}

module_init(ssam_device_hub_init);
module_exit(ssam_device_hub_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface SAM Device Hub Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");

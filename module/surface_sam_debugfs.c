// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/platform_device.h>

#define SSAM_DBGDEV_NAME	"surface_sam_dbgdev"


static int ssam_dbgdev_probe(struct platform_device *pdev)
{
	return 0;	// TODO
}

static int ssam_dbgdev_remove(struct platform_device *pdev)
{
	return 0;	// TODO
}

static void ssam_dbgdev_release(struct device *dev)
{
	// nothing to do
}


static struct platform_device ssam_dbgdev_device = {
	.name = SSAM_DBGDEV_NAME,
	.id = PLATFORM_DEVID_NONE,
	.dev.release = ssam_dbgdev_release,
};

static struct platform_driver ssam_dbgdev_driver = {
	.probe 	= ssam_dbgdev_probe,
	.remove = ssam_dbgdev_remove,
	.driver = {
		.name = SSAM_DBGDEV_NAME,
	},
};

static int __init surface_sam_debugfs_init(void)
{
	int status;

	status = platform_device_register(&ssam_dbgdev_device);
	if (status)
		return status;

	status = platform_driver_register(&ssam_dbgdev_driver);
	if (status)
		platform_device_unregister(&ssam_dbgdev_device);

	return status;
}

static void __exit surface_sam_debugfs_exit(void)
{
	platform_driver_unregister(&ssam_dbgdev_driver);
	platform_device_unregister(&ssam_dbgdev_device);
}

module_init(surface_sam_debugfs_init);
module_exit(surface_sam_debugfs_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("DebugFS entries for Surface Aggregator Module");
MODULE_LICENSE("GPL");

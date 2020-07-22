// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include "surface_sam_ssh.h"

#define SSAM_DBGDEV_NAME	"surface_sam_dbgdev"
#define SSAM_DBGDEV_VERS	0x0100


struct ssam_dbgdev_request {
	__u8 target_category;
	__u8 command_id;
	__u8 instance_id;
	__u8 channel;
	__u16 flags;
	__s16 status;

	struct {
		__u8 __pad[6];
		__u16 length;
		const __u8 __user *data;
	} payload;

	struct {
		__u8 __pad[6];
		__u16 length;
		__u8 __user *data;
	} response;
};

#define SSAM_DBGDEV_IOCTL_GETVERSION	_IOR(0xA5, 0, __u32)
#define SSAM_DBGDEV_IOCTL_REQUEST	_IOWR(0xA5, 1, struct ssam_dbgdev_request)


struct ssam_dbgdev {
	struct ssam_controller *ctrl;
	struct dentry *dentry_dir;
	struct dentry *dentry_dev;
};


static int ssam_dbgdev_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return nonseekable_open(inode, filp);
}

static long ssam_dbgdev_request(struct file *file, unsigned long arg)
{
	return 0;	// TODO
}

static long ssam_dbgdev_getversion(struct file *file, unsigned long arg)
{
	put_user(SSAM_DBGDEV_VERS, (u32 __user *)arg);
	return 0;
}

static long ssam_dbgdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SSAM_DBGDEV_IOCTL_GETVERSION:
		return ssam_dbgdev_getversion(file, arg);

	case SSAM_DBGDEV_IOCTL_REQUEST:
		return ssam_dbgdev_request(file, arg);

	default:
		return -EINVAL;
	}
}

const struct file_operations ssam_dbgdev_fops = {
	.owner          = THIS_MODULE,
	.open           = ssam_dbgdev_open,
	.unlocked_ioctl = ssam_dbgdev_ioctl,
	.compat_ioctl   = ssam_dbgdev_ioctl,
	.llseek         = noop_llseek,
};

static int ssam_dbgdev_probe(struct platform_device *pdev)
{
	struct ssam_dbgdev *ddev;
	struct ssam_controller *ctrl;
	int status;

	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	ddev = devm_kzalloc(&pdev->dev, sizeof(struct ssam_dbgdev), GFP_KERNEL);
	if (!ddev)
		return -ENOMEM;

	ddev->ctrl = ctrl;

	ddev->dentry_dir = debugfs_create_dir("surface_sam", NULL);
	if (IS_ERR(ddev->dentry_dir))
		return PTR_ERR(ddev->dentry_dir);

	ddev->dentry_dev = debugfs_create_file("controller", 0600,
					       ddev->dentry_dir, ddev,
					       &ssam_dbgdev_fops);
	if (IS_ERR(ddev->dentry_dev)) {
		debugfs_remove(ddev->dentry_dir);
		return PTR_ERR(ddev->dentry_dev);
	}

	platform_set_drvdata(pdev, ddev);
	return 0;
}

static int ssam_dbgdev_remove(struct platform_device *pdev)
{
	struct ssam_dbgdev *ddev = platform_get_drvdata(pdev);

	debugfs_remove(ddev->dentry_dev);
	debugfs_remove(ddev->dentry_dir);

	platform_set_drvdata(pdev, NULL);
	return 0;
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

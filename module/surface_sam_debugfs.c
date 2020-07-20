// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>


static int __init surface_sam_debugfs_init(void)
{
	return 0;       // TODO
}

static void __exit surface_sam_debugfs_exit(void)
{
	// TODO
}

module_init(surface_sam_debugfs_init);
module_exit(surface_sam_debugfs_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("DebugFS entries for Surface Aggregator Module");
MODULE_LICENSE("GPL");

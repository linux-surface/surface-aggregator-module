#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/serdev.h>

#include "surfacegen5_acpi_notify_ec.h"


int surfacegen5_ec_rqst(struct surfacegen5_rqst *rqst, struct surfacegen5_buf *result)
{
	// FIXME: temporary fix for base status (lid notify loop)
	if (
		rqst->tc  == 0x11 &&
		rqst->iid == 0x00 &&
		rqst->cid == 0x0D &&
		rqst->snc == 0x01
	) {
		if (result->cap < 1) {
			printk(KERN_ERR "surfacegen5_ec_rqst: output buffer too small\n");
			return -ENOMEM;
		}

		result->len    = 0x01;
		result->pld[0] = 0x01;		// base-status: attached

		return 0;
	}

	// TODO: surfacegen5_ec_rqst

	printk(KERN_WARNING "surfacegen5_ec_rqst: "
	       "unsupported request: RQST(0x%02x, 0x%02x, 0x%02x)\n",
	       rqst->tc, rqst->cid, rqst->iid);

	return 1;
}


static int surfacegen5_acpi_notify_ssh_probe(struct serdev_device *serdev)
{
	dev_info(&serdev->dev, "surfacegen5_acpi_notify_ssh_probe\n");		// TODO: serdev driver
	return 0;
}

static void surfacegen5_acpi_notify_ssh_remove(struct serdev_device *serdev)
{
	dev_info(&serdev->dev, "surfacegen5_acpi_notify_ssh_remove\n");		// TODO: serdev driver
}


static const struct acpi_device_id surfacegen5_acpi_notify_ssh_match[] = {
	{ "MSHW0084", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surfacegen5_acpi_notify_ssh_match);

struct serdev_device_driver surfacegen5_acpi_notify_ssh = {
	.probe = surfacegen5_acpi_notify_ssh_probe,
	.remove = surfacegen5_acpi_notify_ssh_remove,
	.driver = {
		.name = "surfacegen5_acpi_notify_ssh",
		.acpi_match_table = ACPI_PTR(surfacegen5_acpi_notify_ssh_match),
	},
};

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/serdev.h>


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

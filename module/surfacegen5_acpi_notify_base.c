#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/serdev.h>


extern struct serdev_device_driver surfacegen5_acpi_notify_ssh;
extern struct platform_driver surfacegen5_acpi_notify_san;


int __init surfacegen5_acpi_notify_init(void)
{
	int status = 0;

	status = serdev_device_driver_register(&surfacegen5_acpi_notify_ssh);
	if (status) goto err_init_ssh;

	status = platform_driver_register(&surfacegen5_acpi_notify_san);
	if (status) goto err_init_san;

	return 0;

err_init_san:
	serdev_device_driver_unregister(&surfacegen5_acpi_notify_ssh);
err_init_ssh:
	return status;
}

void __exit surfacegen5_acpi_notify_exit(void)
{
	platform_driver_unregister(&surfacegen5_acpi_notify_san);
	serdev_device_driver_unregister(&surfacegen5_acpi_notify_ssh);
}


module_init(surfacegen5_acpi_notify_init)
module_exit(surfacegen5_acpi_notify_exit)

MODULE_AUTHOR("Maximilian Luz");
MODULE_DESCRIPTION("ACPI Notify Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL v2");

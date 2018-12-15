#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/serdev.h>


extern struct serdev_device_driver surfacegen5_acpi_ssh;
extern struct platform_driver surfacegen5_acpi_san;
extern struct platform_driver surfacegen5_acpi_vhf;


int __init surfacegen5_acpi_init(void)
{
	int status;

	status = serdev_device_driver_register(&surfacegen5_acpi_ssh);
	if (status) {
		goto err_init_ssh;
	}

	status = platform_driver_register(&surfacegen5_acpi_san);
	if (status) {
		goto err_init_san;
	}

	status = platform_driver_register(&surfacegen5_acpi_vhf);
	if (status) {
		goto err_init_vhf;
	}

	return 0;

err_init_vhf:
	platform_driver_unregister(&surfacegen5_acpi_san);
err_init_san:
	serdev_device_driver_unregister(&surfacegen5_acpi_ssh);
err_init_ssh:
	return status;
}

void __exit surfacegen5_acpi_exit(void)
{
	platform_driver_unregister(&surfacegen5_acpi_vhf);
	platform_driver_unregister(&surfacegen5_acpi_san);
	serdev_device_driver_unregister(&surfacegen5_acpi_ssh);
}


module_init(surfacegen5_acpi_init)
module_exit(surfacegen5_acpi_exit)

MODULE_AUTHOR("Maximilian Luz");
MODULE_DESCRIPTION("ACPI/Platform Drivers for 5th Generation Surface Devices");
MODULE_LICENSE("GPL v2");

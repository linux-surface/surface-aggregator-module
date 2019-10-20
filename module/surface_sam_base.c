#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/serdev.h>


extern struct serdev_device_driver surface_sam_ssh;
extern struct platform_driver surface_sam_san;
extern struct platform_driver surface_sam_vhf;
extern struct platform_driver surface_sam_dtx;
extern struct platform_driver surface_sam_sid;


int __init surface_sam_init(void)
{
	int status;

	status = serdev_device_driver_register(&surface_sam_ssh);
	if (status) {
		goto err_ssh;
	}

	status = platform_driver_register(&surface_sam_san);
	if (status) {
		goto err_san;
	}

	status = platform_driver_register(&surface_sam_vhf);
	if (status) {
		goto err_vhf;
	}

	status = platform_driver_register(&surface_sam_dtx);
	if (status) {
		goto err_dtx;
	}

	status = platform_driver_register(&surface_sam_sid);
	if (status) {
		goto err_sid;
	}

	return 0;

err_sid:
	platform_driver_unregister(&surface_sam_dtx);
err_dtx:
	platform_driver_unregister(&surface_sam_vhf);
err_vhf:
	platform_driver_unregister(&surface_sam_san);
err_san:
	serdev_device_driver_unregister(&surface_sam_ssh);
err_ssh:
	return status;
}

void __exit surface_sam_exit(void)
{
	platform_driver_unregister(&surface_sam_sid);
	platform_driver_unregister(&surface_sam_dtx);
	platform_driver_unregister(&surface_sam_vhf);
	platform_driver_unregister(&surface_sam_san);
	serdev_device_driver_unregister(&surface_sam_ssh);
}


module_init(surface_sam_init)
module_exit(surface_sam_exit)

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("System Aggregator Module/Platform Drivers for 5th Generation Surface Devices");
MODULE_LICENSE("GPL v2");

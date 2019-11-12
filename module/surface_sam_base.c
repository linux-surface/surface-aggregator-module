#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/serdev.h>


extern struct serdev_device_driver surface_sam_ssh;
extern struct platform_driver surface_sam_san;
extern struct platform_driver surface_sam_vhf;
extern struct platform_driver surface_sam_dtx;
extern struct platform_driver surface_sam_sid;
extern struct platform_driver surface_sam_sid_gpelid;
extern struct platform_driver surface_sam_sid_perfmode;
extern struct platform_driver surface_sam_sid_vhf;
extern struct platform_driver surface_sam_sid_battery;
extern struct platform_driver surface_sam_sid_ac;


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

	status = platform_driver_register(&surface_sam_sid_gpelid);
	if (status) {
		goto err_sid_gpelid;
	}

	status = platform_driver_register(&surface_sam_sid_perfmode);
	if (status) {
		goto err_sid_perfmode;
	}

	status = platform_driver_register(&surface_sam_sid_vhf);
	if (status) {
		goto err_sid_vhf;
	}

	status = platform_driver_register(&surface_sam_sid_ac);
	if (status) {
		goto err_sid_ac;
	}

	status = platform_driver_register(&surface_sam_sid_battery);
	if (status) {
		goto err_sid_battery;
	}

	return 0;

err_sid_battery:
	platform_driver_unregister(&surface_sam_sid_ac);
err_sid_ac:
	platform_driver_unregister(&surface_sam_sid_vhf);
err_sid_vhf:
	platform_driver_unregister(&surface_sam_sid_perfmode);
err_sid_perfmode:
	platform_driver_unregister(&surface_sam_sid_gpelid);
err_sid_gpelid:
	platform_driver_unregister(&surface_sam_sid);
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
	platform_driver_unregister(&surface_sam_sid_battery);
	platform_driver_unregister(&surface_sam_sid_ac);
	platform_driver_unregister(&surface_sam_sid_vhf);
	platform_driver_unregister(&surface_sam_sid_perfmode);
	platform_driver_unregister(&surface_sam_sid_gpelid);
	platform_driver_unregister(&surface_sam_sid);
	platform_driver_unregister(&surface_sam_dtx);
	platform_driver_unregister(&surface_sam_vhf);
	platform_driver_unregister(&surface_sam_san);
	serdev_device_driver_unregister(&surface_sam_ssh);
}

/*
 * Ensure that the driver is loaded late due to some issues with the UART
 * communication. Specifically, we want to ensure that DMA is ready and being
 * used. Not using DMA can result in spurious communication failures,
 * especially during boot, which among other things will result in wrong
 * battery information (via ACPI _BIX) being displayed. Using a late init_call
 * instead of the normal module_init gives the DMA subsystem time to
 * initialize and via that results in a more stable communication, avoiding
 * such failures.
 */
late_initcall(surface_sam_init)
module_exit(surface_sam_exit)

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("System Aggregator Module/Platform Drivers for 5th Generation Surface Devices");
MODULE_LICENSE("GPL v2");

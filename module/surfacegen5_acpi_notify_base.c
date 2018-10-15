#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/serdev.h>


extern struct serdev_device_driver surfacegen5_acpi_notify_ssh;
extern struct platform_driver surfacegen5_acpi_notify_san;


static struct device_link *surfacegen5_devlink;

static int surfacegen5_devlink_init(void)
{
	struct acpi_device *san_dev;
	struct acpi_device *ssh_dev;
	acpi_handle san_handle;
	acpi_handle ssh_handle;
	acpi_status status = 0;

	status = acpi_get_handle(ACPI_ROOT_OBJECT, "\\_SB._SAN", &san_handle);
	if (ACPI_FAILURE(status)) {
		return status;
	}

	status = acpi_get_handle(ACPI_ROOT_OBJECT, "\\_SB._SSH", &ssh_handle);
	if (ACPI_FAILURE(status)) {
		return status;
	}

	status = acpi_bus_get_device(san_handle, &san_dev);
	if (ACPI_FAILURE(status)) {
		return status;
	}

	status = acpi_bus_get_device(ssh_handle, &ssh_dev);
	if (ACPI_FAILURE(status)) {
		return status;
	}

	surfacegen5_devlink = device_link_add(&san_dev->dev, &ssh_dev->dev, 0);
	if (IS_ERR_OR_NULL(surfacegen5_devlink)) {
		status = surfacegen5_devlink ? PTR_ERR(surfacegen5_devlink) : -EFAULT;
		surfacegen5_devlink = NULL;
	}

	return status;
}

static void surfacegen5_devlink_remove(void)
{
	device_link_del(surfacegen5_devlink);
	surfacegen5_devlink = NULL;
}


int __init surfacegen5_acpi_notify_init(void)
{
	int status = 0;

	status = surfacegen5_devlink_init();
	if (status) goto err_init_devlink;

	status = serdev_device_driver_register(&surfacegen5_acpi_notify_ssh);
	if (status) goto err_init_ssh;

	status = platform_driver_register(&surfacegen5_acpi_notify_san);
	if (status) goto err_init_san;

	return 0;

err_init_san:
	serdev_device_driver_unregister(&surfacegen5_acpi_notify_ssh);
err_init_ssh:
	surfacegen5_devlink_remove();
err_init_devlink:
	return status;
}

void __exit surfacegen5_acpi_notify_exit(void)
{
	platform_driver_unregister(&surfacegen5_acpi_notify_san);
	serdev_device_driver_unregister(&surfacegen5_acpi_notify_ssh);
	surfacegen5_devlink_remove();
}


module_init(surfacegen5_acpi_notify_init)
module_exit(surfacegen5_acpi_notify_exit)

MODULE_AUTHOR("Maximilian Luz");
MODULE_DESCRIPTION("ACPI Notify Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL v2");

#include <linux/acpi.h>
#include <linux/gpio.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>


#define SB2_SHPS_DSM_REVISION	0
#define SB2_SHPS_DSM_GPU_STATE	0x05

static const guid_t SB2_SHPS_DSM_UUID =
	GUID_INIT(0x5515a847, 0xed55, 0x4b27, 0x83, 0x52, 0xcd,
	          0x32, 0x0e, 0x10, 0x36, 0x0a);

#define SB2_PARAM_PERM	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)


static const struct acpi_gpio_params gpio_base_presence_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_base_presence     = { 1, 0, false };
static const struct acpi_gpio_params gpio_dgpu_power_int    = { 2, 0, false };
static const struct acpi_gpio_params gpio_dgpu_power        = { 3, 0, false };
static const struct acpi_gpio_params gpio_dgpu_presence_int = { 4, 0, false };
static const struct acpi_gpio_params gpio_dgpu_presence     = { 5, 0, false };

static const struct acpi_gpio_mapping sb2_mshw0153_acpi_gpios[] = {
	{ "base_presence-int-gpio", &gpio_base_presence_int, 1 },
	{ "base_presence-gpio",     &gpio_base_presence,     1 },
	{ "dgpu_power-int-gpio",    &gpio_dgpu_power_int,    1 },
	{ "dgpu_power-gpio",        &gpio_dgpu_power,        1 },
	{ "dgpu_presence-int-gpio", &gpio_dgpu_presence_int, 1 },
	{ "dgpu_presence-gpio",     &gpio_dgpu_presence,     1 },
	{ },
};


static bool sb2_dgpu_default_pwr = false;

module_param_named(dgpu_pwr, sb2_dgpu_default_pwr, bool, SB2_PARAM_PERM);
MODULE_PARM_DESC(dgpu_pwr, "dGPU power state (on/off)");


// TODO: sysfs interface


static int sb2_shps_dgpu_set_power(acpi_handle handle, bool on)
{
	union acpi_object *result;
	union acpi_object pkg;
	union acpi_object param[1];

	pkg.type = ACPI_TYPE_PACKAGE;
	pkg.package.count = ARRAY_SIZE(param);
	pkg.package.elements = param;

	param[0].type = ACPI_TYPE_INTEGER;
	param[0].integer.value = on;

	result = acpi_evaluate_dsm_typed(handle, &SB2_SHPS_DSM_UUID, SB2_SHPS_DSM_REVISION,
	                                 SB2_SHPS_DSM_GPU_STATE, &pkg, ACPI_TYPE_BUFFER);

	if (IS_ERR_OR_NULL(result)) {
		return result ? PTR_ERR(result) : -EFAULT;
	}

	if (result->buffer.length != 1 || result->buffer.pointer[0] != 0) {
		return -EIO;
	}

	printk(KERN_INFO "SB2 SHPS: dGPU power state set to \'%d\'\n", on);

	ACPI_FREE(result);
	return 0;
}

static int sb2_shps_probe(struct platform_device *pdev)
{
	struct acpi_device *shps_dev = ACPI_COMPANION(&pdev->dev);
	acpi_handle shps = ACPI_HANDLE(&pdev->dev);
	int status = 0;

	if (gpiod_count(&pdev->dev, NULL) < 0) {
		return -ENODEV;
	}

	status = acpi_dev_add_driver_gpios(shps_dev, sb2_mshw0153_acpi_gpios);
	if (status) {
		return status;
	}

	status = sb2_shps_dgpu_set_power(shps, sb2_dgpu_default_pwr);
	if (status) {
		acpi_dev_remove_driver_gpios(shps_dev);
		return status;
	}

	return 0;
}

static int sb2_shps_remove(struct platform_device *pdev)
{
	struct acpi_device *shps_dev = ACPI_COMPANION(&pdev->dev);

	acpi_dev_remove_driver_gpios(shps_dev);

	return 0;
}


static const struct acpi_device_id sb2_shps_acpi_match[] = {
	{ "MSHW0153", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, sb2_shps_acpi_match);

static struct platform_driver sb2_shps_driver = {
	.probe = sb2_shps_probe,
	.remove = sb2_shps_remove,
	.driver = {
		.name = "sb2_shps",
		.acpi_match_table = ACPI_PTR(sb2_shps_acpi_match),
	},
};
module_platform_driver(sb2_shps_driver);

MODULE_AUTHOR("Maximilian Luz");
MODULE_DESCRIPTION("Surface Book 2 Hot-Plug System Driver");
MODULE_LICENSE("GPL v2");

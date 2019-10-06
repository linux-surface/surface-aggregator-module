#include <linux/acpi.h>
#include <linux/gpio.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/sysfs.h>


// TODO: turn off dGPU Root Port when dgpu_presence changes to 'not-present'
// TODO: restore previous power state when dgpu_presence changes to 'present'?
// TODO: check dGPU presence before attempting any operations?
// TODO: proper suspend/resume power-state handling
// TODO: vgaswitcheroo integration
// TODO: module parameters?


#define SHPS_DSM_REVISION	1
#define SHPS_DSM_GPU_POWER	0x05
static const guid_t SHPS_DSM_UUID =
	GUID_INIT(0x5515a847, 0xed55, 0x4b27, 0x83, 0x52, 0xcd,
	          0x32, 0x0e, 0x10, 0x36, 0x0a);


static const struct acpi_gpio_params gpio_base_presence_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_base_presence     = { 1, 0, false };
static const struct acpi_gpio_params gpio_dgpu_power_int    = { 2, 0, false };
static const struct acpi_gpio_params gpio_dgpu_power        = { 3, 0, false };
static const struct acpi_gpio_params gpio_dgpu_presence_int = { 4, 0, false };
static const struct acpi_gpio_params gpio_dgpu_presence     = { 5, 0, false };

static const struct acpi_gpio_mapping shps_acpi_gpios[] = {
	{ "base_presence-int-gpio", &gpio_base_presence_int, 1 },
	{ "base_presence-gpio",     &gpio_base_presence,     1 },
	{ "dgpu_power-int-gpio",    &gpio_dgpu_power_int,    1 },
	{ "dgpu_power-gpio",        &gpio_dgpu_power,        1 },
	{ "dgpu_presence-int-gpio", &gpio_dgpu_presence_int, 1 },
	{ "dgpu_presence-gpio",     &gpio_dgpu_presence,     1 },
	{ },
};


enum shps_dgpu_power {
	SHPS_DGPU_POWER_OFF      = 0,
	SHPS_DGPU_POWER_ON       = 1,
	SHPS_DGPU_POWER_UNKNOWN  = 2,
};

static const char* shps_dgpu_power_str(enum shps_dgpu_power power) {
	if (power == SHPS_DGPU_POWER_OFF)
		return "off";
	else if (power == SHPS_DGPU_POWER_ON)
		return "on";
	else if (power == SHPS_DGPU_POWER_UNKNOWN)
		return "unknown";
	else
		return "<invalid>";
}


struct shps_driver_data {
	struct pci_dev *dgpu_root_port;
	struct gpio_desc *gpio_dgpu_power;
	struct gpio_desc *gpio_dgpu_presence;
	struct gpio_desc *gpio_base_presence;
};


static int shps_dgpu_dsm_get_power(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct gpio_desc *gpio = drvdata->gpio_dgpu_power;
	int status;

	status = gpiod_get_value_cansleep(gpio);
	if (status < 0)
		return status;

	return status == 0 ? SHPS_DGPU_POWER_OFF : SHPS_DGPU_POWER_ON;
}

static int __shps_dgpu_dsm_set_power(struct platform_device *pdev, enum shps_dgpu_power power)
{
	acpi_handle handle = ACPI_HANDLE(&pdev->dev);
	union acpi_object *result;
	union acpi_object param;

	dev_info(&pdev->dev, "shps: setting dGPU direct power to \'%s\'\n", shps_dgpu_power_str(power));

	param.type = ACPI_TYPE_INTEGER;
	param.integer.value = power == SHPS_DGPU_POWER_ON;

	result = acpi_evaluate_dsm_typed(handle, &SHPS_DSM_UUID, SHPS_DSM_REVISION,
	                                 SHPS_DSM_GPU_POWER, &param, ACPI_TYPE_BUFFER);

	if (IS_ERR_OR_NULL(result))
		return result ? PTR_ERR(result) : -EIO;

	// check for the expected result
	if (result->buffer.length != 1 || result->buffer.pointer[0] != 0) {
		ACPI_FREE(result);
		return -EIO;
	}

	ACPI_FREE(result);
	return 0;
}

static int shps_dgpu_dsm_set_power(struct platform_device *pdev, enum shps_dgpu_power power)
{
	int status;

	if (power != SHPS_DGPU_POWER_ON && power != SHPS_DGPU_POWER_OFF)
		return -EINVAL;

	status = shps_dgpu_dsm_get_power(pdev);
	if (status < 0)
		return status;
	if (status == power)
		return 0;

	return __shps_dgpu_dsm_set_power(pdev, power);
}


static int shps_dgpu_rp_get_power(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct pci_dev *rp = drvdata->dgpu_root_port;

	if (rp->current_state == PCI_D3hot || rp->current_state == PCI_D3cold)
		return SHPS_DGPU_POWER_OFF;
	else if (rp->current_state == PCI_UNKNOWN || rp->current_state == PCI_POWER_ERROR)
		return SHPS_DGPU_POWER_UNKNOWN;
	else
		return SHPS_DGPU_POWER_ON;
}

static int __shps_dgpu_rp_set_power(struct platform_device *pdev, enum shps_dgpu_power power)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct pci_dev *rp = drvdata->dgpu_root_port;
	int status;

	dev_info(&pdev->dev, "shps: setting dGPU power state to \'%s\'\n", shps_dgpu_power_str(power));

	if (power == SHPS_DGPU_POWER_ON) {
		pci_set_power_state(rp, PCI_D0);
		pci_restore_state(rp);

		status = pci_enable_device(rp);
		if (status)
			return status;

		pci_set_master(rp);
	} else {
		pci_save_state(rp);
		pci_clear_master(rp);
		pci_disable_device(rp);
		pci_set_power_state(rp, PCI_D3cold);
	}

	return 0;
}

static int shps_dgpu_rp_set_power(struct platform_device *pdev, enum shps_dgpu_power power)
{
	int status;

	if (power != SHPS_DGPU_POWER_ON && power != SHPS_DGPU_POWER_OFF)
		return -EINVAL;

	status = shps_dgpu_rp_get_power(pdev);
	if (status < 0)
		return status;
	if (status == power)
		return 0;

	return __shps_dgpu_rp_set_power(pdev, power);
}


static ssize_t dgpu_power_show(struct device *dev, struct device_attribute *attr, char *data)
{
	struct platform_device *pdev = to_platform_device(dev);
	int power = shps_dgpu_rp_get_power(pdev);

	if (power < 0)
		return power;

	return sprintf(data, "%s\n", shps_dgpu_power_str(power));
}

static ssize_t dgpu_power_store(struct device *dev, struct device_attribute *attr,
                                const char *data, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	enum shps_dgpu_power power;
	bool b = false;
	int status;

	status = kstrtobool(data, &b);
	if (status)
		return status;

	power = b ? SHPS_DGPU_POWER_ON : SHPS_DGPU_POWER_OFF;
	status = shps_dgpu_rp_set_power(pdev, power);

	return status < 0 ? status : count;
}

static ssize_t dgpu_power_dsm_show(struct device *dev, struct device_attribute *attr, char *data)
{
	struct platform_device *pdev = to_platform_device(dev);
	int power = shps_dgpu_dsm_get_power(pdev);

	if (power < 0)
		return power;

	return sprintf(data, "%s\n", shps_dgpu_power_str(power));
}

static ssize_t dgpu_power_dsm_store(struct device *dev, struct device_attribute *attr,
                                    const char *data, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	enum shps_dgpu_power power;
	bool b = false;
	int status;

	status = kstrtobool(data, &b);
	if (status)
		return status;

	power = b ? SHPS_DGPU_POWER_ON : SHPS_DGPU_POWER_OFF;
	status = shps_dgpu_dsm_set_power(pdev, power);

	return status < 0 ? status : count;
}

static DEVICE_ATTR_RW(dgpu_power);
static DEVICE_ATTR_RW(dgpu_power_dsm);

static struct attribute *shps_power_attrs[] = {
	&dev_attr_dgpu_power.attr,
	&dev_attr_dgpu_power_dsm.attr,
	NULL,
};
ATTRIBUTE_GROUPS(shps_power);


static int shps_suspend(struct device *dev)
{
	return 0;	// TODO: set state on suspend?
}

static int shps_resume(struct device *dev)
{
	return 0;	// TODO: set state on resume?
}


static struct pci_dev *shps_find_dgpu(void)
{
	struct pci_dev *dev = NULL;
	int class = PCI_CLASS_DISPLAY_3D << 8;

	while ((dev = pci_get_class(class, dev)) != NULL) {
		if (dev->vendor == PCI_VENDOR_ID_NVIDIA) {
			break;
		}
	}

	return dev;
}

static struct pci_dev *shps_find_dgpu_root_port(void)
{
	struct pci_dev *dgpu, *root_port;

	dgpu = shps_find_dgpu();
	if (!dgpu)
		return NULL;

	root_port = pci_find_pcie_root_port(dgpu);
	pci_dev_put(dgpu);

	return root_port;
}

static int shps_gpios_setup(struct platform_device *pdev, struct shps_driver_data *drvdata)
{
	struct gpio_desc *gpio_dgpu_power;
	struct gpio_desc *gpio_dgpu_presence;
	struct gpio_desc *gpio_base_presence;
	int status;

	// get GPIOs
	gpio_dgpu_power = devm_gpiod_get(&pdev->dev, "dgpu_power", GPIOD_IN);
	if (IS_ERR(gpio_dgpu_power)) {
		status = PTR_ERR(gpio_dgpu_power);
		goto err_out;
	}

	gpio_dgpu_presence = devm_gpiod_get(&pdev->dev, "dgpu_presence", GPIOD_IN);
	if (IS_ERR(gpio_dgpu_presence)) {
		status = PTR_ERR(gpio_dgpu_presence);
		goto err_out;
	}

	gpio_base_presence = devm_gpiod_get(&pdev->dev, "base_presence", GPIOD_IN);
	if (IS_ERR(gpio_base_presence)) {
		status = PTR_ERR(gpio_base_presence);
		goto err_out;
	}

	// export GPIOs
	status = gpiod_export(gpio_dgpu_power, false);
	if (status)
		goto err_out;

	status = gpiod_export(gpio_dgpu_presence, false);
	if (status)
		goto err_export_dgpu_presence;

	status = gpiod_export(gpio_base_presence, false);
	if (status)
		goto err_export_base_presence;

	// create sysfs links
	status = gpiod_export_link(&pdev->dev, "gpio-dgpu_power", gpio_dgpu_power);
	if (status)
		goto err_link_dgpu_power;

	status = gpiod_export_link(&pdev->dev, "gpio-dgpu_presence", gpio_dgpu_presence);
	if (status)
		goto err_link_dgpu_presence;

	status = gpiod_export_link(&pdev->dev, "gpio-base_presence", gpio_base_presence);
	if (status)
		goto err_link_base_presence;

	drvdata->gpio_dgpu_power = gpio_dgpu_power;
	drvdata->gpio_dgpu_presence = gpio_dgpu_presence;
	drvdata->gpio_base_presence = gpio_base_presence;
	return 0;

err_link_base_presence:
	sysfs_remove_link(&pdev->dev.kobj, "gpio-dgpu_presence");
err_link_dgpu_presence:
	sysfs_remove_link(&pdev->dev.kobj, "gpio-dgpu_power");
err_link_dgpu_power:
	gpiod_unexport(gpio_base_presence);
err_export_base_presence:
	gpiod_unexport(gpio_dgpu_presence);
err_export_dgpu_presence:
	gpiod_unexport(gpio_dgpu_power);
err_out:
	return status;
}

static void shps_gpios_remove(struct platform_device *pdev, struct shps_driver_data *drvdata)
{
	sysfs_remove_link(&pdev->dev.kobj, "gpio-base_presence");
	sysfs_remove_link(&pdev->dev.kobj, "gpio-dgpu_presence");
	sysfs_remove_link(&pdev->dev.kobj, "gpio-dgpu_power");
	gpiod_unexport(drvdata->gpio_base_presence);
	gpiod_unexport(drvdata->gpio_dgpu_presence);
	gpiod_unexport(drvdata->gpio_dgpu_power);
}

static int shps_probe(struct platform_device *pdev)
{
	struct acpi_device *shps_dev = ACPI_COMPANION(&pdev->dev);
	struct shps_driver_data *drvdata;
	int status = 0;

	if (gpiod_count(&pdev->dev, NULL) < 0)
		return -ENODEV;

	status = acpi_dev_add_driver_gpios(shps_dev, shps_acpi_gpios);
	if (status)
		return status;

	drvdata = kzalloc(sizeof(struct shps_driver_data), GFP_KERNEL);
	if (!drvdata) {
		status = -ENOMEM;
		goto err_drvdata;
	}

	drvdata->dgpu_root_port = shps_find_dgpu_root_port();
	if (!drvdata->dgpu_root_port) {
		status = -ENODEV;
		goto err_rp_lookup;
	}

	status = shps_gpios_setup(pdev, drvdata);
	if (status)
		goto err_gpio;

	status = device_add_groups(&pdev->dev, shps_power_groups);
	if (status)
		goto err_devattr;

	platform_set_drvdata(pdev, drvdata);
	return 0;

err_devattr:
	shps_gpios_remove(pdev, drvdata);
err_gpio:
	pci_dev_put(drvdata->dgpu_root_port);
err_rp_lookup:
	kfree(drvdata);
err_drvdata:
	acpi_dev_remove_driver_gpios(shps_dev);
	return status;
}

static int shps_remove(struct platform_device *pdev)
{
	struct acpi_device *shps_dev = ACPI_COMPANION(&pdev->dev);
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);

	device_remove_groups(&pdev->dev, shps_power_groups);

	shps_gpios_remove(pdev, drvdata);
	pci_dev_put(drvdata->dgpu_root_port);
	platform_set_drvdata(pdev, NULL);
	kfree(drvdata);

	acpi_dev_remove_driver_gpios(shps_dev);
	return 0;
}


static SIMPLE_DEV_PM_OPS(shps_pm_ops, shps_suspend, shps_resume);

static const struct acpi_device_id shps_acpi_match[] = {
	{ "MSHW0153", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, shps_acpi_match);

static struct platform_driver shps_driver = {
	.probe = shps_probe,
	.remove = shps_remove,
	.driver = {
		.name = "surface_dgpu_hps",
		.acpi_match_table = ACPI_PTR(shps_acpi_match),
		.pm = &shps_pm_ops,
	},
};
module_platform_driver(shps_driver);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface Book 2 dGPU Hot-Plug System Driver");
MODULE_LICENSE("GPL v2");

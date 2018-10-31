#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

#include "surfacegen5_acpi_notify_san.h"


#define SG5_IRQ_NOTIFY_TIMEOUT		5000


static const struct acpi_gpio_params gpio_base_presence_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_base_presence     = { 1, 0, false };
static const struct acpi_gpio_params gpio_dgpu_power_int    = { 2, 0, false };
static const struct acpi_gpio_params gpio_dgpu_power        = { 3, 0, false };
static const struct acpi_gpio_params gpio_dgpu_presence_int = { 4, 0, false };
static const struct acpi_gpio_params gpio_dgpu_presence     = { 5, 0, false };

static const struct acpi_gpio_mapping sg5_mshw0153_acpi_gpios[] = {
	{ "base_presence-int-gpio", &gpio_base_presence_int, 1 },
	{ "base_presence-gpio",     &gpio_base_presence,     1 },
	{ "dgpu_power-int-gpio",    &gpio_dgpu_power_int,    1 },
	{ "dgpu_power-gpio",        &gpio_dgpu_power,        1 },
	{ "dgpu_presence-int-gpio", &gpio_dgpu_presence_int, 1 },
	{ "dgpu_presence-gpio",     &gpio_dgpu_presence,     1 },
	{ },
};


struct sg5_shps_data {
	struct device *dev;
	unsigned int base_presence_irq;
};


static int sg5_irq_from_gpio(struct device *dev, const char* id)
{
	struct gpio_desc *gpio;
	int irq;

	gpio = gpiod_get(dev, id, GPIOD_IN);
	if (IS_ERR(gpio)) {
		return -ENXIO;
	}

	irq = gpiod_to_irq(gpio);

	gpiod_put(gpio);
	return irq;
}

static irqreturn_t sg5_base_state_irq_check(int irq, void *vdata)
{
	return IRQ_WAKE_THREAD;
}

static irqreturn_t sg5_base_state_irq_handler(int irq, void *vdata)
{
	struct sg5_shps_data *data = vdata;
	int status;

	dev_info(data->dev, "notifying battery presence change\n");

	msleep(SG5_IRQ_NOTIFY_TIMEOUT);

	// re-check secondary battery
	status = surfacegen5_acpi_notify_power_event(SURFACEGEN5_PWR_EVENT_BAT2_INFO);
	if (status) {
		dev_err(data->dev, "failed to send BAT2_INFO_CHANGED event\n");
		return IRQ_HANDLED;
	}

	// re-check primary battery (power-adapter may be connected to base)
	status = surfacegen5_acpi_notify_power_event(SURFACEGEN5_PWR_EVENT_BAT1_STAT);
	if (status) {
		dev_err(data->dev, "failed to send BAT1_STATE_CHANGED event\n");
		return IRQ_HANDLED;
	}

	// re-check power adapter (may be connected to base)
	status = surfacegen5_acpi_notify_power_event(SURFACEGEN5_PWR_EVENT_ADP1_STAT);
	if (status) {
		dev_err(data->dev, "failed to send ADP1_STATE_CHANGED event\n");
		return IRQ_HANDLED;
	}

	return IRQ_HANDLED;
}

static int sg5_base_state_irq_setup(struct device *dev, struct sg5_shps_data *data)
{
	const int irqflags = IRQF_SHARED | IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING;
	int base_presence_irq;
	int status;

	dev_info(dev, "sg5_base_state_irq_setup\n");

	base_presence_irq = sg5_irq_from_gpio(dev, "base_presence-int");
	if (base_presence_irq < 0) {
		dev_warn(dev, "failed to get base_presence-int GPIO\n");
		return base_presence_irq;
	}

	status = request_threaded_irq(base_presence_irq, sg5_base_state_irq_check,
	                              sg5_base_state_irq_handler, irqflags,
                                      "surfacegen5-int-base_presence", data);
	if (status) {
		return status;
	}

	data->base_presence_irq = base_presence_irq;

	return 0;
}

static void sg5_base_state_irq_free(struct device *dev, struct sg5_shps_data *data)
{
	free_irq(data->base_presence_irq, data);
}


static int surfacegen5_acpi_notify_shps_probe(struct platform_device *pdev)
{
	struct acpi_device *shps_dev = ACPI_COMPANION(&pdev->dev);
	struct sg5_shps_data *data;
	int status = 0;

	dev_info(&pdev->dev, "surfacegen5_acpi_notify_shps_probe\n");

	if (gpiod_count(&pdev->dev, NULL) < 0) {
		dev_err(&pdev->dev, "no GPIOs found\n");
		return -ENODEV;
	}

	status = acpi_dev_add_driver_gpios(shps_dev, sg5_mshw0153_acpi_gpios);
	if (status) {
		dev_err(&pdev->dev, "failed to register GPIO names\n");
		return status;
	}

	data = kzalloc(sizeof(struct sg5_shps_data), GFP_KERNEL);
	if (!data) {
		status = -ENOMEM;
		goto err_alloc;
	}

	data->dev = &pdev->dev;

	status = sg5_base_state_irq_setup(&pdev->dev, data);
	if (status) {
		goto err_irq_setup;
	}

	platform_set_drvdata(pdev, data);
	return 0;

err_irq_setup:
	kfree(data);
err_alloc:
	acpi_dev_remove_driver_gpios(shps_dev);
	return status;
}

static int surfacegen5_acpi_notify_shps_remove(struct platform_device *pdev)
{
	struct acpi_device *shps_dev = ACPI_COMPANION(&pdev->dev);
	struct sg5_shps_data *data = platform_get_drvdata(pdev);

	dev_info(&pdev->dev, "surfacegen5_acpi_notify_shps_remove\n");

	sg5_base_state_irq_free(&pdev->dev, data);
	kfree(data);

	acpi_dev_remove_driver_gpios(shps_dev);
	return 0;
}

static const struct acpi_device_id surfacegen5_acpi_notify_shps_match[] = {
	{ "MSHW0153", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surfacegen5_acpi_notify_shps_match);

struct platform_driver surfacegen5_acpi_notify_shps = {
	.probe = surfacegen5_acpi_notify_shps_probe,
	.remove = surfacegen5_acpi_notify_shps_remove,
	.driver = {
		.name = "surfacegen5_acpi_notify_shps",
		.acpi_match_table = ACPI_PTR(surfacegen5_acpi_notify_shps_match),
	},
};

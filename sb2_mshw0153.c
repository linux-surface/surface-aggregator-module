#include <linux/acpi.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

// Notes:
// - we should probably also listen to acpi notify events


static const struct acpi_gpio_params gpio_unknown1_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_unknown1     = { 1, 0, false };
static const struct acpi_gpio_params gpio_unknown2_int = { 2, 0, false };
static const struct acpi_gpio_params gpio_unknown2     = { 3, 0, false };
static const struct acpi_gpio_params gpio_unknown3_int = { 4, 0, false };
static const struct acpi_gpio_params gpio_unknown3     = { 5, 0, false };

static const struct acpi_gpio_mapping sb2_mshw0153_acpi_gpios[] = {
	{ "unknown1-int-gpio", &gpio_unknown1_int, 1 },
	{ "unknown1-gpio",     &gpio_unknown1,     1 },
	{ "unknown2-int-gpio", &gpio_unknown2_int, 1 },
	{ "unknown2-gpio",     &gpio_unknown2,     1 },
	{ "unknown3-int-gpio", &gpio_unknown3_int, 1 },
	{ "unknown3-gpio",     &gpio_unknown3,     1 },
	{ },
};


struct sb2_mshw0153_irq_data {
	struct device *dev;
	const char *desc;
};

struct sb2_mshw0153_irq {
	unsigned int gpio1;
	unsigned int gpio2;
	unsigned int gpio3;
	struct sb2_mshw0153_irq_data *gpio1_data;
	struct sb2_mshw0153_irq_data *gpio2_data;
	struct sb2_mshw0153_irq_data *gpio3_data;
};

struct sb2_mshw0153_data {
	struct sb2_mshw0153_irq irq;
};



static int sb2_mshw0153_dump_gpio_status(struct device *dev, struct gpio_desc *gpio, const char *id)
{
	int direction = 0;
	int status = 0;
	int value = 0;

	direction = gpiod_get_direction(gpio);
	if (direction < 0) {
		return direction;
	}

	dev_info(dev, "gpio [%s] direction: %x\n", id, direction);

	status = gpiod_direction_input(gpio);
	if (status) {
		return status;
	}

	value = gpiod_get_value_cansleep(gpio);
	if (value < 0) {
		return value;
	}

	dev_info(dev, "gpio [%s] value: %x\n", id, value);

	return 0;
}

static int sb2_mshw0153_dump_gpios(struct device *dev)
{
	struct gpio_desc *gd1 = NULL;
	struct gpio_desc *gd2 = NULL;
	struct gpio_desc *gd3 = NULL;
	int status = 0;

	dev_info(dev, "printing current GPIO values\n");

	gd1 = gpiod_get(dev, "unknown1", GPIOD_ASIS);
	if (!IS_ERR(gd1)) {
		status = sb2_mshw0153_dump_gpio_status(dev, gd1, "1");
		gpiod_put(gd1);

		if (status) {
			return status;
		}
	} else {
		dev_err(dev, "cannot access gpio [1]: %lx\n", PTR_ERR(gd1));
	}

	gd2 = gpiod_get(dev, "unknown2", GPIOD_ASIS);
	if (!IS_ERR(gd2)) {
		status = sb2_mshw0153_dump_gpio_status(dev, gd2, "2");
		gpiod_put(gd2);

		if (status) {
			return status;
		}
	} else {
		dev_err(dev, "cannot access gpio [2]: %lx\n", PTR_ERR(gd2));
	}

	gd3 = gpiod_get(dev, "unknown3", GPIOD_ASIS);
	if (!IS_ERR(gd3)) {
		status = sb2_mshw0153_dump_gpio_status(dev, gd3, "3");
		gpiod_put(gd3);

		if (status) {
			return status;
		}
	} else {
		dev_err(dev, "cannot access gpio [3]: %lx\n", PTR_ERR(gd3));
	}

	return 0;
}


static irqreturn_t sb2_mshw0153_irq_handler(int irq, void* vdata)
{
	struct sb2_mshw0153_irq_data *data = vdata;

	// FIXME: we probably should not do this in a hardirq context?
	dev_info(data->dev, "interrupt handler called [%s]", data->desc);

	return IRQ_HANDLED;
}

static int sb2_mshw0153_irq_from_gpio(struct device *dev, const char* id)
{
	struct gpio_desc *gpio = NULL;
	int irq = -ENXIO;

	gpio = gpiod_get(dev, id, GPIOD_ASIS);
	if (IS_ERR(gpio)) {
		return -ENXIO;
	}

	irq = gpiod_to_irq(gpio);

	gpiod_put(gpio);
	return irq;
}

static int sb2_mshw0153_irq_init(struct device *dev, struct sb2_mshw0153_irq *irq)
{
	int gpio1_irq = -ENXIO;
	int gpio2_irq = -ENXIO;
	int gpio3_irq = -ENXIO;

	struct sb2_mshw0153_irq_data *gpio1_irq_data = NULL;
	struct sb2_mshw0153_irq_data *gpio2_irq_data = NULL;
	struct sb2_mshw0153_irq_data *gpio3_irq_data = NULL;

	const int irq_flags = IRQF_SHARED | IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING;

	int status = 0;

	// get IRQ IDs
	gpio1_irq = sb2_mshw0153_irq_from_gpio(dev, "unknown1-int");
	if (gpio1_irq < 0) {
		return gpio1_irq;
	}

	gpio2_irq = sb2_mshw0153_irq_from_gpio(dev, "unknown2-int");
	if (gpio2_irq < 0) {
		return gpio2_irq;
	}

	gpio3_irq = sb2_mshw0153_irq_from_gpio(dev, "unknown3-int");
	if (gpio3_irq < 0) {
		return gpio3_irq;
	}

	// allocate IRQ handler data
	gpio1_irq_data = kzalloc(sizeof(struct sb2_mshw0153_irq_data), GFP_KERNEL);
	if (!gpio1_irq_data) {
		status = -ENOMEM;
		goto err_gpio1_data;
	}

	gpio2_irq_data = kzalloc(sizeof(struct sb2_mshw0153_irq_data), GFP_KERNEL);
	if (!gpio2_irq_data) {
		status = -ENOMEM;
		goto err_gpio2_data;
	}

	gpio3_irq_data = kzalloc(sizeof(struct sb2_mshw0153_irq_data), GFP_KERNEL);
	if (!gpio3_irq_data) {
		status = -ENOMEM;
		goto err_gpio3_data;
	}

	// initialize IRQ handler data
	gpio1_irq_data->dev = dev;
	gpio1_irq_data->desc = "1";

	gpio2_irq_data->dev = dev;
	gpio2_irq_data->desc = "2";

	gpio3_irq_data->dev = dev;
	gpio3_irq_data->desc = "3";

	// setup IRQ request handlers
	status = request_irq(gpio1_irq, sb2_mshw0153_irq_handler,
			irq_flags, "sb2_mshw0153-int-unknown1", gpio1_irq_data);
	if (status) {
		goto err_gpio1_int;
	}

	status = request_irq(gpio2_irq, sb2_mshw0153_irq_handler,
			irq_flags, "sb2_mshw0153-int-unknown2", gpio2_irq_data);
	if (status) {
		goto err_gpio2_int;
	}

	status = request_irq(gpio3_irq, sb2_mshw0153_irq_handler,
			irq_flags, "sb2_mshw0153-int-unknown2", gpio3_irq_data);
	if (status) {
		goto err_gpio3_int;
	}

	// set returned data
	irq->gpio1 = gpio1_irq;
	irq->gpio1_data = gpio1_irq_data;

	irq->gpio2 = gpio2_irq;
	irq->gpio2_data = gpio2_irq_data;

	irq->gpio3 = gpio3_irq;
	irq->gpio3_data = gpio3_irq_data;

	return 0;

err_gpio3_int:
	free_irq(gpio2_irq, gpio2_irq_data);
err_gpio2_int:
	free_irq(gpio1_irq, gpio1_irq_data);
err_gpio1_int:
	kfree(gpio3_irq_data);
err_gpio3_data:
	kfree(gpio2_irq_data);
err_gpio2_data:
	kfree(gpio1_irq_data);
err_gpio1_data:
	return status;
}

static void sb2_mshw0153_irq_free(struct sb2_mshw0153_irq *irq)
{
	free_irq(irq->gpio1, irq->gpio1_data);
	free_irq(irq->gpio2, irq->gpio2_data);
	free_irq(irq->gpio3, irq->gpio3_data);

	kfree(irq->gpio1_data);
	kfree(irq->gpio2_data);
	kfree(irq->gpio3_data);
}


static int sb2_mshw0153_probe(struct platform_device *pdev)
{
	struct acpi_device *shps_dev = ACPI_COMPANION(&pdev->dev);
	struct sb2_mshw0153_data *data = NULL;
	int status = 0;

	if (gpiod_count(&pdev->dev, NULL) < 0) {
		return -ENODEV;
	}

	status = acpi_dev_add_driver_gpios(shps_dev, sb2_mshw0153_acpi_gpios);
	if (status) {
		return status;
	}

	// dump current states
	status = sb2_mshw0153_dump_gpios(&pdev->dev);
	if (status) {
		goto err_alloc;
	}

	// allocate driver data
	data = kzalloc(sizeof(struct sb2_mshw0153_data), GFP_KERNEL);
	if (!data) {
		status = -ENOMEM;
		goto err_alloc;
	}

	// initialize GPIO interrupts
	status = sb2_mshw0153_irq_init(&pdev->dev, &data->irq);
	if (status) {
		goto err_init;
	}

	platform_set_drvdata(pdev, data);

	return 0;

err_init:
	kfree(data);
err_alloc:
	acpi_dev_remove_driver_gpios(shps_dev);
	return status;
}

static int sb2_mshw0153_remove(struct platform_device *pdev)
{
	struct acpi_device *shps_dev = ACPI_COMPANION(&pdev->dev);
	struct sb2_mshw0153_data *data = NULL;
	int status = 0;

	data = platform_get_drvdata(pdev);
	sb2_mshw0153_irq_free(&data->irq);
	kfree(data);

	acpi_dev_remove_driver_gpios(shps_dev);

	return status;
}


static const struct acpi_device_id sb2_mshw0153_acpi_match[] = {
	{ "MSHW0153", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, sb2_mshw0153_acpi_match);

static struct platform_driver sb2_platform_driver = {
	.probe = sb2_mshw0153_probe,
	.remove = sb2_mshw0153_remove,
	.driver = {
		.name = "sb2_mshw0153",
		.acpi_match_table = ACPI_PTR(sb2_mshw0153_acpi_match),
	},
};
module_platform_driver(sb2_platform_driver);

MODULE_AUTHOR("Maximilian Luz");
MODULE_DESCRIPTION("Surface Book 2 MSHW0153 driver");
MODULE_LICENSE("GPL v2");

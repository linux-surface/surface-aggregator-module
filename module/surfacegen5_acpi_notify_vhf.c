#include <linux/acpi.h>
#include <linux/platform_device.h>

#include "surfacegen5_acpi_notify_ssh.h"


/*
 * Request ID for VHF events. This value is based on the output of the Surface
 * EC and should not be changed.
 */
#define SG5_VHF_RQID	0x0001


struct surfacegen5_vhf_evtctx {
	struct device *dev;
};

struct surfacegen5_vhf_drvdata {
	struct device_link           *ec_link;
	struct surfacegen5_vhf_evtctx event_ctx;
};


static int surfacegen5_vhf_handle_event(struct surfacegen5_event *event, void *data)
{
	struct surfacegen5_vhf_evtctx *ctx = (struct surfacegen5_vhf_evtctx *)data;

	if (event->tc == 0x08 && (event->cid == 0x03 || event->cid == 0x04)) {

		// TODO: handle keyboard event
		dev_warn(ctx->dev, "sg5_vhf: received HID record of length %d\n", event->len);

		return 0;
	}

	dev_warn(ctx->dev, "sg5_vhf: unsupported event (tc = %d, cid = %d)\n", event->tc, event->cid);
	return 0;
}

static int surfacegen5_vhf_probe(struct platform_device *pdev)
{
	struct surfacegen5_vhf_drvdata *drvdata;
	struct device_link *ec_link;
	int status;

	drvdata = kzalloc(sizeof(struct surfacegen5_vhf_drvdata), GFP_KERNEL);
	if (!drvdata) {
		return -ENOMEM;
	}

	// add device link to EC
	ec_link = surfacegen5_ec_consumer_add(&pdev->dev, DL_FLAG_PM_RUNTIME);
	if (IS_ERR_OR_NULL(ec_link)) {
		if (PTR_ERR(ec_link) == -ENXIO) {
			status = -EPROBE_DEFER;
		} else {
			status = -EFAULT;
		}

		goto err_probe_ec_link;
	}

	drvdata->ec_link = ec_link;
	drvdata->event_ctx.dev = &pdev->dev;

	platform_set_drvdata(pdev, drvdata);

	/*
         * Set event hanlder for VHF events. They seem to be enabled by
         * default, thus there should be no need to explicitly enable them.
	 */
	status = surfacegen5_ec_set_event_handler(SG5_VHF_RQID,
	                                          surfacegen5_vhf_handle_event,
						  &drvdata->event_ctx);
	if (status) {
		goto err_event_handler;
	}

	dev_info(&pdev->dev, "sg5_vhf: probe successful\n");

	return 0;

err_event_handler:
	platform_set_drvdata(pdev, NULL);
	surfacegen5_ec_consumer_remove(drvdata->ec_link);
err_probe_ec_link:
	kfree(drvdata);
	return status;
}

static int surfacegen5_vhf_remove(struct platform_device *pdev)
{
	struct surfacegen5_vhf_drvdata *drvdata = platform_get_drvdata(pdev);

	surfacegen5_ec_remove_event_handler(SG5_VHF_RQID);

	surfacegen5_ec_consumer_remove(drvdata->ec_link);
	kfree(drvdata);

	platform_set_drvdata(pdev, NULL);
	return 0;
}


static const struct acpi_device_id surfacegen5_vhf_match[] = {
	{ "MSHW0096" },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surfacegen5_vhf_match);

struct platform_driver surfacegen5_vhf = {
	.probe = surfacegen5_vhf_probe,
	.remove = surfacegen5_vhf_remove,
	.driver = {
		.name = "surfacegen5_vhf",
		.acpi_match_table = ACPI_PTR(surfacegen5_vhf_match),
	},
};

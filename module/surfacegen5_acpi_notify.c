#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>


#define surfacegen5_BASE_DETACHED		0x00
#define surfacegen5_BASE_ATTACHED		0x01
#define surfacegen5_BASE_UNDEFINED		0xFF


struct surfacegen5_handler_context {
	struct acpi_connection_info connection;
	struct device *dev;
};

struct gsb_data_in {
	u8 cv;
} __packed;

struct gsb_data_rqsx {
	u8 cv;
	u8 tc;
	u8 tid;
	u8 iid;
	u8 snc;
	u8 cid;
	u8 cdl;
	u8 _pad;
	u8 pld[0];
} __packed;

struct gsb_data_etwl {
	u8 cv;
	u8 etw3;
	u8 etw4;
	char msg[0];
} __packed;

struct gsb_data_out {
	u8 status;
	u8 len;
	u8 pld[0];
} __packed;

union gsb_buffer_data {
	struct gsb_data_in   in;    // common input
	struct gsb_data_rqsx rqsx;  // RQSX input
	struct gsb_data_etwl etwl;  // ETWL input
	struct gsb_data_out  out;   // output
};

struct gsb_buffer {
	u8 status;
	u8 len;
	union gsb_buffer_data data;
} __packed;


static acpi_status
surfacegen5_etwl(struct surfacegen5_handler_context *ctx, struct gsb_buffer *buffer)
{
	struct gsb_data_etwl *etwl = &buffer->data.etwl;

	u8 msglen = buffer->len - 3;
	u8 etw3   = etwl->etw3;
	u8 etw4   = etwl->etw4;
	char *msg = etwl->msg;

	dev_err(ctx->dev, "ETWL(0x%02x, 0x%02x): %.*s\n", etw3, etw4, msglen, msg);
	return AE_OK;
}

static acpi_status
surfacegen5_rqst(struct surfacegen5_handler_context *ctx, struct gsb_buffer *buffer)
{
	struct gsb_data_rqsx *rqsx = &buffer->data.rqsx;

	// temporary fix for base status (lid notify loop)
	if (
		rqsx->tc  == 0x11 &&
		rqsx->tid == 0x01 &&
		rqsx->iid == 0x00 &&
		rqsx->snc == 0x01 &&
		rqsx->cid == 0x0D
	) {
		buffer->status          = 0x00;
		buffer->len             = 0x03;
		buffer->data.out.status = 0x00;
		buffer->data.out.len    = 0x01;
		buffer->data.out.pld[0] = surfacegen5_BASE_ATTACHED;

		return AE_OK;
	}

	// TODO:

	dev_warn(ctx->dev, "unsupported RQST request (tc: 0x%02x, cid: 0x%02x)\n", rqsx->tc, rqsx->cid);
	return AE_OK;
}

static acpi_status
surfacegen5_rqsg(struct surfacegen5_handler_context *ctx, struct gsb_buffer *buffer)
{
	// TODO: implement RQSG handler

	dev_warn(ctx->dev, "unsupported RQSG request\n");
	return AE_OK;
}


static acpi_status
surfacegen5_space_handler(u32 function, acpi_physical_address command,
			u32 bits, u64 *value64,
			void *handler_context, void *region_context)
{
	struct surfacegen5_handler_context *context = handler_context;
	struct gsb_buffer *buffer = (struct gsb_buffer *)value64;

	// TODO: input validation
	// - check lenght of buffer (min. 2 and consistency)
	// - check if command == SAN0 (== 0) ?
	// - check if AttribRawProcessCall?

	switch (buffer->data.in.cv) {
	case 0x01:
		return surfacegen5_rqst(context, buffer);
	case 0x02:
		return surfacegen5_etwl(context, buffer);
	case 0x03:
		return surfacegen5_rqsg(context, buffer);
	}

	dev_dbg(context->dev, "unsupported request (cv: 0x%02x)\n", buffer->data.in.cv);
	return AE_OK;
}


static int surfacegen5_acpi_notify_probe(struct platform_device *pdev)
{
	struct surfacegen5_handler_context *context = NULL;
	acpi_handle san = ACPI_HANDLE(&pdev->dev);	// _SAN device node
	acpi_status status = AE_OK;

	context = kzalloc(sizeof(struct surfacegen5_handler_context), GFP_KERNEL);
	if (!context) {
		return -ENOMEM;
	}

	context->dev = &pdev->dev;

	status = acpi_bus_attach_private_data(san, context);
	if (ACPI_FAILURE(status)) {
		goto err_privdata;
	}

	status = acpi_install_address_space_handler(san,
			ACPI_ADR_SPACE_GSBUS,
			&surfacegen5_space_handler,
			NULL,
			context);

	if (ACPI_FAILURE(status)) {
		goto err_install_handler;
	}

	return status;

err_install_handler:
	acpi_bus_detach_private_data(san);
err_privdata:
	kfree(context);
	return status;
}

static int surfacegen5_acpi_notify_remove(struct platform_device *pdev)
{
	acpi_handle san = ACPI_HANDLE(&pdev->dev);	// _SAN device node
	acpi_status status = AE_OK;

	struct surfacegen5_handler_context *context = NULL;

	acpi_remove_address_space_handler(san, ACPI_ADR_SPACE_GSBUS, &surfacegen5_space_handler);

	status = acpi_bus_get_private_data(san, (void **)&context);
	if (ACPI_SUCCESS(status) && context) {
		kfree(context);
	}
	acpi_bus_detach_private_data(san);

	return status;
}


static const struct acpi_device_id surfacegen5_acpi_match[] = {
	{ "MSHW0091", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surfacegen5_acpi_match);

static struct platform_driver sb2_platform_driver = {
	.probe = surfacegen5_acpi_notify_probe,
	.remove = surfacegen5_acpi_notify_remove,
	.driver = {
		.name = "surfacegen5_acpi_notify",
		.acpi_match_table = ACPI_PTR(surfacegen5_acpi_match),
	},
};
module_platform_driver(sb2_platform_driver);

MODULE_AUTHOR("Maximilian Luz");
MODULE_DESCRIPTION("ACPI Notify Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL v2");

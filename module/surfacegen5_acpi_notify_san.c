#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

#include "surfacegen5_acpi_notify_ssh.h"
#include "surfacegen5_acpi_notify_san.h"

#define SG5_RQST_RETRY          10

#define SG5_RQST_MSG            "surfacegen5_ec_rqst: "
#define SG5_NOTIFY_PWR_MSG      "surfacegen5_acpi_notify_power_event: "

#define SG5_SAN_PATH            "\\_SB._SAN"
#define SG5_SAN_DSM_REVISION    0

static const guid_t SG5_SAN_DSM_UUID =
	GUID_INIT(0x93b666c5, 0x70c6, 0x469f, 0xa2, 0x15, 0x3d,
	          0x48, 0x7c, 0x91, 0xab, 0x3c);


struct surfacegen5_san_handler_context {
	struct acpi_connection_info connection;
	struct device *dev;
};

struct gsb_data_in {
	u8 cv;
} __packed;

struct gsb_data_rqsx {
	u8 cv;				// command value (should be 0x01 or 0x03)
	u8 tc;				// target controller
	u8 tid;				// expected to be 0x01, could be revision
	u8 iid;				// target sub-controller (e.g. primary vs. secondary battery)
	u8 snc;				// expect-response-flag
	u8 cid;				// command ID
	u8 cdl;				// payload length
	u8 _pad;			// padding
	u8 pld[0];			// payload
} __packed;

struct gsb_data_etwl {
	u8 cv;				// command value (should be 0x02)
	u8 etw3;			// ?
	u8 etw4;			// ?
	u8 msg[0];			// error message (ASCIIZ)
} __packed;

struct gsb_data_out {
	u8 status;			// _SSH communication status
	u8 len;				// _SSH payload length
	u8 pld[0];			// _SSH payload
} __packed;

union gsb_buffer_data {
	struct gsb_data_in   in;	// common input
	struct gsb_data_rqsx rqsx;	// RQSX input
	struct gsb_data_etwl etwl;	// ETWL input
	struct gsb_data_out  out;	// output
};

struct gsb_buffer {
	u8 status;			// GSB AttribRawProcess status
	u8 len;				// GSB AttribRawProcess length
	union gsb_buffer_data data;
} __packed;


int surfacegen5_acpi_notify_power_event(enum surfacegen5_pwr_event event)
{
	acpi_handle san;
	union acpi_object *obj;
	int status;

	if (event < _surfacegen5_pwr_event_MIN || event > _surfacegen5_pwr_event_MAX) {
		return -EINVAL;
	}

	status = acpi_get_handle(NULL, SG5_SAN_PATH, &san);
	if (ACPI_FAILURE(status)) {
		printk(KERN_ERR SG5_NOTIFY_PWR_MSG "failed to get _SAN handle\n");
		return status;
	}

	obj = acpi_evaluate_dsm_typed(san, &SG5_SAN_DSM_UUID, SG5_SAN_DSM_REVISION,
	                              (u8) event, NULL, ACPI_TYPE_BUFFER);

	if (IS_ERR_OR_NULL(obj)) {
		printk(KERN_ERR SG5_NOTIFY_PWR_MSG "failed to evaluate _DSM\n");
		return obj ? PTR_ERR(obj) : -EFAULT;
	}

	if (obj->buffer.length != 1 || obj->buffer.pointer[0] != 0) {
		printk(KERN_ERR SG5_NOTIFY_PWR_MSG "got unexpected result from _DSM\n");
		return -EIO;
	}

	ACPI_FREE(obj);
	return 0;
}


static struct gsb_data_rqsx *surfacegen5_san_validate_rqsx(
	struct device *dev, const char *type, struct gsb_buffer *buffer)
{
	struct gsb_data_rqsx *rqsx = &buffer->data.rqsx;

	if (buffer->len < 8) {
		dev_err(dev, "invalid %s package (len = %d)\n",
			type, buffer->len);
		return NULL;
	}

	if (rqsx->cdl != buffer->len - 8) {
		dev_err(dev, "bogus %s package (len = %d, cdl = %d)\n",
			type, buffer->len, rqsx->cdl);
		return NULL;
	}

	if (rqsx->tid != 0x01) {
		dev_warn(dev, "unsupported %s package (tid = 0x%02x)\n",
			 type, rqsx->tid);
		return NULL;
	}

	return rqsx;
}

static acpi_status
surfacegen5_san_etwl(struct surfacegen5_san_handler_context *ctx, struct gsb_buffer *buffer)
{
	struct gsb_data_etwl *etwl = &buffer->data.etwl;

	if (buffer->len < 3) {
		dev_err(ctx->dev, "invalid ETWL package (len = %d)\n", buffer->len);
		return AE_OK;
	}

	dev_err(ctx->dev, "ETWL(0x%02x, 0x%02x): %.*s\n",
		etwl->etw3, etwl->etw4,
		buffer->len - 3, (char *)etwl->msg);

	// indicate success
	buffer->status = 0x00;
	buffer->len = 0x00;

	return AE_OK;
}

static acpi_status
surfacegen5_san_rqst(struct surfacegen5_san_handler_context *ctx, struct gsb_buffer *buffer)
{
	struct gsb_data_rqsx *gsb_rqst = surfacegen5_san_validate_rqsx(ctx->dev, "RQST", buffer);
	struct surfacegen5_rqst rqst = {};
	struct surfacegen5_buf result = {};
	int status = 0;
	int try;

	if (!gsb_rqst) {
		return AE_OK;
	}

	rqst.tc  = gsb_rqst->tc;
	rqst.iid = gsb_rqst->iid;
	rqst.cid = gsb_rqst->cid;
	rqst.snc = gsb_rqst->snc;
	rqst.cdl = gsb_rqst->cdl;
	rqst.pld = &gsb_rqst->pld[0];

	result.cap  = SURFACEGEN5_MAX_RQST_RESPONSE;
	result.len  = 0;
	result.data = kzalloc(result.cap, GFP_KERNEL);

	if (!result.data) {
		return -ENOMEM;
	}

	for (try = 0; try < SG5_RQST_RETRY; try++) {
		if (try) {
			dev_warn(ctx->dev, SG5_RQST_MSG "IO error occured, trying again\n");
		}

		status = surfacegen5_ec_rqst(&rqst, &result);
		if (status != -EIO) break;
	}

	if (!status) {
		buffer->status          = 0x00;
		buffer->len             = result.len + 2;
		buffer->data.out.status = 0x00;
		buffer->data.out.len    = result.len;
		memcpy(&buffer->data.out.pld[0], result.data, result.len);
		dev_info(ctx->dev, SG5_RQST_MSG "succeeded\n");

	} else {
		dev_err(ctx->dev, SG5_RQST_MSG "failed with error %d\n", status);
		buffer->status          = 0x00;
		buffer->len             = 0x02;
		buffer->data.out.status = 0x01;		// indicate _SSH error
		buffer->data.out.len    = 0x00;
	}

	kfree(result.data);

	return AE_OK;
}

static acpi_status
surfacegen5_san_rqsg(struct surfacegen5_san_handler_context *ctx, struct gsb_buffer *buffer)
{
	struct gsb_data_rqsx *rqsg = surfacegen5_san_validate_rqsx(ctx->dev, "RQSG", buffer);
	if (!rqsg) { return AE_OK; }

	// TODO: implement RQSG handler

	dev_warn(ctx->dev, "unsupported request: RQSG(0x%02x, 0x%02x, 0x%02x)\n",
		 rqsg->tc, rqsg->cid, rqsg->iid);

	return AE_OK;
}


static acpi_status
surfacegen5_san_space_handler(u32 function, acpi_physical_address command,
			u32 bits, u64 *value64,
			void *handler_context, void *region_context)
{
	struct surfacegen5_san_handler_context *context = handler_context;
	struct gsb_buffer *buffer = (struct gsb_buffer *)value64;
	int accessor_type = (0xFFFF0000 & function) >> 16;

	if (command != 0) {
		dev_warn(context->dev, "unsupported command: 0x%02llx\n", command);
		return AE_OK;
	}

	if (accessor_type != ACPI_GSB_ACCESS_ATTRIB_RAW_PROCESS) {
		dev_err(context->dev, "invalid access type: 0x%02x\n", accessor_type);
		return AE_OK;
	}

	// buffer must have at least contain the command-value
	if (buffer->len == 0) {
		dev_err(context->dev, "request-package too small\n");
		return AE_OK;
	}

	switch (buffer->data.in.cv) {
	case 0x01:  return surfacegen5_san_rqst(context, buffer);
	case 0x02:  return surfacegen5_san_etwl(context, buffer);
	case 0x03:  return surfacegen5_san_rqsg(context, buffer);
	}

	dev_warn(context->dev, "unsupported SAN0 request (cv: 0x%02x)\n", buffer->data.in.cv);
	return AE_OK;
}


static int surfacegen5_acpi_notify_san_probe(struct platform_device *pdev)
{
	struct surfacegen5_san_handler_context *context = NULL;
	acpi_handle san = ACPI_HANDLE(&pdev->dev);	// _SAN device node
	acpi_status status = AE_OK;

	dev_info(&pdev->dev, "surfacegen5_acpi_notify_san_probe\n");

	/*
	 * Defer probe if the _SSH driver has not set up the controller yet. This
	 * makes sure we do not fail any initial requests (e.g. _STA request without
	 * which the battery does not get set up correctly). Otherwise register as
	 * consumer to set up a device_link.
	 */
	status = surfacegen5_ec_consumer_set(&pdev->dev);
	if (status == -ENXIO) {
		return -EPROBE_DEFER;
	} else if (status) {
		return status;
	}

	context = kzalloc(sizeof(struct surfacegen5_san_handler_context), GFP_KERNEL);
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
			&surfacegen5_san_space_handler,
			NULL,
			context);

	if (ACPI_FAILURE(status)) {
		goto err_install_handler;
	}

	acpi_walk_dep_device_list(san);

	return status;

err_install_handler:
	acpi_bus_detach_private_data(san);
err_privdata:
	kfree(context);
	return status;
}

static int surfacegen5_acpi_notify_san_remove(struct platform_device *pdev)
{
	struct surfacegen5_san_handler_context *context = NULL;
	acpi_handle san = ACPI_HANDLE(&pdev->dev);	// _SAN device node
	acpi_status status = AE_OK;

	dev_info(&pdev->dev, "surfacegen5_acpi_notify_san_remove\n");

	acpi_remove_address_space_handler(san, ACPI_ADR_SPACE_GSBUS, &surfacegen5_san_space_handler);

	status = acpi_bus_get_private_data(san, (void **)&context);
	if (ACPI_SUCCESS(status) && context) {
		kfree(context);
	}
	acpi_bus_detach_private_data(san);

	surfacegen5_ec_consumer_remove(&pdev->dev);

	return status;
}


static const struct acpi_device_id surfacegen5_acpi_notify_san_match[] = {
	{ "MSHW0091", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surfacegen5_acpi_notify_san_match);

struct platform_driver surfacegen5_acpi_notify_san = {
	.probe = surfacegen5_acpi_notify_san_probe,
	.remove = surfacegen5_acpi_notify_san_remove,
	.driver = {
		.name = "surfacegen5_acpi_notify_san",
		.acpi_match_table = ACPI_PTR(surfacegen5_acpi_notify_san_match),
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

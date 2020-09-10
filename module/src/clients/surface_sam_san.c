// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface ACPI Notify (SAN) and ACPI integration driver for SAM.
 * Translates communication from ACPI to SSH and back.
 */

#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

#include "../../include/linux/surface_aggregator_module.h"
#include "../../include/linux/surface_acpi_notify.h"


#define SAM_EVENT_DELAY_PWR_ADAPTER	msecs_to_jiffies(5000)
#define SAM_EVENT_DELAY_PWR_BST		msecs_to_jiffies(2500)

#define SAM_EVENT_PWR_CID_BIX		0x15
#define SAM_EVENT_PWR_CID_BST		0x16
#define SAM_EVENT_PWR_CID_ADAPTER	0x17
#define SAM_EVENT_PWR_CID_DPTF		0x4f

#define SAM_EVENT_TEMP_CID_NOTIFY_SENSOR_TRIP_POINT	0x0b


struct san_acpi_consumer {
	const char *path;
};

struct san_data {
	struct device *dev;
	struct ssam_controller *ctrl;

	struct acpi_connection_info info;

	struct ssam_event_notifier nf_bat;
	struct ssam_event_notifier nf_tmp;
};

#define to_san_data(ptr, member) \
	container_of(ptr, struct san_data, member)

struct san_event_work {
	struct delayed_work work;
	struct device *dev;
	struct ssam_event event;		// must be last
};

struct gsb_data_in {
	u8 cv;
} __packed;

struct gsb_data_rqsx {
	u8 cv;				// command value (should be 0x01 or 0x03)
	u8 tc;				// target category
	u8 tid;				// transport channnel ID
	u8 iid;				// target instance
	u8 snc;				// expect-response-flag
	u8 cid;				// command ID
	u16 cdl;			// payload length
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

#define SAN_GSB_MAX_RQSX_PAYLOAD  (U8_MAX - 2 - sizeof(struct gsb_data_rqsx))
#define SAN_GSB_MAX_RESPONSE	  (U8_MAX - 2 - sizeof(struct gsb_data_out))

#define SAN_GSB_COMMAND		  0

enum san_gsb_request_cv {
	SAN_GSB_REQUEST_CV_RQST = 0x01,
	SAN_GSB_REQUEST_CV_ETWL = 0x02,
	SAN_GSB_REQUEST_CV_RQSG = 0x03,
};


#define SAN_RQST_RETRY		5

#define san_request_sync_onstack(ctrl, rqst, rsp) \
	ssam_request_sync_onstack(ctrl, rqst, rsp, SAN_GSB_MAX_RQSX_PAYLOAD)


#define SAN_DSM_REVISION		0

static const guid_t SAN_DSM_UUID =
	GUID_INIT(0x93b666c5, 0x70c6, 0x469f, 0xa2, 0x15, 0x3d,
		  0x48, 0x7c, 0x91, 0xab, 0x3c);

enum san_dsm_event_fn {
	SAN_DSM_EVENT_FN_BAT1_STAT	= 0x03,
	SAN_DSM_EVENT_FN_BAT1_INFO	= 0x04,
	SAN_DSM_EVENT_FN_ADP1_STAT	= 0x05,
	SAN_DSM_EVENT_FN_ADP1_INFO	= 0x06,
	SAN_DSM_EVENT_FN_BAT2_STAT	= 0x07,
	SAN_DSM_EVENT_FN_BAT2_INFO	= 0x08,
	SAN_DSM_EVENT_FN_THERMAL	= 0x09,
	SAN_DSM_EVENT_FN_DPTF		= 0x0a,
};


static int sam_san_default_rqsg_handler(struct ssam_anf_dgpu_event *rqsg, void *data);

struct san_rqsg_if {
	struct mutex lock;
	struct device *san_dev;
	ssam_anf_rqsg_handler_fn handler;
	void *handler_data;
};

static struct san_rqsg_if san_rqsg_if = {
	.lock = __MUTEX_INITIALIZER(san_rqsg_if.lock),
	.san_dev = NULL,
	.handler = sam_san_default_rqsg_handler,
	.handler_data = NULL,
};

static int san_set_rqsg_interface_device(struct device *dev)
{
	int status = 0;

	mutex_lock(&san_rqsg_if.lock);
	if (!san_rqsg_if.san_dev && dev)
		san_rqsg_if.san_dev = dev;
	else
		status = -EBUSY;
	mutex_unlock(&san_rqsg_if.lock);

	return status;
}

int ssam_anf_consumer_register(struct device *consumer, u32 flags)
{
	const u32 valid = DL_FLAG_PM_RUNTIME | DL_FLAG_RPM_ACTIVE;
	int status;

	if ((flags | valid) != valid)
		return -EINVAL;

	flags |= DL_FLAG_AUTOREMOVE_CONSUMER;

	mutex_lock(&san_rqsg_if.lock);
	if (san_rqsg_if.san_dev)
		status = device_link_add(consumer, san_rqsg_if.san_dev, flags) ? 0 : -EINVAL;
	else
		status = -ENXIO;
	mutex_unlock(&san_rqsg_if.lock);
	return status;
}
EXPORT_SYMBOL_GPL(ssam_anf_consumer_register);

int ssam_anf_set_rqsg_handler(ssam_anf_rqsg_handler_fn fn, void *data)
{
	int status = -EBUSY;

	mutex_lock(&san_rqsg_if.lock);

	if (san_rqsg_if.handler == sam_san_default_rqsg_handler || !fn) {
		san_rqsg_if.handler = fn ? fn : sam_san_default_rqsg_handler;
		san_rqsg_if.handler_data = fn ? data : NULL;
		status = 0;
	}

	mutex_unlock(&san_rqsg_if.lock);
	return status;
}
EXPORT_SYMBOL_GPL(ssam_anf_set_rqsg_handler);

int san_call_rqsg_handler(struct ssam_anf_dgpu_event *rqsg)
{
	int status;

	mutex_lock(&san_rqsg_if.lock);
	status = san_rqsg_if.handler(rqsg, san_rqsg_if.handler_data);
	mutex_unlock(&san_rqsg_if.lock);

	return status;
}

static int sam_san_default_rqsg_handler(struct ssam_anf_dgpu_event *rqsg, void *data)
{
	struct device *dev = san_rqsg_if.san_dev;

	dev_warn(dev, "unhandled request: RQSG(0x%02x, 0x%02x, 0x%02x)\n",
		 rqsg->category, rqsg->command, rqsg->instance);

	return 0;
}


static int san_acpi_notify_event(struct device *dev, u64 func,
				 union acpi_object *param)
{
	acpi_handle san = ACPI_HANDLE(dev);
	union acpi_object *obj;
	int status = 0;

	if (!acpi_check_dsm(san, &SAN_DSM_UUID, SAN_DSM_REVISION, 1 << func))
		return 0;

	dev_dbg(dev, "notify event 0x%02llx\n", func);

	obj = acpi_evaluate_dsm_typed(san, &SAN_DSM_UUID, SAN_DSM_REVISION,
				      func, param, ACPI_TYPE_BUFFER);
	if (IS_ERR_OR_NULL(obj))
		return obj ? PTR_ERR(obj) : -ENXIO;

	if (obj->buffer.length != 1 || obj->buffer.pointer[0] != 0) {
		dev_err(dev, "got unexpected result from _DSM\n");
		status = -EFAULT;
	}

	ACPI_FREE(obj);
	return status;
}

static int san_evt_power_adp(struct device *dev, const struct ssam_event *event)
{
	int status;

	status = san_acpi_notify_event(dev, SAN_DSM_EVENT_FN_ADP1_STAT, NULL);
	if (status)
		return status;

	/*
	 * Enusre that the battery states get updated correctly.
	 * When the battery is fully charged and an adapter is plugged in, it
	 * sometimes is not updated correctly, instead showing it as charging.
	 * Explicitly trigger battery updates to fix this.
	 */

	status = san_acpi_notify_event(dev, SAN_DSM_EVENT_FN_BAT1_STAT, NULL);
	if (status)
		return status;

	return san_acpi_notify_event(dev, SAN_DSM_EVENT_FN_BAT2_STAT, NULL);
}

static int san_evt_power_bix(struct device *dev, const struct ssam_event *event)
{
	enum san_dsm_event_fn fn;

	if (event->instance_id == 0x02)
		fn = SAN_DSM_EVENT_FN_BAT2_INFO;
	else
		fn = SAN_DSM_EVENT_FN_BAT1_INFO;

	return san_acpi_notify_event(dev, fn, NULL);
}

static int san_evt_power_bst(struct device *dev, const struct ssam_event *event)
{
	enum san_dsm_event_fn fn;

	if (event->instance_id == 0x02)
		fn = SAN_DSM_EVENT_FN_BAT2_STAT;
	else
		fn = SAN_DSM_EVENT_FN_BAT1_STAT;

	return san_acpi_notify_event(dev, fn, NULL);
}

static int san_evt_power_dptf(struct device *dev, const struct ssam_event *event)
{
	union acpi_object payload;

	/*
	 * The Surface ACPI expects a buffer and not a package. It specifically
	 * checks for ObjectType (Arg3) == 0x03. This will cause a warning in
	 * acpica/nsarguments.c, but that warning can be safely ignored.
	 */
	payload.type = ACPI_TYPE_BUFFER;
	payload.buffer.length = event->length;
	payload.buffer.pointer = (u8 *)&event->data[0];

	return san_acpi_notify_event(dev, SAN_DSM_EVENT_FN_DPTF, &payload);
}

static unsigned long san_evt_power_delay(u8 cid)
{
	switch (cid) {
	case SAM_EVENT_PWR_CID_ADAPTER:
		/*
		 * Wait for battery state to update before signalling adapter
		 * change.
		 */
		return SAM_EVENT_DELAY_PWR_ADAPTER;

	case SAM_EVENT_PWR_CID_BST:
		/* Ensure we do not miss anything important due to caching. */
		return SAM_EVENT_DELAY_PWR_BST;

	case SAM_EVENT_PWR_CID_BIX:
	case SAM_EVENT_PWR_CID_DPTF:
	default:
		return 0;
	}
}

static bool san_evt_power(const struct ssam_event *event, struct device *dev)
{
	int status;

	switch (event->command_id) {
	case SAM_EVENT_PWR_CID_BIX:
		status = san_evt_power_bix(dev, event);
		break;

	case SAM_EVENT_PWR_CID_BST:
		status = san_evt_power_bst(dev, event);
		break;

	case SAM_EVENT_PWR_CID_ADAPTER:
		status = san_evt_power_adp(dev, event);
		break;

	case SAM_EVENT_PWR_CID_DPTF:
		status = san_evt_power_dptf(dev, event);
		break;

	default:
		return false;
	}

	if (status)
		dev_err(dev, "error handling power event (cid = %x)\n",
			event->command_id);

	return true;
}

static void san_evt_power_workfn(struct work_struct *work)
{
	struct san_event_work *ev;
	
	ev = container_of(work, struct san_event_work, work.work);
	san_evt_power(&ev->event, ev->dev);
	kfree(ev);
}


static u32 san_evt_power_nf(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	struct san_data *d = to_san_data(nf, nf_bat);
	struct san_event_work *work;
	unsigned long delay = san_evt_power_delay(event->command_id);

	if (delay == 0) {
		if (san_evt_power(event, d->dev))
			return SSAM_NOTIF_HANDLED;
		else
			return 0;
	}

	work = kzalloc(sizeof(struct san_event_work) + event->length, GFP_KERNEL);
	if (!work)
		return ssam_notifier_from_errno(-ENOMEM);

	INIT_DELAYED_WORK(&work->work, san_evt_power_workfn);
	work->dev = d->dev;

	memcpy(&work->event, event, sizeof(struct ssam_event) + event->length);

	schedule_delayed_work(&work->work, delay);
	return SSAM_NOTIF_HANDLED;
}


static inline int san_evt_thermal_notify(struct device *dev, const struct ssam_event *event)
{
	union acpi_object param;

	/*
	 * The Surface ACPI expects an integer and not a package. This will
	 * cause a warning in acpica/nsarguments.c, but that warning can be
	 * safely ignored.
	 */
	param.type = ACPI_TYPE_INTEGER;
	param.integer.value = event->instance_id;

	return san_acpi_notify_event(dev, SAN_DSM_EVENT_FN_THERMAL, &param);
}

static bool san_evt_thermal(const struct ssam_event *event, struct device *dev)
{
	int status;

	switch (event->command_id) {
	case SAM_EVENT_TEMP_CID_NOTIFY_SENSOR_TRIP_POINT:
		status = san_evt_thermal_notify(dev, event);
		break;

	default:
		return false;
	}

	if (status) {
		dev_err(dev, "error handling thermal event (cid = %x)\n",
			event->command_id);
	}

	return true;
}

static u32 san_evt_thermal_nf(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	if (san_evt_thermal(event, to_san_data(nf, nf_tmp)->dev))
		return SSAM_NOTIF_HANDLED;
	else
		return 0;
}


static acpi_status san_etwl(struct san_data *d, struct gsb_buffer *b)
{
	struct gsb_data_etwl *etwl = &b->data.etwl;

	if (b->len < sizeof(struct gsb_data_etwl)) {
		dev_err(d->dev, "invalid ETWL package (len = %d)\n", b->len);
		return AE_OK;
	}

	dev_err(d->dev, "ETWL(0x%02x, 0x%02x): %.*s\n", etwl->etw3, etwl->etw4,
		(unsigned int)(b->len - sizeof(struct gsb_data_etwl)),
		(char *)etwl->msg);

	// indicate success
	b->status = 0x00;
	b->len = 0x00;

	return AE_OK;
}

static struct gsb_data_rqsx *san_validate_rqsx(struct device *dev,
		const char *type, struct gsb_buffer *b)
{
	struct gsb_data_rqsx *rqsx = &b->data.rqsx;

	if (b->len < sizeof(struct gsb_data_rqsx)) {
		dev_err(dev, "invalid %s package (len = %d)\n", type, b->len);
		return NULL;
	}

	if (get_unaligned(&rqsx->cdl) != b->len - sizeof(struct gsb_data_rqsx)) {
		dev_err(dev, "bogus %s package (len = %d, cdl = %d)\n",
			type, b->len, get_unaligned(&rqsx->cdl));
		return NULL;
	}

	if (get_unaligned(&rqsx->cdl) > SAN_GSB_MAX_RQSX_PAYLOAD) {
		dev_err(dev, "payload for %s package too large (cdl = %d)\n",
			type, get_unaligned(&rqsx->cdl));
		return NULL;
	}

	return rqsx;
}

static void gsb_rqsx_response_error(struct gsb_buffer *gsb, int status)
{
	gsb->status = 0x00;
	gsb->len = 0x02;
	gsb->data.out.status = (u8)(-status);
	gsb->data.out.len = 0x00;
}

static void gsb_rqsx_response_success(struct gsb_buffer *gsb, u8 *ptr, size_t len)
{
	gsb->status = 0x00;
	gsb->len = len + 2;
	gsb->data.out.status = 0x00;
	gsb->data.out.len = len;

	if (len)
		memcpy(&gsb->data.out.pld[0], ptr, len);
}

static acpi_status san_rqst_fixup_suspended(struct ssam_request *rqst,
					    struct gsb_buffer *gsb)
{
	if (rqst->target_category == SSAM_SSH_TC_BAS && rqst->command_id == 0x0D) {
		u8 base_state = 1;

		/* Base state quirk:
		 * The base state may be queried from ACPI when the EC is still
		 * suspended. In this case it will return '-EPERM'. This query
		 * will only be triggered from the ACPI lid GPE interrupt, thus
		 * we are either in laptop or studio mode (base status 0x01 or
		 * 0x02). Furthermore, we will only get here if the device (and
		 * EC) have been suspended.
		 *
		 * We now assume that the device is in laptop mode (0x01). This
		 * has the drawback that it will wake the device when unfolding
		 * it in studio mode, but it also allows us to avoid actively
		 * waiting for the EC to wake up, which may incur a notable
		 * delay.
		 */

		gsb_rqsx_response_success(gsb, &base_state, sizeof(base_state));
		return AE_OK;
	}

	gsb_rqsx_response_error(gsb, -ENXIO);
	return AE_OK;
}

static acpi_status san_rqst(struct san_data *d, struct gsb_buffer *buffer)
{
	u8 rspbuf[SAN_GSB_MAX_RESPONSE];
	struct gsb_data_rqsx *gsb_rqst;
	struct ssam_request rqst;
	struct ssam_response rsp;
	int status = 0;
	int try;

	gsb_rqst = san_validate_rqsx(d->dev, "RQST", buffer);
	if (!gsb_rqst)
		return AE_OK;

	rqst.target_category = gsb_rqst->tc;
	rqst.target_id = gsb_rqst->tid;
	rqst.command_id = gsb_rqst->cid;
	rqst.instance_id = gsb_rqst->iid;
	rqst.flags = gsb_rqst->snc ? SSAM_REQUEST_HAS_RESPONSE : 0;
	rqst.length = get_unaligned(&gsb_rqst->cdl);
	rqst.payload = &gsb_rqst->pld[0];

	rsp.capacity = ARRAY_SIZE(rspbuf);
	rsp.length = 0;
	rsp.pointer = &rspbuf[0];

	// handle suspended device
	if (d->dev->power.is_suspended) {
		dev_warn(d->dev, "rqst: device is suspended, not executing\n");
		return san_rqst_fixup_suspended(&rqst, buffer);
	}

	for (try = 0; try < SAN_RQST_RETRY; try++) {
		if (try)
			dev_warn(d->dev, "rqst: IO error, trying again\n");

		status = san_request_sync_onstack(d->ctrl, &rqst, &rsp);
		if (status != -ETIMEDOUT && status != -EREMOTEIO)
			break;
	}

	if (!status) {
		gsb_rqsx_response_success(buffer, rsp.pointer, rsp.length);
	} else {
		dev_err(d->dev, "rqst: failed with error %d\n", status);
		gsb_rqsx_response_error(buffer, status);
	}

	return AE_OK;
}

static acpi_status san_rqsg(struct san_data *d, struct gsb_buffer *buffer)
{
	struct gsb_data_rqsx *gsb_rqsg;
	struct ssam_anf_dgpu_event evt;
	int status;

	gsb_rqsg = san_validate_rqsx(d->dev, "RQSG", buffer);
	if (!gsb_rqsg)
		return AE_OK;

	evt.category = gsb_rqsg->tc;
	evt.target = gsb_rqsg->tid;
	evt.command = gsb_rqsg->cid;
	evt.instance = gsb_rqsg->iid;
	evt.length = get_unaligned(&gsb_rqsg->cdl);
	evt.payload = &gsb_rqsg->pld[0];

	status = san_call_rqsg_handler(&evt);
	if (!status) {
		gsb_rqsx_response_success(buffer, NULL, 0);
	} else {
		dev_err(d->dev, "rqsg: failed with error %d\n", status);
		gsb_rqsx_response_error(buffer, status);
	}

	return AE_OK;
}

static acpi_status san_opreg_handler(u32 function,
		acpi_physical_address command, u32 bits, u64 *value64,
		void *opreg_context, void *region_context)
{
	struct san_data *d = to_san_data(opreg_context, info);
	struct gsb_buffer *buffer = (struct gsb_buffer *)value64;
	int accessor_type = (function & 0xFFFF0000) >> 16;

	if (command != SAN_GSB_COMMAND) {
		dev_warn(d->dev, "unsupported command: 0x%02llx\n", command);
		return AE_OK;
	}

	if (accessor_type != ACPI_GSB_ACCESS_ATTRIB_RAW_PROCESS) {
		dev_err(d->dev, "invalid access type: 0x%02x\n", accessor_type);
		return AE_OK;
	}

	// buffer must have at least contain the command-value
	if (buffer->len == 0) {
		dev_err(d->dev, "request-package too small\n");
		return AE_OK;
	}

	switch (buffer->data.in.cv) {
	case SAN_GSB_REQUEST_CV_RQST:
		return san_rqst(d, buffer);

	case SAN_GSB_REQUEST_CV_ETWL:
		return san_etwl(d, buffer);

	case SAN_GSB_REQUEST_CV_RQSG:
		return san_rqsg(d, buffer);

	default:
		dev_warn(d->dev, "unsupported SAN0 request (cv: 0x%02x)\n",
			 buffer->data.in.cv);
		return AE_OK;
	}
}


static int san_events_register(struct platform_device *pdev)
{
	struct san_data *d = platform_get_drvdata(pdev);
	int status;

	d->nf_bat.base.priority = 1;
	d->nf_bat.base.fn = san_evt_power_nf;
	d->nf_bat.event.reg = SSAM_EVENT_REGISTRY_SAM;
	d->nf_bat.event.id.target_category = SSAM_SSH_TC_BAT;
	d->nf_bat.event.id.instance = 0;
	d->nf_bat.event.mask = SSAM_EVENT_MASK_TARGET;
	d->nf_bat.event.flags = SSAM_EVENT_SEQUENCED;

	d->nf_tmp.base.priority = 1;
	d->nf_tmp.base.fn = san_evt_thermal_nf;
	d->nf_tmp.event.reg = SSAM_EVENT_REGISTRY_SAM;
	d->nf_tmp.event.id.target_category = SSAM_SSH_TC_TMP;
	d->nf_tmp.event.id.instance = 0;
	d->nf_tmp.event.mask = SSAM_EVENT_MASK_TARGET;
	d->nf_tmp.event.flags = SSAM_EVENT_SEQUENCED;

	status = ssam_notifier_register(d->ctrl, &d->nf_bat);
	if (status)
		return status;

	status = ssam_notifier_register(d->ctrl, &d->nf_tmp);
	if (status)
		ssam_notifier_unregister(d->ctrl, &d->nf_bat);

	return status;
}

static void san_events_unregister(struct platform_device *pdev)
{
	struct san_data *d = platform_get_drvdata(pdev);

	ssam_notifier_unregister(d->ctrl, &d->nf_bat);
	ssam_notifier_unregister(d->ctrl, &d->nf_tmp);
}

static int san_consumers_link(struct platform_device *pdev,
			      const struct san_acpi_consumer *cons)
{
	const u32 flags = DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_SUPPLIER;
	const struct san_acpi_consumer *c;

	for (c = cons; c && c->path; ++c) {
		struct acpi_device *adev;
		acpi_handle handle;
		int status;

		status = acpi_get_handle(NULL, (acpi_string)c->path, &handle);
		if (status && status != AE_NOT_FOUND)
			return -ENXIO;

		status = acpi_bus_get_device(handle, &adev);
		if (status)
			return status;

		if (!device_link_add(&adev->dev, &pdev->dev, flags))
			return -EFAULT;
	}

	return 0;
}

static int surface_sam_san_probe(struct platform_device *pdev)
{
	const struct san_acpi_consumer *cons;
	acpi_handle san = ACPI_HANDLE(&pdev->dev);
	struct ssam_controller *ctrl;
	struct san_data *data;
	int status;

	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	cons = acpi_device_get_match_data(&pdev->dev);
	if (cons) {
		status = san_consumers_link(pdev, cons);
		if (status)
			return status;
	}

	data = devm_kzalloc(&pdev->dev, sizeof(struct san_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->dev = &pdev->dev;
	data->ctrl = ctrl;

	platform_set_drvdata(pdev, data);

	status = acpi_install_address_space_handler(san, ACPI_ADR_SPACE_GSBUS,
			&san_opreg_handler, NULL, &data->info);

	if (ACPI_FAILURE(status)) {
		status = -ENXIO;
		goto err_install_handler;
	}

	status = san_events_register(pdev);
	if (status)
		goto err_enable_events;

	status = san_set_rqsg_interface_device(&pdev->dev);
	if (status)
		goto err_install_dev;

	acpi_walk_dep_device_list(san);
	return 0;

err_install_dev:
	san_events_unregister(pdev);
err_enable_events:
	acpi_remove_address_space_handler(san, ACPI_ADR_SPACE_GSBUS, &san_opreg_handler);
err_install_handler:
	platform_set_drvdata(san, NULL);
	return status;
}

static int surface_sam_san_remove(struct platform_device *pdev)
{
	acpi_handle san = ACPI_HANDLE(&pdev->dev);	// _SAN device node
	acpi_status status = AE_OK;

	san_set_rqsg_interface_device(NULL);
	acpi_remove_address_space_handler(san, ACPI_ADR_SPACE_GSBUS,
					  &san_opreg_handler);
	san_events_unregister(pdev);

	/*
	 * We have unregistered our event sources. Now we need to ensure that
	 * all delayed works they may have spawned are run to completion.
	 */
	flush_scheduled_work();

	platform_set_drvdata(pdev, NULL);
	return status;
}


/*
 * ACPI devices that make use of the SAM EC via the SAN interface. Link them
 * to the SAN device to try and enforce correct suspend/resume orderding.
 */
static const struct san_acpi_consumer san_mshw0091_consumers[] = {
	{ "\\_SB.SRTC" },
	{ "\\ADP1"     },
	{ "\\_SB.BAT1" },
	{ "\\_SB.BAT2" },
	{ },
};

static const struct acpi_device_id surface_sam_san_match[] = {
	{ "MSHW0091", (unsigned long) san_mshw0091_consumers },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_san_match);

static struct platform_driver surface_sam_san = {
	.probe = surface_sam_san_probe,
	.remove = surface_sam_san_remove,
	.driver = {
		.name = "surface_sam_san",
		.acpi_match_table = surface_sam_san_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_sam_san);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface ACPI Notify Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");

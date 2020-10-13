// SPDX-License-Identifier: GPL-2.0+
/*
 * Surface Book (gen. 2 and later) detachment system (DTX) driver.
 *
 * Provides a user-space interface to properly handle clipboard/tablet
 * (containing screen and processor) detachment from the base of the device
 * (containing the keyboard and optionally a discrete GPU). Allows to
 * acknowledge (to speed things up), abort (e.g. in case the dGPU is stil in
 * use), or request detachment via user-space.
 *
 * Copyright (C) 2019-2020 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/input.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "../../include/linux/surface_aggregator/controller.h"


/* -- Public Interface. ----------------------------------------------------- */

/* Status/error categories */
#define SDTX_CATEGORY_STATUS		0x0000
#define SDTX_CATEGORY_RUNTIME_ERROR	0x1000
#define SDTX_CATEGORY_HARDWARE_ERROR	0x2000
#define SDTX_CATEGORY_UNKNOWN		0xf000

#define SDTX_CATEGORY_MASK		0xf000
#define SDTX_CATEGORY(value)		((value) & SDTX_CATEGORY_MASK)

#define SDTX_STATUS(code)		((code) | SDTX_CATEGORY_STATUS)
#define SDTX_ERR_RT(code)		((code) | SDTX_CATEGORY_RUNTIME_ERROR)
#define SDTX_ERR_HW(code)		((code) | SDTX_CATEGORY_HARDWARE_ERROR)
#define SDTX_UNKNOWN(code)		((code) | SDTX_CATEGORY_UNKNOWN)

#define SDTX_SUCCESS(value)	(SDTX_CATEGORY(value) == SDTX_CATEGORY_STATUS)

/* Latch status values */
#define SDTX_LATCH_CLOSED		SDTX_STATUS(0x00)
#define SDTX_LATCH_OPENED		SDTX_STATUS(0x01)

/* Base state values */
#define SDTX_BASE_DETACHED		SDTX_STATUS(0x00)
#define SDTX_BASE_ATTACHED		SDTX_STATUS(0x01)

/* Runtime errors (non-critical) */
#define SDTX_DETACH_NOT_FEASIBLE	SDTX_ERR_RT(0x01)
#define SDTX_DETACH_TIMEDOUT		SDTX_ERR_RT(0x02)

/* Hardware errors (critical) */
#define SDTX_ERR_FAILED_TO_OPEN		SDTX_ERR_HW(0x01)
#define SDTX_ERR_FAILED_TO_REMAIN_OPEN	SDTX_ERR_HW(0x02)
#define SDTX_ERR_FAILED_TO_CLOSE	SDTX_ERR_HW(0x03)


/* Base types */
#define SDTX_DEVICE_TYPE_HID		0x0100
#define SDTX_DEVICE_TYPE_SSH		0x0200

#define SDTX_DEVICE_TYPE_MASK		0x0f00
#define SDTX_DEVICE_TYPE(value)		((value) & SDTX_DEVICE_TYPE_MASK)

#define SDTX_BASE_TYPE_HID(id)		((id) | SDTX_DEVICE_TYPE_HID)
#define SDTX_BASE_TYPE_SSH(id)		((id) | SDTX_DEVICE_TYPE_SSH)


/* Device mode */
enum sdtx_device_mode {
	SDTX_DEVICE_MODE_TABLET		= 0x00,
	SDTX_DEVICE_MODE_LAPTOP		= 0x01,
	SDTX_DEVICE_MODE_STUDIO		= 0x02,
};


/* Event provided by reading from the device */
struct sdtx_event {
	__u16 length;
	__u16 code;
	__u8 data[];
} __packed;

enum sdtx_event_code {
	SDTX_EVENT_REQUEST		= 1,
	SDTX_EVENT_CANCEL		= 2,
	SDTX_EVENT_BASE_CONNECTION	= 3,
	SDTX_EVENT_LATCH_STATUS		= 4,
	SDTX_EVENT_DEVICE_MODE		= 5,
};


/* IOCTL interface */
struct sdtx_base_info {
	__u16 state;
	__u16 base_id;
} __packed;

#define SDTX_IOCTL_EVENTS_ENABLE	_IO(0xa5, 0x21)
#define SDTX_IOCTL_EVENTS_DISABLE	_IO(0xa5, 0x22)

#define SDTX_IOCTL_LATCH_LOCK		_IO(0xa5, 0x23)
#define SDTX_IOCTL_LATCH_UNLOCK		_IO(0xa5, 0x24)
#define SDTX_IOCTL_LATCH_REQUEST	_IO(0xa5, 0x25)
#define SDTX_IOCTL_LATCH_CONFIRM	_IO(0xa5, 0x26)
#define SDTX_IOCTL_LATCH_HEARTBEAT	_IO(0xa5, 0x27)
#define SDTX_IOCTL_LATCH_CANCEL		_IO(0xa5, 0x28)

#define SDTX_IOCTL_GET_BASE_INFO	_IOR(0xa5, 0x29, struct sdtx_base_info)
#define SDTX_IOCTL_GET_DEVICE_MODE	_IOR(0xa5, 0x2a, u16)
#define SDTX_IOCTL_GET_LATCH_STATUS	_IOR(0xa5, 0x2b, u16)


/* -- SSAM Interface. ------------------------------------------------------- */

enum sam_event_cid_bas {
	SAM_EVENT_CID_DTX_CONNECTION			= 0x0c,
	SAM_EVENT_CID_DTX_REQUEST			= 0x0e,
	SAM_EVENT_CID_DTX_CANCEL			= 0x0f,
	SAM_EVENT_CID_DTX_LATCH_STATUS			= 0x11,
};

enum dtx_base_state {
	SDTX_BASE_STATE_DETACH_SUCCESS			= 0x00,
	SDTX_BASE_STATE_ATTACHED			= 0x01,
	SDTX_BASE_STATE_NOT_FEASIBLE			= 0x02,
};

enum dtx_latch_status {
	SDTX_LATCH_STATUS_CLOSED			= 0x00,
	SDTX_LATCH_STATUS_OPENED			= 0x01,
	SDTX_LATCH_STATUS_FAILED_TO_OPEN		= 0x02,
	SDTX_LATCH_STATUS_FAILED_TO_REMAIN_OPEN		= 0x03,
	SDTX_LATCH_STATUS_FAILED_TO_CLOSE		= 0x04,
};

enum dtx_cancel_reason {
	SDTX_CANCEL_REASON_NOT_FEASIBLE			= 0x00,  // low battery
	SDTX_CANCEL_REASON_TIMEOUT			= 0x02,
	SDTX_CANCEL_REASON_FAILED_TO_OPEN		= 0x03,
	SDTX_CANCEL_REASON_FAILED_TO_REMAIN_OPEN	= 0x04,
	SDTX_CANCEL_REASON_FAILED_TO_CLOSE		= 0x05,
};


struct ssam_dtx_base_info {
	u8 state;
	u8 base_id;
} __packed;

static_assert(sizeof(struct ssam_dtx_base_info) == 2);

static SSAM_DEFINE_SYNC_REQUEST_N(ssam_bas_latch_lock, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x06,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_N(ssam_bas_latch_unlock, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x07,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_N(ssam_bas_latch_request, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x08,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_N(ssam_bas_latch_confirm, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x09,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_N(ssam_bas_latch_heartbeat, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x0a,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_N(ssam_bas_latch_cancel, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x0b,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_bas_get_base, struct ssam_dtx_base_info, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x0c,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_bas_get_device_mode, u8, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x0d,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_bas_get_latch_status, u8, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x11,
	.instance_id     = 0x00,
});


/* -- TODO ------------------------------------------------------------------ */

#define DTX_ERR		KERN_ERR "surface_dtx: "
#define DTX_WARN	KERN_WARNING "surface_dtx: "

struct surface_dtx_dev {
	struct device *dev;
	struct ssam_controller *ctrl;

	spinlock_t client_lock;
	struct list_head client_list;

	struct ssam_event_notifier notif;
	wait_queue_head_t waitq;
	struct miscdevice mdev;
	struct mutex mutex;
	bool active;

	struct delayed_work mode_work;
	struct input_dev *mode_switch;
};

struct surface_dtx_client {
	struct surface_dtx_dev *ddev;

	struct list_head node;
	struct rcu_head rcu;

	struct fasync_struct *fasync;

	struct mutex read_lock;
	spinlock_t write_lock;
	DECLARE_KFIFO(buffer, u8, 512);
};


static struct surface_dtx_dev surface_dtx_dev;


/* -- Firmware Value Translations. ------------------------------------------ */

static u16 sdtx_translate_base_state(struct surface_dtx_dev *ddev, u8 state)
{
	switch (state) {
	case SDTX_BASE_STATE_ATTACHED:
		return SDTX_BASE_ATTACHED;

	case SDTX_BASE_STATE_DETACH_SUCCESS:
		return SDTX_BASE_DETACHED;

	case SDTX_BASE_STATE_NOT_FEASIBLE:
		return SDTX_DETACH_NOT_FEASIBLE;

	default:
		dev_err(ddev->dev, "unknown base state: 0x%02x\n", state);
		return SDTX_UNKNOWN(state);
	}
}

static u16 sdtx_translate_latch_status(struct surface_dtx_dev *ddev, u8 status)
{
	switch (status) {
	case SDTX_LATCH_STATUS_CLOSED:
		return SDTX_LATCH_CLOSED;

	case SDTX_LATCH_STATUS_OPENED:
		return SDTX_LATCH_OPENED;

	case SDTX_LATCH_STATUS_FAILED_TO_OPEN:
		return SDTX_ERR_FAILED_TO_OPEN;

	case SDTX_LATCH_STATUS_FAILED_TO_REMAIN_OPEN:
		return SDTX_ERR_FAILED_TO_REMAIN_OPEN;

	case SDTX_LATCH_STATUS_FAILED_TO_CLOSE:
		return SDTX_ERR_FAILED_TO_CLOSE;

	default:
		dev_err(ddev->dev, "unknown latch status: 0x%02x\n", status);
		return SDTX_UNKNOWN(status);
	}
}

static u16 sdtx_translate_cancel_reason(struct surface_dtx_dev *ddev, u8 reason)
{
	switch (reason) {
	case SDTX_CANCEL_REASON_NOT_FEASIBLE:
		return SDTX_DETACH_NOT_FEASIBLE;

	case SDTX_CANCEL_REASON_TIMEOUT:
		return SDTX_DETACH_TIMEDOUT;

	case SDTX_CANCEL_REASON_FAILED_TO_OPEN:
		return SDTX_ERR_FAILED_TO_OPEN;

	case SDTX_CANCEL_REASON_FAILED_TO_REMAIN_OPEN:
		return SDTX_ERR_FAILED_TO_REMAIN_OPEN;

	case SDTX_CANCEL_REASON_FAILED_TO_CLOSE:
		return SDTX_ERR_FAILED_TO_CLOSE;

	default:
		dev_err(ddev->dev, "unknown cancel reason: 0x%02x\n", reason);
		return SDTX_UNKNOWN(reason);
	}
}


/* -- IOCTLs. --------------------------------------------------------------- */

static int sdtx_ioctl_get_base_info(struct surface_dtx_dev *ddev,
				    struct sdtx_base_info __user *buf)
{
	struct ssam_dtx_base_info raw;
	struct sdtx_base_info info;
	int status;

	status = ssam_bas_get_base(ddev->ctrl, &raw);
	if (status < 0)
		return status;

	info.state = sdtx_translate_base_state(ddev, raw.state);
	info.base_id = SDTX_BASE_TYPE_SSH(raw.base_id);

	if (copy_to_user(buf, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

static int sdtx_ioctl_get_device_mode(struct surface_dtx_dev *ddev, u16 __user *buf)
{
	u8 mode;
	int status;

	status = ssam_bas_get_device_mode(ddev->ctrl, &mode);
	if (status < 0)
		return status;

	return put_user(mode, buf);
}

static int sdtx_ioctl_get_latch_status(struct surface_dtx_dev *ddev, u16 __user *buf)
{
	u8 latch;
	int status;

	status = ssam_bas_get_latch_status(ddev->ctrl, &latch);
	if (status < 0)
		return status;

	return put_user(sdtx_translate_latch_status(ddev, latch), buf);
}

static long surface_dtx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct surface_dtx_client *client = file->private_data;
	struct surface_dtx_dev *ddev = client->ddev;

	switch (cmd) {
	case SDTX_IOCTL_EVENTS_ENABLE:
		return -EINVAL;		// TODO

	case SDTX_IOCTL_EVENTS_DISABLE:
		return -EINVAL;		// TODO

	case SDTX_IOCTL_LATCH_LOCK:
		return ssam_bas_latch_lock(ddev->ctrl);

	case SDTX_IOCTL_LATCH_UNLOCK:
		return ssam_bas_latch_unlock(ddev->ctrl);

	case SDTX_IOCTL_LATCH_REQUEST:
		return ssam_bas_latch_request(ddev->ctrl);

	case SDTX_IOCTL_LATCH_CONFIRM:
		return ssam_bas_latch_confirm(ddev->ctrl);

	case SDTX_IOCTL_LATCH_HEARTBEAT:
		return ssam_bas_latch_heartbeat(ddev->ctrl);

	case SDTX_IOCTL_LATCH_CANCEL:
		return ssam_bas_latch_cancel(ddev->ctrl);

	case SDTX_IOCTL_GET_BASE_INFO:
		return sdtx_ioctl_get_base_info(ddev,
				(struct sdtx_base_info __user *)arg);

	case SDTX_IOCTL_GET_DEVICE_MODE:
		return sdtx_ioctl_get_device_mode(ddev, (u16 __user *)arg);

	case SDTX_IOCTL_GET_LATCH_STATUS:
		return sdtx_ioctl_get_latch_status(ddev, (u16 __user *)arg);

	default:
		return -EINVAL;
	}
}


/* -- File Operations. ------------------------------------------------------ */

static void sdtx_client_free(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct surface_dtx_client, rcu));
}

static int surface_dtx_open(struct inode *inode, struct file *file)
{
	struct surface_dtx_dev *ddev;
	struct surface_dtx_client *client;

	ddev = container_of(file->private_data, struct surface_dtx_dev, mdev);

	// initialize client
	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;

	client->ddev = ddev;
	mutex_init(&client->read_lock);
	INIT_KFIFO(client->buffer);

	file->private_data = client;

	// attach client
	spin_lock(&ddev->client_lock);
	list_add_tail_rcu(&client->node, &ddev->client_list);
	spin_unlock(&ddev->client_lock);

	stream_open(inode, file);
	return 0;
}

static int surface_dtx_release(struct inode *inode, struct file *file)
{
	struct surface_dtx_client *client = file->private_data;

	// detach client
	spin_lock(&client->ddev->client_lock);
	list_del_rcu(&client->node);
	spin_unlock(&client->ddev->client_lock);
	call_rcu(&client->rcu, sdtx_client_free);

	return 0;
}

static ssize_t surface_dtx_read(struct file *file, char __user *buf,
				size_t count, loff_t *offs)
{
	struct surface_dtx_client *client = file->private_data;
	struct surface_dtx_dev *ddev = client->ddev;
	unsigned int copied;
	int status;

	do {
		// check availability, wait if necessary
		if (kfifo_is_empty(&client->buffer)) {
			if (file->f_flags & O_NONBLOCK)
				return -EAGAIN;

			status = wait_event_interruptible(ddev->waitq,
					!kfifo_is_empty(&client->buffer));
			if (status < 0)
				return status;
		}

		// try to read from fifo
		if (mutex_lock_interruptible(&client->read_lock))
			return -ERESTARTSYS;

		status = kfifo_to_user(&client->buffer, buf, count, &copied);
		mutex_unlock(&client->read_lock);

		if (status < 0)
			return status;

		// we might not have gotten anything, check this here
		if (copied == 0 && (file->f_flags & O_NONBLOCK))
			return -EAGAIN;

	} while (copied == 0);

	return copied;
}

static __poll_t surface_dtx_poll(struct file *file, struct poll_table_struct *pt)
{
	struct surface_dtx_client *client = file->private_data;

	poll_wait(file, &client->ddev->waitq, pt);
	if (!kfifo_is_empty(&client->buffer))
		return EPOLLIN | EPOLLRDNORM;

	return 0;
}

static int surface_dtx_fasync(int fd, struct file *file, int on)
{
	struct surface_dtx_client *client = file->private_data;

	return fasync_helper(fd, file, on, &client->fasync);
}

static const struct file_operations surface_dtx_fops = {
	.owner          = THIS_MODULE,
	.open           = surface_dtx_open,
	.release        = surface_dtx_release,
	.read           = surface_dtx_read,
	.poll           = surface_dtx_poll,
	.fasync         = surface_dtx_fasync,
	.unlocked_ioctl = surface_dtx_ioctl,
	.compat_ioctl   = surface_dtx_ioctl,
	.llseek         = no_llseek,
};


/* -- Event Handling/Forwarding. -------------------------------------------- */

/*
 * The device operation mode is not immediately updated on the EC when the
 * base has been connected, i.e. querying the device mode inside the
 * connection event callback yields an outdated value. Thus, we can only
 * determine the new tablet-mode switch and device mode values after some
 * time.
 *
 * These delays have been chosen by experimenting. We first delay on connect
 * events, then check and validate the device mode against the base state and
 * if invalid delay again by the "recheck" delay.
 */
#define SDTX_DEVICE_MODE_DELAY_CONNECT	msecs_to_jiffies(100)
#define SDTX_DEVICE_MODE_DELAY_RECHECK	msecs_to_jiffies(100)

static void sdtx_update_device_mode(struct surface_dtx_dev *ddev, unsigned long delay);


struct sdtx_status_event {
	struct sdtx_event e;
	u16 v;
} __packed;

struct sdtx_base_info_event {
	struct sdtx_event e;
	struct sdtx_base_info v;
} __packed;

union sdtx_generic_event {
	struct sdtx_event common;
	struct sdtx_status_event status;
	struct sdtx_base_info_event base;
};

static void sdtx_push_event(struct surface_dtx_dev *ddev, struct sdtx_event *evt)
{
	const size_t len = sizeof(struct sdtx_event) + evt->length;
	struct surface_dtx_client *client;

	rcu_read_lock();
	list_for_each_entry_rcu(client, &ddev->client_list, node) {
		spin_lock(&client->write_lock);

		if (likely(kfifo_avail(&client->buffer) >= len)) {
			kfifo_in(&client->buffer, (const u8 *)evt, len);
			spin_unlock(&client->write_lock);
		} else {
			spin_unlock(&client->write_lock);
			printk(DTX_WARN "event buffer overrun\n");
		}

		kill_fasync(&client->fasync, SIGIO, POLL_IN);
	}
	rcu_read_unlock();

	wake_up_interruptible(&ddev->waitq);
}

static u32 sdtx_notifier(struct ssam_event_notifier *nf,
			 const struct ssam_event *in)
{
	struct surface_dtx_dev *ddev = container_of(nf, struct surface_dtx_dev, notif);
	union sdtx_generic_event event;
	size_t len;

	// validate event payload length
	switch (in->command_id) {
	case SAM_EVENT_CID_DTX_CONNECTION:
		len = 2;
		break;

	case SAM_EVENT_CID_DTX_REQUEST:
		len = 0;
		break;

	case SAM_EVENT_CID_DTX_CANCEL:
		len = 1;
		break;

	case SAM_EVENT_CID_DTX_LATCH_STATUS:
		len = 1;
		break;

	default:
		return 0;
	};

	if (in->length != len) {
		dev_err(ddev->dev, "unexpected payload size for event 0x%02x: "
			"got %u, expected %zu", in->command_id, in->length, len);
		return 0;
	}

	// translate event
	switch (in->command_id) {
	case SAM_EVENT_CID_DTX_CONNECTION:
		event.base.e.code = SDTX_EVENT_BASE_CONNECTION;
		event.base.e.length = sizeof(struct sdtx_base_info);
		event.base.v.state = sdtx_translate_base_state(ddev, in->data[0]);
		event.base.v.base_id = SDTX_BASE_TYPE_SSH(in->data[1]);
		break;

	case SAM_EVENT_CID_DTX_REQUEST:
		event.common.code = SDTX_EVENT_REQUEST;
		event.common.length = 0;
		break;

	case SAM_EVENT_CID_DTX_CANCEL:
		event.status.e.code = SDTX_EVENT_CANCEL;
		event.status.e.length = sizeof(u16);
		event.status.v = sdtx_translate_cancel_reason(ddev, in->data[0]);
		break;

	case SAM_EVENT_CID_DTX_LATCH_STATUS:
		event.status.e.code = SDTX_EVENT_LATCH_STATUS;
		event.status.e.length = sizeof(u16);
		event.status.v = sdtx_translate_latch_status(ddev, in->data[0]);
		break;
	}

	sdtx_push_event(ddev, &event.common);

	// update device mode on base connection change
	if (in->command_id == SAM_EVENT_CID_DTX_CONNECTION) {
		unsigned long delay;

		delay = in->data[0] ? SDTX_DEVICE_MODE_DELAY_CONNECT : 0;
		sdtx_update_device_mode(ddev, delay);
	}

	return SSAM_NOTIF_HANDLED;
}


/* -- Tablet Mode Switch. --------------------------------------------------- */

static void sdtx_update_device_mode(struct surface_dtx_dev *ddev, unsigned long delay)
{
	schedule_delayed_work(&ddev->mode_work, delay);
}

static void sdtx_device_mode_workfn(struct work_struct *work)
{
	struct surface_dtx_dev *ddev;
	struct sdtx_status_event event;
	struct ssam_dtx_base_info base;
	int status, tablet;
	bool invalid;
	u8 mode;

	ddev = container_of(work, struct surface_dtx_dev, mode_work.work);

	// get operation mode
	status = ssam_bas_get_device_mode(ddev->ctrl, &mode);
	if (status) {
		dev_err(ddev->dev, "failed to get device mode: %d\n", status);
		return;
	}

	// get base info
	status = ssam_bas_get_base(ddev->ctrl, &base);
	if (status) {
		dev_err(ddev->dev, "failed to get base info: %d\n", status);
		return;
	}

	/*
	 * In some cases (specifically when attaching the base), the device
	 * mode isn't updated right away. Thus we check if the device mode
	 * makes sense for the given base state and try again later if it
	 * doesn't.
	 */
	invalid = ((base.state == SDTX_BASE_STATE_ATTACHED)
			&& (mode == SDTX_DEVICE_MODE_TABLET))
		|| ((base.state == SDTX_BASE_STATE_DETACH_SUCCESS)
			&& (mode != SDTX_DEVICE_MODE_TABLET));

	if (invalid) {
		dev_dbg(ddev->dev, "device mode is invalid, trying again\n");
		sdtx_update_device_mode(ddev, SDTX_DEVICE_MODE_DELAY_RECHECK);
		return;
	}

	event.e.code = SDTX_EVENT_DEVICE_MODE;
	event.e.length = sizeof(u16);
	event.v = mode;

	sdtx_push_event(ddev, &event.e);

	// send SW_TABLET_MODE event
	tablet = mode != SDTX_DEVICE_MODE_LAPTOP;
	input_report_switch(ddev->mode_switch, SW_TABLET_MODE, tablet);
	input_sync(ddev->mode_switch);
}


/* -- TODO ------------------------------------------------------------------ */

static struct surface_dtx_dev surface_dtx_dev = {
	.mdev = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "surface_dtx",
		.nodename = "surface/dtx",
		.fops = &surface_dtx_fops,
	},
	.client_lock = __SPIN_LOCK_UNLOCKED(),
	.mutex  = __MUTEX_INITIALIZER(surface_dtx_dev.mutex),
	.active = false,
};


static struct input_dev *surface_dtx_register_inputdev(
		struct platform_device *pdev, struct ssam_controller *ctrl)
{
	struct input_dev *input_dev;
	u8 mode;
	int status;

	input_dev = input_allocate_device();
	if (!input_dev)
		return ERR_PTR(-ENOMEM);

	input_dev->name = "Microsoft Surface DTX Device Mode Switch";
	input_dev->dev.parent = &pdev->dev;
	input_dev->id.bustype = BUS_HOST;

	input_set_capability(input_dev, EV_SW, SW_TABLET_MODE);

	status = ssam_bas_get_device_mode(ctrl, &mode);
	if (status < 0) {
		input_free_device(input_dev);
		return ERR_PTR(status);
	}

	input_report_switch(input_dev, SW_TABLET_MODE, mode != SDTX_DEVICE_MODE_LAPTOP);

	status = input_register_device(input_dev);
	if (status) {
		input_unregister_device(input_dev);
		return ERR_PTR(status);
	}

	return input_dev;
}


static int surface_sam_dtx_probe(struct platform_device *pdev)
{
	struct surface_dtx_dev *ddev = &surface_dtx_dev;
	struct ssam_controller *ctrl;
	struct input_dev *input_dev;
	int status;

	// link to ec
	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	input_dev = surface_dtx_register_inputdev(pdev, ctrl);
	if (IS_ERR(input_dev))
		return PTR_ERR(input_dev);

	// initialize device
	mutex_lock(&ddev->mutex);
	if (ddev->active) {
		mutex_unlock(&ddev->mutex);
		status = -ENODEV;
		goto err_register;
	}

	ddev->dev = &pdev->dev;
	ddev->ctrl = ctrl;
	INIT_DELAYED_WORK(&ddev->mode_work, sdtx_device_mode_workfn);
	INIT_LIST_HEAD(&ddev->client_list);
	init_waitqueue_head(&ddev->waitq);
	ddev->active = true;
	ddev->mode_switch = input_dev;
	mutex_unlock(&ddev->mutex);

	status = misc_register(&ddev->mdev);
	if (status)
		goto err_register;

	// set up events
	ddev->notif.base.priority = 1;
	ddev->notif.base.fn = sdtx_notifier;
	ddev->notif.event.reg = SSAM_EVENT_REGISTRY_SAM;
	ddev->notif.event.id.target_category = SSAM_SSH_TC_BAS;
	ddev->notif.event.id.instance = 0;
	ddev->notif.event.mask = SSAM_EVENT_MASK_NONE;
	ddev->notif.event.flags = SSAM_EVENT_SEQUENCED;

	status = ssam_notifier_register(ctrl, &ddev->notif);
	if (status)
		goto err_events_setup;

	return 0;

err_events_setup:
	misc_deregister(&ddev->mdev);
err_register:
	input_unregister_device(ddev->mode_switch);
	return status;
}

static int surface_sam_dtx_remove(struct platform_device *pdev)
{
	struct surface_dtx_dev *ddev = &surface_dtx_dev;
	struct surface_dtx_client *client;

	// After this call we're guaranteed that no more input events will arive
	ssam_notifier_unregister(ddev->ctrl, &ddev->notif);

	// wake up clients
	spin_lock(&ddev->client_lock);
	list_for_each_entry(client, &ddev->client_list, node) {
		kill_fasync(&client->fasync, SIGIO, POLL_HUP);
	}
	spin_unlock(&ddev->client_lock);

	wake_up_interruptible(&ddev->waitq);

	// unregister user-space devices
	input_unregister_device(ddev->mode_switch);
	misc_deregister(&ddev->mdev);

	// mark as inactive
	mutex_lock(&ddev->mutex);
	ddev->active = false;
	mutex_unlock(&ddev->mutex);

	/*
	 * Make sure all clients have been freed, so it's safe to unload the
	 * module afterwards.
	 */
	synchronize_rcu();
	return 0;
}


static const struct acpi_device_id surface_sam_dtx_match[] = {
	{ "MSHW0133", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_dtx_match);

static struct platform_driver surface_sam_dtx = {
	.probe = surface_sam_dtx_probe,
	.remove = surface_sam_dtx_remove,
	.driver = {
		.name = "surface_dtx",
		.acpi_match_table = surface_sam_dtx_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_sam_dtx);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Detachment-system driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");

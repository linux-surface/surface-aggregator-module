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

// Warning: This must always be a power of 2!
#define DTX_CLIENT_BUF_SIZE			16

#define DTX_CONNECT_DEVICE_MODE_DELAY		1000

#define DTX_ERR		KERN_ERR "surface_dtx: "
#define DTX_WARN	KERN_WARNING "surface_dtx: "

struct surface_dtx_event {
	u8 type;
	u8 code;
	u8 arg0;
	u8 arg1;
} __packed;

struct surface_dtx_dev {
	struct ssam_controller *ctrl;

	struct ssam_event_notifier notif;
	wait_queue_head_t waitq;
	struct miscdevice mdev;
	spinlock_t client_lock;
	struct list_head client_list;
	struct mutex mutex;
	bool active;

	struct delayed_work mode_work;
	struct input_dev *mode_switch;
};

struct surface_dtx_client {
	struct list_head node;
	struct surface_dtx_dev *ddev;
	struct fasync_struct *fasync;
	spinlock_t buffer_lock;
	unsigned int buffer_head;
	unsigned int buffer_tail;
	struct surface_dtx_event buffer[DTX_CLIENT_BUF_SIZE];
};


static struct surface_dtx_dev surface_dtx_dev;


static int sdtx_ioctl_get_device_mode(struct surface_dtx_dev *ddev,
				      u16 __user *buf)
{
	u8 mode;
	int status;

	status = ssam_bas_get_device_mode(ddev->ctrl, &mode);
	if (status < 0)
		return status;

	return put_user(mode, buf);
}


static int surface_dtx_open(struct inode *inode, struct file *file)
{
	struct surface_dtx_dev *ddev = container_of(file->private_data, struct surface_dtx_dev, mdev);
	struct surface_dtx_client *client;

	// initialize client
	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return -ENOMEM;

	spin_lock_init(&client->buffer_lock);
	client->buffer_head = 0;
	client->buffer_tail = 0;
	client->ddev = ddev;

	// attach client
	spin_lock(&ddev->client_lock);
	list_add_tail_rcu(&client->node, &ddev->client_list);
	spin_unlock(&ddev->client_lock);

	file->private_data = client;
	nonseekable_open(inode, file);

	return 0;
}

static int surface_dtx_release(struct inode *inode, struct file *file)
{
	struct surface_dtx_client *client = file->private_data;

	// detach client
	spin_lock(&client->ddev->client_lock);
	list_del_rcu(&client->node);
	spin_unlock(&client->ddev->client_lock);
	synchronize_rcu();

	kfree(client);
	file->private_data = NULL;

	return 0;
}

static ssize_t surface_dtx_read(struct file *file, char __user *buf, size_t count, loff_t *offs)
{
	struct surface_dtx_client *client = file->private_data;
	struct surface_dtx_dev *ddev = client->ddev;
	struct surface_dtx_event event;
	size_t read = 0;
	int status = 0;

	if (count != 0 && count < sizeof(struct surface_dtx_event))
		return -EINVAL;

	if (!ddev->active)
		return -ENODEV;

	// check availability
	if (client->buffer_head == client->buffer_tail) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		status = wait_event_interruptible(ddev->waitq,
				client->buffer_head != client->buffer_tail ||
				!ddev->active);
		if (status)
			return status;

		if (!ddev->active)
			return -ENODEV;
	}

	// copy events one by one
	while (read + sizeof(struct surface_dtx_event) <= count) {
		spin_lock_irq(&client->buffer_lock);

		if (client->buffer_head == client->buffer_tail) {
			spin_unlock_irq(&client->buffer_lock);
			break;
		}

		// get one event
		event = client->buffer[client->buffer_tail];
		client->buffer_tail = (client->buffer_tail + 1) & (DTX_CLIENT_BUF_SIZE - 1);
		spin_unlock_irq(&client->buffer_lock);

		// copy to userspace
		if (copy_to_user(buf, &event, sizeof(struct surface_dtx_event)))
			return -EFAULT;

		read += sizeof(struct surface_dtx_event);
	}

	return read;
}

static __poll_t surface_dtx_poll(struct file *file, struct poll_table_struct *pt)
{
	struct surface_dtx_client *client = file->private_data;
	int mask;

	poll_wait(file, &client->ddev->waitq, pt);

	if (client->ddev->active)
		mask = EPOLLOUT | EPOLLWRNORM;
	else
		mask = EPOLLHUP | EPOLLERR;

	if (client->buffer_head != client->buffer_tail)
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static int surface_dtx_fasync(int fd, struct file *file, int on)
{
	struct surface_dtx_client *client = file->private_data;

	return fasync_helper(fd, file, on, &client->fasync);
}

static long surface_dtx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct surface_dtx_client *client = file->private_data;
	struct surface_dtx_dev *ddev = client->ddev;
	int status;

	status = mutex_lock_interruptible(&ddev->mutex);
	if (status)
		return status;

	if (!ddev->active) {
		mutex_unlock(&ddev->mutex);
		return -ENODEV;
	}

	switch (cmd) {
	case SDTX_IOCTL_LATCH_LOCK:
		status = ssam_bas_latch_lock(ddev->ctrl);
		break;

	case SDTX_IOCTL_LATCH_UNLOCK:
		status = ssam_bas_latch_unlock(ddev->ctrl);
		break;

	case SDTX_IOCTL_LATCH_REQUEST:
		status = ssam_bas_latch_request(ddev->ctrl);
		break;

	case SDTX_IOCTL_LATCH_CONFIRM:
		status = ssam_bas_latch_confirm(ddev->ctrl);
		break;

	case SDTX_IOCTL_GET_DEVICE_MODE:
		status = sdtx_ioctl_get_device_mode(ddev, (u16 __user *)arg);
		break;

	default:
		status = -EINVAL;
		break;
	}

	mutex_unlock(&ddev->mutex);
	return status;
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


static void surface_dtx_push_event(struct surface_dtx_dev *ddev, struct surface_dtx_event *event)
{
	struct surface_dtx_client *client;

	rcu_read_lock();
	list_for_each_entry_rcu(client, &ddev->client_list, node) {
		spin_lock(&client->buffer_lock);

		client->buffer[client->buffer_head++] = *event;
		client->buffer_head &= DTX_CLIENT_BUF_SIZE - 1;

		if (unlikely(client->buffer_head == client->buffer_tail)) {
			printk(DTX_WARN "event buffer overrun\n");
			client->buffer_tail = (client->buffer_tail + 1) & (DTX_CLIENT_BUF_SIZE - 1);
		}

		spin_unlock(&client->buffer_lock);

		kill_fasync(&client->fasync, SIGIO, POLL_IN);
	}
	rcu_read_unlock();

	wake_up_interruptible(&ddev->waitq);
}


static void surface_dtx_update_device_mode(struct surface_dtx_dev *ddev)
{
	struct surface_dtx_event event;
	u8 mode;
	int tablet;
	int status;

	// get operation mode
	status = ssam_bas_get_device_mode(ddev->ctrl, &mode);
	if (status < 0) {
		printk(DTX_ERR "EC request failed with error %d\n", status);
		return;
	}

	// send DTX event
	event.type = 0x11;
	event.code = 0x0D;
	event.arg0 = mode;
	event.arg1 = 0x00;

	surface_dtx_push_event(ddev, &event);

	// send SW_TABLET_MODE event
	tablet = mode != SDTX_DEVICE_MODE_LAPTOP;
	input_report_switch(ddev->mode_switch, SW_TABLET_MODE, tablet);
	input_sync(ddev->mode_switch);
}

static void surface_dtx_device_mode_workfn(struct work_struct *work)
{
	struct surface_dtx_dev *ddev;

	ddev = container_of(work, struct surface_dtx_dev, mode_work.work);
	surface_dtx_update_device_mode(ddev);
}

static u32 surface_dtx_notification(struct ssam_event_notifier *nf, const struct ssam_event *in_event)
{
	struct surface_dtx_dev *ddev = container_of(nf, struct surface_dtx_dev, notif);
	struct surface_dtx_event event;
	unsigned long delay;

	switch (in_event->command_id) {
	case SAM_EVENT_CID_DTX_CONNECTION:
	case SAM_EVENT_CID_DTX_REQUEST:
	case SAM_EVENT_CID_DTX_CANCEL:
	case SAM_EVENT_CID_DTX_LATCH_STATUS:
		if (in_event->length > 2) {
			printk(DTX_ERR "unexpected payload size (cid: %x, len: %u)\n",
			       in_event->command_id, in_event->length);
			return SSAM_NOTIF_HANDLED;
		}

		event.type = in_event->target_category;
		event.code = in_event->command_id;
		event.arg0 = in_event->length >= 1 ? in_event->data[0] : 0x00;
		event.arg1 = in_event->length >= 2 ? in_event->data[1] : 0x00;
		surface_dtx_push_event(ddev, &event);
		break;

	default:
		return 0;
	}

	// update device mode
	if (in_event->command_id == SAM_EVENT_CID_DTX_CONNECTION) {
		delay = event.arg0 ? DTX_CONNECT_DEVICE_MODE_DELAY : 0;
		schedule_delayed_work(&ddev->mode_work, delay);
	}

	return SSAM_NOTIF_HANDLED;
}


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

	ddev->ctrl = ctrl;
	INIT_DELAYED_WORK(&ddev->mode_work, surface_dtx_device_mode_workfn);
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
	ddev->notif.base.fn = surface_dtx_notification;
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

	mutex_lock(&ddev->mutex);
	if (!ddev->active) {
		mutex_unlock(&ddev->mutex);
		return 0;
	}

	// mark as inactive
	ddev->active = false;
	mutex_unlock(&ddev->mutex);

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

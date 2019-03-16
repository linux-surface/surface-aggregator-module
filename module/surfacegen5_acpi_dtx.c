#include <linux/acpi.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>

#include "surfacegen5_acpi_ssh.h"


#define SURFACE_DTX_CMD_TYPE_DETACH             	0x11
#define SURFACE_DTX_CMD_DETACH_SAFEGUARD_ENGAGE		0x06
#define SURFACE_DTX_CMD_DETACH_SAFEGUARD_DISENGAGE	0x07
#define SURFACE_DTX_CMD_DETACH_ABORT            	0x08
#define SURFACE_DTX_CMD_DETACH_COMMENCE         	0x09

// Warning: This must always be a power of 2!
#define SURFACE_DTX_CLIENT_BUF_SIZE             	16

#define SG5_EVENT_CLIPBOARD_TC				0x11
#define SG5_EVENT_CLIPBOARD_RQID			0x0011
#define SG5_EVENT_CLIPBOARD_CID_CONNECTION		0x0c
#define SG5_EVENT_CLIPBOARD_CID_BUTTON			0x0e
#define SG5_EVENT_CLIPBOARD_CID_TIMEDOUT		0x0f
#define SG5_EVENT_CLIPBOARD_CID_NOTIFICATION		0x11

#define DTX_ERR		KERN_ERR "surfacegen5_acpi_dtx: "
#define DTX_WARN	KERN_WARNING "surfacegen5_acpi_dtx: "


struct surface_dtx_event {
	u8 type;
	u8 code;
	u8 arg0;
	u8 arg1;
} __packed;

struct surface_dtx_cmd {
	u8 type;
	u8 code;
} __packed;

struct surface_dtx_dev {
	wait_queue_head_t waitq;
	struct miscdevice mdev;
	spinlock_t client_lock;
	struct list_head client_list;
	struct mutex mutex;
	bool active;
	struct device_link *ec_link;
};

struct surface_dtx_client {
	struct list_head node;
	struct surface_dtx_dev *ddev;
	struct fasync_struct *fasync;
	spinlock_t buffer_lock;
	unsigned int buffer_head;
	unsigned int buffer_tail;
	struct surface_dtx_event buffer[SURFACE_DTX_CLIENT_BUF_SIZE];
};


static struct surface_dtx_dev surface_dtx_dev;


static bool validate_dtx_cmd(struct surface_dtx_cmd *cmd)
{
	if (cmd->type == SURFACE_DTX_CMD_TYPE_DETACH) {
		return cmd->code == SURFACE_DTX_CMD_DETACH_SAFEGUARD_ENGAGE ||
		       cmd->code == SURFACE_DTX_CMD_DETACH_SAFEGUARD_DISENGAGE ||
		       cmd->code == SURFACE_DTX_CMD_DETACH_ABORT ||
		       cmd->code == SURFACE_DTX_CMD_DETACH_COMMENCE;
	}

	return false;
}

static int surface_dtx_execute_command(struct surface_dtx_cmd *cmd)
{
	struct surfacegen5_rqst rqst = {
		.tc  = cmd->type,
		.iid = 0,
		.cid = cmd->code,
		.snc = 0,
		.cdl = 0,
		.pld = NULL,
	};

	return surfacegen5_ec_rqst(&rqst, NULL);
}


static int surface_dtx_open(struct inode *inode, struct file *file)
{
	struct surface_dtx_dev *ddev = container_of(file->private_data, struct surface_dtx_dev, mdev);
	struct surface_dtx_client *client;

	// initialize client
	client = kzalloc(sizeof(struct surface_dtx_client), GFP_KERNEL);
	if (!client) {
		return -ENOMEM;
	}

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

	if (count != 0 && count < sizeof(struct surface_dtx_event)) {
		return -EINVAL;
	}

	if (!ddev->active) {
		return -ENODEV;
	}

	// check availability
	if (client->buffer_head == client->buffer_tail){
		if (file->f_flags & O_NONBLOCK) {
			return -EAGAIN;
		}

		status = wait_event_interruptible(ddev->waitq,
				client->buffer_head != client->buffer_tail ||
				!ddev->active);
		if (status) {
			return status;
		}

		if (!ddev->active) {
			return -ENODEV;
		}
	}

	// copy events one by one
	while (read + sizeof(struct surface_dtx_event) <= count) {
		spin_lock_irq(&client->buffer_lock);

		if(client->buffer_head == client->buffer_tail) {
			spin_unlock_irq(&client->buffer_lock);
			break;
		}

		// get one event
		event = client->buffer[client->buffer_tail];
		client->buffer_tail = (client->buffer_tail + 1) & (SURFACE_DTX_CLIENT_BUF_SIZE - 1);
		spin_unlock_irq(&client->buffer_lock);

		// copy to userspace
		if(copy_to_user(buf, &event, sizeof(struct surface_dtx_event))) {
			return -EFAULT;
		}

		read += sizeof(struct surface_dtx_event);
	}

	return read;
}

static ssize_t surface_dtx_write(struct file *file, const char __user *buf, size_t count, loff_t *offs)
{
	struct surface_dtx_client *client = file->private_data;
	struct surface_dtx_dev *ddev = client->ddev;
	struct surface_dtx_cmd command;
	size_t sent = 0;
	int status;

	if (count != 0 && count < sizeof(struct surface_dtx_cmd)) {
		return -EINVAL;
	}

	status = mutex_lock_interruptible(&ddev->mutex);
	if (status) {
		return status;
	}

	if (!ddev->active) {
		mutex_unlock(&ddev->mutex);
		return -ENODEV;
	}

	while (sent + sizeof(struct surface_dtx_cmd) <= count) {
		if (copy_from_user(&command, buf + sent, sizeof(struct surface_dtx_cmd))) {
			status = -EFAULT;
			break;
		}

		if (!validate_dtx_cmd(&command)) {
			status = -EINVAL;
			break;
		}

		if(surface_dtx_execute_command(&command)) {
			status = -EIO;
			break;
		}

		sent += sizeof(struct surface_dtx_cmd);
	}

	mutex_unlock(&ddev->mutex);
	return status < 0 ? status : sent;
}

static __poll_t surface_dtx_poll(struct file *file, struct poll_table_struct *pt)
{
	struct surface_dtx_client *client = file->private_data;
	int mask;

	poll_wait(file, &client->ddev->waitq, pt);

	if (client->ddev->active) {
		mask = EPOLLOUT | EPOLLWRNORM;
	} else {
		mask = EPOLLHUP | EPOLLERR;
	}

	if (client->buffer_head != client->buffer_tail) {
		mask |= EPOLLIN | EPOLLRDNORM;
	}

	return mask;
}

static int surface_dtx_fasync(int fd, struct file *file, int on)
{
	struct surface_dtx_client *client = file->private_data;

	return fasync_helper(fd, file, on, &client->fasync);
}

static const struct file_operations surface_dtx_fops = {
	.owner   = THIS_MODULE,
	.open    = surface_dtx_open,
	.release = surface_dtx_release,
	.read    = surface_dtx_read,
	.write   = surface_dtx_write,
	.poll    = surface_dtx_poll,
	.fasync  = surface_dtx_fasync,
	.llseek  = no_llseek,
	// TODO: unlocked_ioctl, replace write with IOCTLs
};

static struct surface_dtx_dev surface_dtx_dev = {
	.mdev = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "surface_dtx",
		.fops = &surface_dtx_fops,
	},
	.client_lock = __SPIN_LOCK_UNLOCKED(),
	.mutex  = __MUTEX_INITIALIZER(surface_dtx_dev.mutex),
	.active = false,
};


static void surface_dtx_push_event(struct surface_dtx_event *event)
{
	struct surface_dtx_dev *ddev = &surface_dtx_dev;
	struct surface_dtx_client *client;

	rcu_read_lock();
	list_for_each_entry_rcu(client, &ddev->client_list, node) {
		spin_lock(&client->buffer_lock);

		client->buffer[client->buffer_head++] = *event;
		client->buffer_head &= SURFACE_DTX_CLIENT_BUF_SIZE - 1;

		if (unlikely(client->buffer_head == client->buffer_tail)) {
			printk(DTX_WARN "event buffer overrun\n");
			client->buffer_tail = (client->buffer_tail + 1) & (SURFACE_DTX_CLIENT_BUF_SIZE - 1);
		}

		spin_unlock(&client->buffer_lock);

		kill_fasync(&client->fasync, SIGIO, POLL_IN);
	}
	rcu_read_unlock();

	wake_up_interruptible(&ddev->waitq);
}


static int surface_dtx_evt_clipboard(struct surfacegen5_event *in_event, void *data)
{
	struct surface_dtx_event event;

	switch (in_event->cid) {
	case SG5_EVENT_CLIPBOARD_CID_CONNECTION:
	case SG5_EVENT_CLIPBOARD_CID_BUTTON:
	case SG5_EVENT_CLIPBOARD_CID_TIMEDOUT:
	case SG5_EVENT_CLIPBOARD_CID_NOTIFICATION:
		if (in_event->len > 2) {
			printk(DTX_ERR "unexpected payload size (cid: %x, len: %u)\n",
			       in_event->cid, in_event->len);
			return 0;
		}

		event.type = in_event->tc;
		event.code = in_event->cid;
		event.arg0 = in_event->len >= 1 ? in_event->pld[0] : 0x00;
		event.arg1 = in_event->len >= 2 ? in_event->pld[1] : 0x00;
		surface_dtx_push_event(&event);
		break;

	default:
		printk(DTX_WARN "unhandled clipboard event (cid: %x)\n", in_event->cid);
	}

	return 0;
}

static int surface_dtx_events_setup(void)
{
	int status;

	status = surfacegen5_ec_set_event_handler(SG5_EVENT_CLIPBOARD_RQID, surface_dtx_evt_clipboard, NULL);
	if (status) {
		goto err_event_handler;
	}

	status = surfacegen5_ec_enable_event_source(SG5_EVENT_CLIPBOARD_TC, 0x01, SG5_EVENT_CLIPBOARD_RQID);
	if (status) {
		goto err_event_source;
	}

	return 0;

err_event_source:
	surfacegen5_ec_remove_event_handler(SG5_EVENT_CLIPBOARD_RQID);
err_event_handler:
	return status;
}

static void surface_dtx_events_disable(void)
{
	surfacegen5_ec_disable_event_source(SG5_EVENT_CLIPBOARD_TC, 0x01, SG5_EVENT_CLIPBOARD_RQID);
	surfacegen5_ec_remove_event_handler(SG5_EVENT_CLIPBOARD_RQID);
}


static int surfacegen5_acpi_dtx_probe(struct platform_device *pdev)
{
	struct surface_dtx_dev *ddev = &surface_dtx_dev;
	struct device_link *ec_link;
	int status;

	// link to ec
	ec_link = surfacegen5_ec_consumer_add(&pdev->dev, DL_FLAG_PM_RUNTIME);
	if (IS_ERR_OR_NULL(ec_link)) {
		if (PTR_ERR(ec_link) == -ENXIO) {
	 		// Defer probe if the _SSH driver has not set up the controller yet.
			status = -EPROBE_DEFER;
		} else {
			status = -EFAULT;
		}

		goto err_probe_ec_link;
	}

	// initialize device
	mutex_lock(&ddev->mutex);
	if (ddev->active) {
		mutex_unlock(&ddev->mutex);
		status = -ENODEV;
		goto err_register;
	}

	INIT_LIST_HEAD(&ddev->client_list);
	init_waitqueue_head(&ddev->waitq);
	ddev->active = true;
	ddev->ec_link = ec_link;
	mutex_unlock(&ddev->mutex);

	status = misc_register(&ddev->mdev);
	if (status) {
		goto err_register;
	}

	// enable events
	status = surface_dtx_events_setup();
	if (status) {
		goto err_events_setup;
	}

	return 0;

err_events_setup:
	misc_deregister(&ddev->mdev);
err_register:
	surfacegen5_ec_consumer_remove(ec_link);
err_probe_ec_link:
	return status;
}

static int surfacegen5_acpi_dtx_remove(struct platform_device *pdev)
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

	surface_dtx_events_disable();

	// wake up clients
	spin_lock(&ddev->client_lock);
	list_for_each_entry(client, &ddev->client_list, node) {
		kill_fasync(&client->fasync, SIGIO, POLL_HUP);
	}
	spin_unlock(&ddev->client_lock);

	wake_up_interruptible(&ddev->waitq);

	// deregister device
	misc_deregister(&ddev->mdev);

	// unlink
	surfacegen5_ec_consumer_remove(ddev->ec_link);

	return 0;
}


static const struct acpi_device_id surfacegen5_acpi_dtx_match[] = {
	{ "MSHW0133", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surfacegen5_acpi_dtx_match);

struct platform_driver surfacegen5_acpi_dtx = {
	.probe = surfacegen5_acpi_dtx_probe,
	.remove = surfacegen5_acpi_dtx_remove,
	.driver = {
		.name = "surfacegen5_acpi_dtx",
		.acpi_match_table = ACPI_PTR(surfacegen5_acpi_dtx_match),
	},
};

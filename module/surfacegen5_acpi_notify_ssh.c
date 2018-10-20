#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/serdev.h>
#include <linux/crc-ccitt.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <asm/unaligned.h>

#include "surfacegen5_acpi_notify_ec.h"


#define RQST_PREFIX	"surfacegen5_ec_rqst: "
#define RQST_INFO	KERN_INFO RQST_PREFIX
#define RQST_WARN	KERN_WARNING RQST_PREFIX
#define RQST_ERR	KERN_ERR RQST_PREFIX

#define SG5_SUPPORTED_FLOW_CONTROL_MASK		(~((u8) ACPI_UART_FLOW_CONTROL_HW))

#define SG5_BYTELEN_SYNC	2
#define SG5_BYTELEN_TERM	2
#define SG5_BYTELEN_CRC		2
#define SG5_BYTELEN_ACK		4		// also RETRY
#define SG5_BYTELEN_CMDHDR	4
#define SG5_BYTELEN_CMDFRAME	8		// without payload

#define SG5_MAX_WRITE (                \
	  SG5_BYTELEN_SYNC             \
      	+ SG5_BYTELEN_CMDHDR           \
	+ SG5_BYTELEN_CRC              \
      	+ SG5_BYTELEN_CMDFRAME         \
	+ SURFACEGEN5_MAX_RQST_PAYLOAD \
	+ SG5_BYTELEN_CRC              \
)

#define SG5_WRITE_TIMEOUT	msecs_to_jiffies(1000)


/*
 * Sync:			aa 55
 * Terminate:			ff ff
 *
 * Request Message:		sync cmd-hdr crc(cmd-hdr) cmd-rqst-frame crc(cmd-rqst-frame)
 * Ack Message:			sync ack crc(ack) terminate
 * Retry Message:		sync retry crc(retry) terminate
 * Response Message:		sync cmd-hdr crc(cmd-hdr) cmd-resp-frame crc(cmd-resp-frame)
 *
 * Command Header:		80 LEN 00 SEQ
 * Command Request Frame:	80 RTC 01 00 RIID CNT16LE RCID PLD
 * Command Response Frame:	80 RTC 00 01 RIID CNT16LE RCID PLD
 * Ack:                 	40 00 00 SEQ
 * Retry:			04 00 00 00
 */

enum surfacegen5_ec_state {
	SG5_EC_UNINITIALIZED,
	SG5_EC_INITIALIZED,
};

struct surfacegen5_ec_counters {
	u8  seq;
	u16 pld;
};

struct surfacegen5_io_buf {
	u32 cap;
	u8 *data;
};

struct surfacegen5_ec {
	struct mutex                   lock;
	enum surfacegen5_ec_state      state;
	struct serdev_device          *serdev;
	struct device_link            *link;
	struct surfacegen5_ec_counters count;
	struct surfacegen5_io_buf      buf_write;
	// rcv_buffer?
	// rcv_cv?
};


static struct surfacegen5_ec surfacegen5_ec = {
	.lock   = __MUTEX_INITIALIZER(surfacegen5_ec.lock),
	.state  = SG5_EC_UNINITIALIZED,
	.serdev = NULL,
	.count = {
		.seq = 0,
		.pld = 0,
	},
};


inline static struct surfacegen5_ec *surfacegen5_ec_acquire(void)
{
	struct surfacegen5_ec *ec = &surfacegen5_ec;

	mutex_lock(&ec->lock);
	return ec;
}

inline static void surfacegen5_ec_release(struct surfacegen5_ec *ec)
{
	mutex_unlock(&ec->lock);
}

inline static struct surfacegen5_ec *surfacegen5_ec_acquire_init(void)
{
	struct surfacegen5_ec *ec = surfacegen5_ec_acquire();

	if (ec->state != SG5_EC_INITIALIZED) {
		surfacegen5_ec_release(ec);
		return NULL;
	}

	return ec;
}

int surfacegen5_ec_consumer_set(struct device *consumer)
{
	struct surfacegen5_ec *ec = surfacegen5_ec_acquire_init();
	struct device_link *link;
	int status = 0;

	if (!ec) {
		return -ENXIO;
	}

	if (ec->link) {
		surfacegen5_ec_release(ec);
		return -EBUSY;
	}

	link = device_link_add(consumer, &ec->serdev->dev, 0);
	if (link) {
		ec->link = link;
	} else {
		status = -EFAULT;
	}

	surfacegen5_ec_release(ec);
	return status;
}

int surfacegen5_ec_consumer_remove(struct device *consumer)
{
	struct surfacegen5_ec *ec = surfacegen5_ec_acquire_init();

	if (!ec) {
		return -ENXIO;
	}

	device_link_del(ec->link);
	ec->link = NULL;

	surfacegen5_ec_release(ec);
	return 0;
}


inline static u8 *surfacegen5_ssh_write_u16(u8 *out, u16 in)
{
	put_unaligned_le16(in, out);
	return out + 2;
}

inline static u8 *surfacegen5_ssh_write_crc(u8 *out, const u8 *buf, size_t size)
{
	u16 crc = crc_ccitt_false(0xffff, buf, size);
	return surfacegen5_ssh_write_u16(out, crc);
}

inline static u8 *surfacegen5_ssh_write_syn(u8 *out)
{
	*out++ = 0xaa;
	*out++ = 0x55;

	return out;
}

inline static u8 *surfacegen5_ssh_write_hdr(u8 *out, struct surfacegen5_rqst *rqst, struct surfacegen5_ec *ec)
{
	u8 *w = out;

	*w++ = 0x80;
	*w++ = SG5_BYTELEN_CMDFRAME + rqst->cdl;	// without CRC
	*w++ = 0x00;
	*w++ = ec->count.seq;

	return surfacegen5_ssh_write_crc(w, out, w - out);
}

inline static u8 *surfacegen5_ssh_write_cmd(u8 *out, struct surfacegen5_rqst *rqst, struct surfacegen5_ec *ec)
{
	u8 *w = out;

	*w++ = 0x80;
	*w++ = rqst->tc;
	*w++ = 0x01;
	*w++ = 0x00;
	*w++ = rqst->iid;

	w = surfacegen5_ssh_write_u16(w, ec->count.pld);

	*w++ = rqst->cid;

	w = memcpy(w, rqst->pld, rqst->cdl) + rqst->cdl;

	return surfacegen5_ssh_write_crc(w, out, w - out);
}


int surfacegen5_ec_rqst(struct surfacegen5_rqst *rqst, struct surfacegen5_buf *result)
{
	struct surfacegen5_ec *ec;
	u8 *w;
	int status = 0;

	if (rqst->cdl > SURFACEGEN5_MAX_RQST_PAYLOAD) {
		return -EINVAL;
	}

	ec = surfacegen5_ec_acquire_init();
	if (!ec) {
		printk(RQST_WARN "embedded controller is uninitialized\n");
		return -ENXIO;
	}

	// build request message
	w = ec->buf_write.data;
	w = surfacegen5_ssh_write_syn(w);
	w = surfacegen5_ssh_write_hdr(w, rqst, ec);
	w = surfacegen5_ssh_write_cmd(w, rqst, ec);

	print_hex_dump(KERN_INFO, "rqst: ", DUMP_PREFIX_OFFSET, 16, 1,
	               ec->buf_write.data, w - ec->buf_write.data, false);

	status = serdev_device_write(ec->serdev, ec->buf_write.data,
				     w - ec->buf_write.data, SG5_WRITE_TIMEOUT);

	if (status) {
		goto rqst_out_release;
	}

	// TODO: surfacegen5_ec_rqst

	// FIXME: temporary fix for base status (lid notify loop)
	if (
		rqst->tc  == 0x11 &&
		rqst->iid == 0x00 &&
		rqst->cid == 0x0D &&
		rqst->snc == 0x01
	) {
		if (result->cap < 1) {
			printk(RQST_ERR "output buffer too small\n");

			status = -ENOMEM;
			goto rqst_out_release;
		}

		printk(RQST_INFO "handling base state request\n");

		result->len     = 0x01;
		result->data[0] = 0x01;		// base-status: attached

		goto rqst_out_release;
	}

	printk(RQST_WARN "unsupported request: RQST(0x%02x, 0x%02x, 0x%02x)\n",
	       rqst->tc, rqst->cid, rqst->iid);

rqst_out_release:
	surfacegen5_ec_release(ec);
	return status;
}

static int surfacegen5_ssh_receive_buf(struct serdev_device *serdev,
                                       const unsigned char *buf, size_t size)
{
	// TODO: surfacegen5_ssh_receive_buf

	dev_info(&serdev->dev, "received buffer (size: %zu)\n", size);
	print_hex_dump(KERN_INFO, "recv: ", DUMP_PREFIX_OFFSET, 16, 1, buf, size, false);

	return size;
}

static acpi_status
surfacegen5_ssh_setup_from_resource(struct acpi_resource *resource, void *context)
{
	struct serdev_device *serdev = context;
	struct acpi_resource_common_serialbus *serial;
	struct acpi_resource_uart_serialbus *uart;
	int status = 0;

	if (resource->type != ACPI_RESOURCE_TYPE_SERIAL_BUS) {
		return AE_OK;
	}

	serial = &resource->data.common_serial_bus;
	if (serial->type != ACPI_RESOURCE_SERIAL_TYPE_UART) {
		return AE_OK;
	}

	dev_info(&serdev->dev, "surfacegen5_ssh_setup_from_resource\n");

	uart = &resource->data.uart_serial_bus;

	// set up serdev device
 	serdev_device_set_baudrate(serdev, uart->default_baud_rate);

	// serdev currently only supports RTSCTS flow control
	if (uart->flow_control & SG5_SUPPORTED_FLOW_CONTROL_MASK) {
		dev_warn(&serdev->dev, "unsupported flow control (value: 0x%02x)\n", uart->flow_control);
	}

	// set RTSCTS flow control
	serdev_device_set_flow_control(serdev, uart->flow_control & ACPI_UART_FLOW_CONTROL_HW);

	// serdev currently only supports EVEN/ODD parity
	switch (uart->parity) {
	case ACPI_UART_PARITY_NONE:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_NONE);
		break;
	case ACPI_UART_PARITY_EVEN:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_EVEN);
		break;
	case ACPI_UART_PARITY_ODD:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_ODD);
		break;
	default:
		dev_warn(&serdev->dev, "unsupported parity (value: 0x%02x)\n", uart->parity);
		break;
	}

	if (status) {
		dev_err(&serdev->dev, "failed to set parity (value: 0x%02x)\n", uart->parity);
		return status;
	}

	return AE_CTRL_TERMINATE;       // we've found the resource and are done
}


static const struct serdev_device_ops surfacegen5_ssh_device_ops = {
	.receive_buf  = surfacegen5_ssh_receive_buf,
	.write_wakeup = serdev_device_write_wakeup,
};

static int surfacegen5_acpi_notify_ssh_probe(struct serdev_device *serdev)
{
	struct surfacegen5_ec *ec;
	u8 *buf;
	acpi_handle *ssh = ACPI_HANDLE(&serdev->dev);
	acpi_status status;

	dev_info(&serdev->dev, "surfacegen5_acpi_notify_ssh_probe\n");

	serdev_device_set_client_ops(serdev, &surfacegen5_ssh_device_ops);
	status = serdev_device_open(serdev);
	if (status) {
		return status;
	}

	status = acpi_walk_resources(ssh, METHOD_NAME__CRS,
	                             surfacegen5_ssh_setup_from_resource, serdev);
	if (ACPI_FAILURE(status)) {
		serdev_device_close(serdev);
		return status;
	}

	buf = kzalloc(SG5_MAX_WRITE, GFP_KERNEL);
	if (!buf) {
		serdev_device_close(serdev);
		return -ENOMEM;
	}

	// set up EC state
	ec = surfacegen5_ec_acquire();
	if (ec->state != SG5_EC_UNINITIALIZED) {
		dev_err(&serdev->dev, "embedded controller already initialized\n");
		surfacegen5_ec_release(ec);
		return -EBUSY;		// already initialized via other device
	}

	ec->serdev         = serdev;
	ec->buf_write.cap  = SG5_MAX_WRITE;
	ec->buf_write.data = buf;
	ec->state          = SG5_EC_INITIALIZED;

	surfacegen5_ec_release(ec);

	// TODO: read-buffer setup

	return 0;
}

static void surfacegen5_acpi_notify_ssh_remove(struct serdev_device *serdev)
{
	struct surfacegen5_ec *ec;

	dev_info(&serdev->dev, "surfacegen5_acpi_notify_ssh_remove\n");		// TODO: serdev driver

	ec = surfacegen5_ec_acquire_init();
	if (ec && ec->serdev == serdev) {
		ec->state  = SG5_EC_UNINITIALIZED;
		ec->serdev = NULL;

		kfree(ec->buf_write.data);
		ec->buf_write.cap  = 0;
		ec->buf_write.data = NULL;
	}
	surfacegen5_ec_release(ec);

	serdev_device_close(serdev);
}


static const struct acpi_device_id surfacegen5_acpi_notify_ssh_match[] = {
	{ "MSHW0084", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surfacegen5_acpi_notify_ssh_match);

struct serdev_device_driver surfacegen5_acpi_notify_ssh = {
	.probe = surfacegen5_acpi_notify_ssh_probe,
	.remove = surfacegen5_acpi_notify_ssh_remove,
	.driver = {
		.name = "surfacegen5_acpi_notify_ssh",
		.acpi_match_table = ACPI_PTR(surfacegen5_acpi_notify_ssh_match),
	},
};

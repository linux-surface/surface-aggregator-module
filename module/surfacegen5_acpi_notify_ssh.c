#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/serdev.h>
#include <linux/crc-ccitt.h>
#include <linux/spinlock.h>
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
#define SG5_BYTELEN_CTRL	4		// command-header, ACK, or RETRY
#define SG5_BYTELEN_CMDFRAME	8		// without payload

#define SG5_MAX_WRITE (                \
	  SG5_BYTELEN_SYNC             \
      	+ SG5_BYTELEN_CTRL             \
	+ SG5_BYTELEN_CRC              \
      	+ SG5_BYTELEN_CMDFRAME         \
	+ SURFACEGEN5_MAX_RQST_PAYLOAD \
	+ SG5_BYTELEN_CRC              \
)

#define SG5_WRITE_TIMEOUT	msecs_to_jiffies(1000)
#define SG5_RETRY		3

#define SG5_FRAMETYPE_CMD	0x80
#define SG5_FRAMETYPE_ACK	0x40
#define SG5_FRAMETYPE_RETRY	0x04


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
 * Ack:                 	40 00 00 SEQ
 * Retry:			04 00 00 00
 * Command Request Frame:	80 RTC 01 00 RIID CNT16LE RCID PLD
 * Command Response Frame:	80 RTC 00 01 RIID CNT16LE RCID PLD
 */

struct surfacegen5_frame_ctrl {
	u8 type;
	u8 len;
	u8 pad;
	u8 seq;
} __packed;

struct surfacegen5_frame_cmd {
	u8 type;
	u8 tc;
	u8 unknown1;
	u8 unknown2;
	u8 iid;
	u8 cnt_lo;
	u8 cnt_hi;
	u8 cid;
} __packed;


enum surfacegen5_ec_state {
	SG5_EC_UNINITIALIZED,
	SG5_EC_INITIALIZED,
};

struct surfacegen5_ec_counters {
	u8  seq;
	u16 pld;
};

struct surfacegen5_ec_writer {
	u8 *data;
	u8 *ptr;
};

enum surfacegen5_ec_receiver_state {
	SG5_RCV_DISCARD,
	SG5_RCV_SYNC,
	SG5_RCV_CTRL,
	SG5_RCV_CMD,
};

struct surfacegen5_ec_receiver {
	spinlock_t                         lock;
	enum surfacegen5_ec_receiver_state state;
};

struct surfacegen5_ec {
	struct mutex                   lock;
	enum surfacegen5_ec_state      state;
	struct serdev_device          *serdev;
	struct device_link            *link;
	struct surfacegen5_ec_counters count;
	struct surfacegen5_ec_writer   writer;
	struct surfacegen5_ec_receiver receiver;
};


static struct surfacegen5_ec surfacegen5_ec = {
	.lock   = __MUTEX_INITIALIZER(surfacegen5_ec.lock),
	.state  = SG5_EC_UNINITIALIZED,
	.serdev = NULL,
	.count = {
		.seq = 0,
		.pld = 0,
	},
	.writer = {
		.data = NULL,
		.ptr  = NULL,
	},
	.receiver = {
		.lock  = __SPIN_LOCK_UNLOCKED(surfacegen5_ec.receiver.lock),
		.state = SG5_RCV_DISCARD,
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

inline static u16 surfacegen5_ssh_crc(const u8 *buf, size_t size)
{
	return crc_ccitt_false(0xffff, buf, size);
}

inline static void surfacegen5_ssh_write_u16(struct surfacegen5_ec_writer *writer, u16 in)
{
	put_unaligned_le16(in, writer->ptr);
	writer->ptr += 2;
}

inline static void surfacegen5_ssh_write_crc(struct surfacegen5_ec_writer *writer,
                                             const u8 *buf, size_t size)
{
	surfacegen5_ssh_write_u16(writer, surfacegen5_ssh_crc(buf, size));
}

inline static void surfacegen5_ssh_write_syn(struct surfacegen5_ec_writer *writer)
{
	u8 *w = writer->ptr;

	*w++ = 0xaa;
	*w++ = 0x55;

	writer->ptr = w;
}

inline static void surfacegen5_ssh_write_ter(struct surfacegen5_ec_writer *writer)
{
	u8 *w = writer->ptr;

	*w++ = 0xff;
	*w++ = 0xff;

	writer->ptr = w;
}

inline static void surfacegen5_ssh_write_buf(struct surfacegen5_ec_writer *writer,
                                            u8 *in, size_t len)
{
	writer->ptr = memcpy(writer->ptr, in, len) + len;
}

inline static void surfacegen5_ssh_write_hdr(struct surfacegen5_ec_writer *writer,
                                             struct surfacegen5_rqst *rqst,
                                             struct surfacegen5_ec *ec)
{
	struct surfacegen5_frame_ctrl *hdr = (struct surfacegen5_frame_ctrl *)writer->ptr;
	u8 *begin = writer->ptr;

	hdr->type = SG5_FRAMETYPE_CMD;
	hdr->len  = SG5_BYTELEN_CMDFRAME + rqst->cdl;	// without CRC
	hdr->pad  = 0x00;
	hdr->seq  = ec->count.seq;

	writer->ptr += sizeof(*hdr);

	surfacegen5_ssh_write_crc(writer, begin, writer->ptr - begin);
}

inline static void surfacegen5_ssh_write_cmd(struct surfacegen5_ec_writer *writer,
                                             struct surfacegen5_rqst *rqst,
                                             struct surfacegen5_ec *ec)
{
	struct surfacegen5_frame_cmd *cmd = (struct surfacegen5_frame_cmd *)writer->ptr;
	u8 *begin = writer->ptr;
	u8 cnt_lo = ec->count.pld & 0xFF;
	u8 cnt_hi = ec->count.pld >> 8;

	cmd->type     = SG5_FRAMETYPE_CMD;
	cmd->tc       = rqst->tc;
	cmd->unknown1 = 0x01;
	cmd->unknown2 = 0x00;
	cmd->iid      = rqst->iid;
	cmd->cnt_lo   = cnt_lo;
	cmd->cnt_hi   = cnt_hi;
	cmd->cid      = rqst->cid;

	writer->ptr += sizeof(*cmd);

	surfacegen5_ssh_write_buf(writer, rqst->pld, rqst->cdl);
	surfacegen5_ssh_write_crc(writer, begin, writer->ptr - begin);
}

inline static void surfacegen5_ssh_write_ack(struct surfacegen5_ec_writer *writer, u8 seq)
{
	struct surfacegen5_frame_ctrl *ack = (struct surfacegen5_frame_ctrl *)writer->ptr;
	u8 *begin = writer->ptr;

	ack->type = SG5_FRAMETYPE_ACK;
	ack->len  = 0x00;
	ack->pad  = 0x00;
	ack->seq  = seq;

	writer->ptr += sizeof(*ack);

	surfacegen5_ssh_write_crc(writer, begin, writer->ptr - begin);
	surfacegen5_ssh_write_ter(writer);
}

inline static int surfacegen5_ssh_writer_flush(struct serdev_device *serdev,
                                               struct surfacegen5_ec_writer *writer)
{
	size_t len = writer->ptr - writer->data;
	int status;

	status = serdev_device_write(serdev, writer->data, len, SG5_WRITE_TIMEOUT);
	if (!status) {
		serdev_device_write_flush(serdev);
	}

	return status;
}

inline static void surfacegen5_ssh_writer_reset(struct surfacegen5_ec_writer *writer)
{
	writer->ptr = writer->data;
}


int surfacegen5_ec_rqst(struct surfacegen5_rqst *rqst, struct surfacegen5_buf *result)
{
	struct surfacegen5_ec *ec;
	unsigned long flags;
	int retry;
	int response_seq;
	int status = 0;

	if (rqst->cdl > SURFACEGEN5_MAX_RQST_PAYLOAD) {
		printk(RQST_ERR "request payload too large\n");
		return -EINVAL;
	}

	ec = surfacegen5_ec_acquire_init();
	if (!ec) {
		printk(RQST_WARN "embedded controller is uninitialized\n");
		return -ENXIO;
	}

	// build request message
	surfacegen5_ssh_writer_reset(&ec->writer);
	surfacegen5_ssh_write_syn(&ec->writer);
	surfacegen5_ssh_write_hdr(&ec->writer, rqst, ec);
	surfacegen5_ssh_write_cmd(&ec->writer, rqst, ec);

	print_hex_dump(KERN_INFO, "send: ", DUMP_PREFIX_OFFSET, 16, 1,
	               ec->writer.data, ec->writer.ptr - ec->writer.data,
		       false);

	// reset receiver
	spin_lock_irqsave(&ec->receiver.lock, flags);
	ec->receiver.state = SG5_RCV_SYNC;
	// TODO: clear buffer
	spin_unlock_irqrestore(&ec->receiver.lock, flags);

	// write command message, retry if necessary
	retry = SG5_RETRY;
	do {
		status = surfacegen5_ssh_writer_flush(ec->serdev, &ec->writer);
		if (status) {
			printk(RQST_ERR "error writing request: %d\n", status);
			goto rqst_out_release;
		}

		// read ACK/RETRY
		// TODO: read ack/retry

		// TODO: if ack
		retry = 0;
		// TODO: else retry -= 1

	} while (retry > 0);

//	// increment counters
//	ec->count.seq += 1;
//	ec->count.pld += 1;
//
//	// if we expect a response/payload, read it
//	if (rqst->snc) {
//		response_seq = 0;	// TODO: read response
//
//		// build ACK message
//		surfacegen5_ssh_writer_reset(&ec->writer);
//		surfacegen5_ssh_write_syn(&ec->writer);
//		surfacegen5_ssh_write_ack(&ec->writer, response_seq);
//
//		// send ACK message
//		status = surfacegen5_ssh_writer_flush(ec->serdev, &ec->writer);
//		if (status) {
//			printk(RQST_ERR "error writing ACK: %d\n", status);
//			goto rqst_out_release;
//		}
//
//	} else {
//		result->len = 0;
//	}

	// set receiver to discard
	spin_lock_irqsave(&ec->receiver.lock, flags);
	ec->receiver.state = SG5_RCV_DISCARD;
	// TODO: clear buffer
	spin_unlock_irqrestore(&ec->receiver.lock, flags);

rqst_out_release:
	surfacegen5_ec_release(ec);
	return status;
}

static int surfacegen5_ssh_receive_buf(struct serdev_device *serdev,
                                       const unsigned char *buf, size_t size)
{
	struct surfacegen5_ec_receiver *rcv = serdev_device_get_drvdata(serdev);
	unsigned long flags;
	const u8 *src = buf;
	const u8 *end = buf + size;

	dev_info(&serdev->dev, "received buffer (size: %zu)\n", size);
	print_hex_dump(KERN_INFO, "recv: ", DUMP_PREFIX_OFFSET, 16, 1, buf, size, false);

	// TODO:
	// - notify when syn-ack-term, syn-retry-term, or syn-cmdhdr-cmdfame received
	// - validate crc

	spin_lock_irqsave(&rcv->lock, flags);
//	while (src < end) {
//		switch (rcv->state) {
//		case SG5_RCV_SYNC:
//			// TODO
//			break;
//
//		case SG5_RCV_CTRL:
//			// TODO
//			break;
//
//		case SG5_RCV_CMD:
//			// TODO
//			break;
//
//		case SG5_RCV_DISCARD:
//			// TODO
//			break;
//		}
//	}
	spin_unlock_irqrestore(&rcv->lock, flags);

	return src - buf;
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
	unsigned long flags;
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

	// set up EC
	ec = surfacegen5_ec_acquire();
	if (ec->state != SG5_EC_UNINITIALIZED) {
		dev_err(&serdev->dev, "embedded controller already initialized\n");
		surfacegen5_ec_release(ec);
		return -EBUSY;		// already initialized via other device
	}

	ec->serdev      = serdev;
	ec->writer.data = buf;
	ec->writer.ptr  = buf;

	spin_lock_irqsave(&ec->receiver.lock, flags);
	ec->receiver.state = SG5_RCV_DISCARD;
	// TODO: setup receiver
	spin_unlock_irqrestore(&ec->receiver.lock, flags);

	ec->state = SG5_EC_INITIALIZED;

	serdev_device_set_drvdata(serdev, &ec->receiver);
	surfacegen5_ec_release(ec);

	return 0;
}

static void surfacegen5_acpi_notify_ssh_remove(struct serdev_device *serdev)
{
	struct surfacegen5_ec *ec;
	unsigned long flags;

	dev_info(&serdev->dev, "surfacegen5_acpi_notify_ssh_remove\n");		// TODO: serdev driver

	ec = surfacegen5_ec_acquire_init();
	if (ec && ec->serdev == serdev) {
		ec->state  = SG5_EC_UNINITIALIZED;
		ec->serdev = NULL;

		kfree(ec->writer.data);
		ec->writer.data = NULL;
		ec->writer.ptr  = NULL;

		spin_lock_irqsave(&ec->receiver.lock, flags);
		ec->receiver.state = SG5_RCV_DISCARD;
		// TODO: free receiver
		spin_unlock_irqrestore(&ec->receiver.lock, flags);
	}
	surfacegen5_ec_release(ec);

	serdev_device_set_drvdata(serdev, NULL);
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

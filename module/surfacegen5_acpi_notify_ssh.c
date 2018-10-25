#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/serdev.h>
#include <linux/crc-ccitt.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/kfifo.h>
#include <linux/completion.h>
#include <asm/unaligned.h>

#include "surfacegen5_acpi_notify_ec.h"


#define RQST_PREFIX			"surfacegen5_ec_rqst: "
#define RQST_INFO			KERN_INFO RQST_PREFIX
#define RQST_WARN			KERN_WARNING RQST_PREFIX
#define RQST_ERR			KERN_ERR RQST_PREFIX

#define RECV_PREFIX			"surfacegen5_ssh_receive_buf: "
#define RECV_INFO			KERN_INFO RECV_PREFIX
#define RECV_WARN			KERN_WARNING RECV_PREFIX
#define RECV_ERR			KERN_ERR RECV_PREFIX

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

#define SG5_MSG_LEN_CTRL (             \
	  SG5_BYTELEN_SYNC             \
      	+ SG5_BYTELEN_CTRL             \
	+ SG5_BYTELEN_CRC              \
	+ SG5_BYTELEN_TERM             \
)

#define SG5_MSG_LEN_CMD_BASE (         \
	  SG5_BYTELEN_SYNC             \
      	+ SG5_BYTELEN_CTRL             \
	+ SG5_BYTELEN_CRC              \
	+ SG5_BYTELEN_CRC              \
)	// without payload and command-frame

#define SG5_WRITE_TIMEOUT		msecs_to_jiffies(1000)
#define SG5_READ_TIMEOUT		msecs_to_jiffies(1000)
#define SG5_RETRY			3

#define SG5_FRAME_TYPE_CMD		0x80
#define SG5_FRAME_TYPE_ACK		0x40
#define SG5_FRAME_TYPE_RETRY		0x04

#define SG5_FRAME_OFFS_CTRL		SG5_BYTELEN_SYNC
#define SG5_FRAME_OFFS_CTRL_CRC		(SG5_FRAME_OFFS_CTRL + SG5_BYTELEN_CTRL)
#define SG5_FRAME_OFFS_TERM		(SG5_FRAME_OFFS_CTRL_CRC + SG5_BYTELEN_CRC)
#define SG5_FRAME_OFFS_CMD		SG5_FRAME_OFFS_TERM	// either TERM or CMD
#define SG5_FRAME_OFFS_CMD_PLD		(SG5_FRAME_OFFS_CMD + SG5_BYTELEN_CMDFRAME)

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
	u8 len;			// without crc
	u8 pad;
	u8 seq;
} __packed;

struct surfacegen5_frame_cmd {
	u8 type;
	u8 tc;
	u8 unknown1;
	u8 unknown2;
	u8 iid;
	u8 rqid_lo;		// id for request/response matching (low byte)
	u8 rqid_hi;		// id for request/response matching (high byte)
	u8 cid;
} __packed;


enum surfacegen5_ec_state {
	SG5_EC_UNINITIALIZED,
	SG5_EC_INITIALIZED,
};

struct surfacegen5_ec_counters {
	u8  seq;		// control sequence id
	u16 rqid;		// id for request/response matching
};

struct surfacegen5_ec_writer {
	u8 *data;
	u8 *ptr;
};

enum surfacegen5_ec_receiver_state {
	SG5_RCV_DISCARD,
	SG5_RCV_CONTROL,
	SG5_RCV_COMMAND,
};

struct surfacegen5_ec_receiver {
	spinlock_t        lock;
	struct completion signal;
	enum surfacegen5_ec_receiver_state state;
	struct {
		bool pld;
		u8   seq;
		u16  rqid;
	} expect;
};

struct surfacegen5_ec {
	struct mutex                   lock;
	enum surfacegen5_ec_state      state;
	struct serdev_device          *serdev;
	struct device_link            *link;
	struct surfacegen5_ec_counters counter;
	struct surfacegen5_ec_writer   writer;
	struct surfacegen5_ec_receiver receiver;
};


static struct surfacegen5_ec surfacegen5_ec = {
	.lock   = __MUTEX_INITIALIZER(surfacegen5_ec.lock),
	.state  = SG5_EC_UNINITIALIZED,
	.serdev = NULL,
	.counter = {
		.seq  = 0,
		.rqid = 0,
	},
	.writer = {
		.data = NULL,
		.ptr  = NULL,
	},
	.receiver = {
		.lock = __SPIN_LOCK_UNLOCKED(),
		.state = SG5_RCV_DISCARD,
		.expect = {},
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

	hdr->type = SG5_FRAME_TYPE_CMD;
	hdr->len  = SG5_BYTELEN_CMDFRAME + rqst->cdl;	// without CRC
	hdr->pad  = 0x00;
	hdr->seq  = ec->counter.seq;

	writer->ptr += sizeof(*hdr);

	surfacegen5_ssh_write_crc(writer, begin, writer->ptr - begin);
}

inline static void surfacegen5_ssh_write_cmd(struct surfacegen5_ec_writer *writer,
                                             struct surfacegen5_rqst *rqst,
                                             struct surfacegen5_ec *ec)
{
	struct surfacegen5_frame_cmd *cmd = (struct surfacegen5_frame_cmd *)writer->ptr;
	u8 *begin = writer->ptr;
	u8 rqid_lo = ec->counter.rqid & 0xFF;
	u8 rqid_hi = ec->counter.rqid >> 8;

	cmd->type     = SG5_FRAME_TYPE_CMD;
	cmd->tc       = rqst->tc;
	cmd->unknown1 = 0x01;
	cmd->unknown2 = 0x00;
	cmd->iid      = rqst->iid;
	cmd->rqid_lo  = rqid_lo;
	cmd->rqid_hi  = rqid_hi;
	cmd->cid      = rqst->cid;

	writer->ptr += sizeof(*cmd);

	surfacegen5_ssh_write_buf(writer, rqst->pld, rqst->cdl);
	surfacegen5_ssh_write_crc(writer, begin, writer->ptr - begin);
}

inline static void surfacegen5_ssh_write_ack(struct surfacegen5_ec_writer *writer, u8 seq)
{
	struct surfacegen5_frame_ctrl *ack = (struct surfacegen5_frame_ctrl *)writer->ptr;
	u8 *begin = writer->ptr;

	ack->type = SG5_FRAME_TYPE_ACK;
	ack->len  = 0x00;
	ack->pad  = 0x00;
	ack->seq  = seq;

	writer->ptr += sizeof(*ack);

	surfacegen5_ssh_write_crc(writer, begin, writer->ptr - begin);
}

inline static void surfacegen5_ssh_writer_reset(struct surfacegen5_ec_writer *writer)
{
	writer->ptr = writer->data;
}

inline static int surfacegen5_ssh_writer_flush(struct surfacegen5_ec *ec)
{
	struct surfacegen5_ec_writer *writer = &ec->writer;
	struct serdev_device *serdev = ec->serdev;

	size_t len = writer->ptr - writer->data;
	int status;

	print_hex_dump(KERN_INFO, "send: ", DUMP_PREFIX_OFFSET, 16, 1,
	               writer->data, writer->ptr - writer->data, false);

	status = serdev_device_write(serdev, writer->data, len, SG5_WRITE_TIMEOUT);
	if (!status) {
		serdev_device_write_flush(serdev);
	}

	return status;
}

inline static void surfacegen5_ssh_write_msg_cmd(struct surfacegen5_ec *ec,
                                                 struct surfacegen5_rqst *rqst)
{
	surfacegen5_ssh_writer_reset(&ec->writer);
	surfacegen5_ssh_write_syn(&ec->writer);
	surfacegen5_ssh_write_hdr(&ec->writer, rqst, ec);
	surfacegen5_ssh_write_cmd(&ec->writer, rqst, ec);
}

inline static void surfacegen5_ssh_write_msg_ack(struct surfacegen5_ec *ec, u8 seq)
{
	surfacegen5_ssh_writer_reset(&ec->writer);
	surfacegen5_ssh_write_syn(&ec->writer);
	surfacegen5_ssh_write_ack(&ec->writer, seq);
	surfacegen5_ssh_write_ter(&ec->writer);
}

inline static void surfacegen5_ssh_receiver_restart(struct surfacegen5_ec *ec,
                                                    struct surfacegen5_rqst *rqst)
{
	unsigned long flags;

	spin_lock_irqsave(&ec->receiver.lock, flags);
	reinit_completion(&ec->receiver.signal);
	ec->receiver.state = SG5_RCV_CONTROL;
	ec->receiver.expect.pld  = rqst->snc;
	ec->receiver.expect.seq  = ec->counter.seq;
	ec->receiver.expect.rqid = ec->counter.rqid;
	spin_unlock_irqrestore(&ec->receiver.lock, flags);
}

inline static void surfacegen5_ssh_receiver_discard(struct surfacegen5_ec *ec)
{
	unsigned long flags;

	spin_lock_irqsave(&ec->receiver.lock, flags);
	ec->receiver.state = SG5_RCV_DISCARD;
	// TODO: clear receive buffer
	spin_unlock_irqrestore(&ec->receiver.lock, flags);
}


int surfacegen5_ec_rqst(struct surfacegen5_rqst *rqst, struct surfacegen5_buf *result)
{
	struct surfacegen5_ec *ec;
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

	// write command in buffer, we may need it multiple times
	surfacegen5_ssh_write_msg_cmd(ec, rqst);

//	surfacegen5_ssh_receiver_restart(ec, rqst);
//
//	status = surfacegen5_ssh_writer_flush(ec);
//	wait_for_completion(&ec->receiver.signal);
//
//	surfacegen5_ssh_write_msg_ack(ec, 0);
//
//	status = surfacegen5_ssh_writer_flush(ec);
//	wait_for_completion(&ec->receiver.signal);
//
//	surfacegen5_ssh_receiver_discard(ec);

	surfacegen5_ec_release(ec);
	return status;
}


inline static bool surfacegen5_ssh_is_valid_syn(const u8 *ptr)
{
	return ptr[0] == 0xaa && ptr[1] == 0x55;
}

inline static bool surfacegen5_ssh_is_valid_ter(const u8 *ptr)
{
	return ptr[0] == 0xff && ptr[1] == 0xff;
}

inline static bool surfacegen5_ssh_is_valid_crc(const u8 *begin, const u8 *end)
{
	u16 crc = surfacegen5_ssh_crc(begin, end - begin);
	return (end[0] == (crc & 0xff)) && (end[1] == (crc >> 8));
}


static int surfacegen5_ssh_receive_msg_ctrl(struct surfacegen5_ec_receiver *rcv,
                                            const unsigned char *buf, size_t size)
{
	const struct surfacegen5_frame_ctrl *ctrl;

	const u8 *ctrl_begin = buf + SG5_FRAME_OFFS_CTRL;
	const u8 *ctrl_end   = buf + SG5_FRAME_OFFS_CTRL_CRC;

	ctrl = (const struct surfacegen5_frame_ctrl *)(ctrl_begin);

	// actual length check
	if (size < SG5_MSG_LEN_CTRL) {
		return 0;			// need more bytes
	}

	// validate TERM
	if (!surfacegen5_ssh_is_valid_ter(buf + SG5_FRAME_OFFS_TERM)) {
		printk(RECV_ERR "invalid end of message\n");
		return size;			// discard everything
	}

	// validate CRC
	if (!surfacegen5_ssh_is_valid_crc(ctrl_begin, ctrl_end)) {
		printk(RECV_ERR "invalid checksum\n");
		return SG5_MSG_LEN_CTRL;	// only discard message
	}

	// check if we expect the message
	if (rcv->state != SG5_RCV_CONTROL) {
		return SG5_MSG_LEN_CTRL;	// discard message
	}

	// check if it is for our request
	if (ctrl->type == SG5_FRAME_TYPE_ACK && ctrl->seq != rcv->expect.seq) {
		return SG5_MSG_LEN_CTRL;	// discard message
	}

	// we now have a valid & expected ACK/RETRY message
	printk(RECV_INFO "valid control message received (type: 0x%02x)\n", ctrl->type);

	// TODO: handle ack/retry message

	// update decoder state
	if (ctrl->type == SG5_FRAME_TYPE_ACK) {
		rcv->state = rcv->expect.pld
			? SG5_RCV_COMMAND
			: SG5_RCV_DISCARD;
	}

	complete(&rcv->signal);
	return SG5_MSG_LEN_CTRL;		// handled message
}

static int surfacegen5_ssh_receive_msg_cmd(struct surfacegen5_ec_receiver *rcv,
                                           const unsigned char *buf, size_t size)
{
	const struct surfacegen5_frame_ctrl *ctrl;
	const struct surfacegen5_frame_cmd *cmd;

	const u8 *ctrl_begin     = buf + SG5_FRAME_OFFS_CTRL;
	const u8 *ctrl_end       = buf + SG5_FRAME_OFFS_CTRL_CRC;
	const u8 *cmd_begin      = buf + SG5_FRAME_OFFS_CMD;
	const u8 *cmd_begin_pld  = buf + SG5_FRAME_OFFS_CMD_PLD;
	const u8 *cmd_end;

	size_t msg_len;

	ctrl = (const struct surfacegen5_frame_ctrl *)(ctrl_begin);
	cmd  = (const struct surfacegen5_frame_cmd  *)(cmd_begin);

	// validate control-frame CRC
	if (!surfacegen5_ssh_is_valid_crc(ctrl_begin, ctrl_end)) {
		printk(RECV_ERR "invalid checksum\n");
		/*
		 * We can't be sure here if length is valid, thus
		 * discard everything.
		 */
		return size;
	}

	// actual length check (ctrl->len contains command-frame but not crc)
	msg_len = SG5_MSG_LEN_CMD_BASE + ctrl->len;
	if (size < msg_len) {
		return 0;			// need more bytes
	}

	cmd_end = cmd_begin + ctrl->len;

	// validate command-frame type
	if (cmd->type != SG5_FRAME_TYPE_CMD) {
		printk(RECV_ERR "expected command frame type but got 0x%02x\n", cmd->type);
		return size;			// discard everything
	}

	// validate command-frame CRC
	if (!surfacegen5_ssh_is_valid_crc(cmd_begin, cmd_end)) {
		printk(RECV_ERR "invalid checksum\n");
		return msg_len;			// only discard message
	}

	// check if we expect the message
	if (rcv->state != SG5_RCV_COMMAND) {
		return msg_len;			// discard message
	}

	// check if response is for our request
	if (rcv->expect.rqid != (cmd->rqid_lo | (cmd->rqid_hi << 8))) {
		return msg_len;			// discard message
	}

	// we now have a valid & expected command message
	printk(RECV_INFO "command message received\n");

	// TODO: handle command message

	rcv->state = SG5_RCV_DISCARD;

	complete(&rcv->signal);
	return msg_len;				// handled message
}

static int surfacegen5_ssh_receive_buf(struct serdev_device *serdev,
                                       const unsigned char *buf, size_t size)
{
	struct surfacegen5_ec_receiver *rcv = serdev_device_get_drvdata(serdev);
	struct surfacegen5_frame_ctrl *ctrl;
	unsigned long flags;
	int ret;

	dev_info(&serdev->dev, "received buffer (size: %zu)\n", size);
	print_hex_dump(KERN_INFO, "recv: ", DUMP_PREFIX_OFFSET, 16, 1, buf, size, false);

	// we need at least a control frame to check what to do
	if (size < (SG5_BYTELEN_SYNC + SG5_BYTELEN_CTRL)) {
		return 0;		// need more bytes
	}

	// make sure we're actually at the start of a new message
	if (!surfacegen5_ssh_is_valid_syn(buf)) {
		printk(RECV_ERR "invalid start of message\n");
		return size;		// discard everything
	}

	// handle individual message types seperately
	ctrl = (struct surfacegen5_frame_ctrl *)(buf + SG5_FRAME_OFFS_CTRL);

	spin_lock_irqsave(&rcv->lock, flags);
	switch (ctrl->type) {
	case SG5_FRAME_TYPE_ACK:
	case SG5_FRAME_TYPE_RETRY:
		ret = surfacegen5_ssh_receive_msg_ctrl(rcv, buf, size);

	case SG5_FRAME_TYPE_CMD:
		ret = surfacegen5_ssh_receive_msg_cmd(rcv, buf, size);

	default:
		printk(RECV_WARN "unknown frame type 0x%02x\n", ctrl->type);
		ret = size;		// discard everything
	}
	spin_unlock_irqrestore(&rcv->lock, flags);

	return ret;
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
	u8 *write_buf;
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
		goto err_probe_alloc_write;
	}

	write_buf = kzalloc(SG5_MAX_WRITE, GFP_KERNEL);
	if (!write_buf) {
		status = -ENOMEM;
		goto err_probe_alloc_write;
	}

	// set up EC
	ec = surfacegen5_ec_acquire();
	if (ec->state != SG5_EC_UNINITIALIZED) {
		dev_err(&serdev->dev, "embedded controller already initialized\n");
		surfacegen5_ec_release(ec);

		status = -EBUSY;
		goto err_probe_busy;
	}

	ec->serdev      = serdev;
	ec->writer.data = write_buf;
	ec->writer.ptr  = write_buf;

	spin_lock_irqsave(&ec->receiver.lock, flags);
	init_completion(&ec->receiver.signal);
	// TODO: init receive buffer
	spin_unlock_irqrestore(&ec->receiver.lock, flags);

	ec->state = SG5_EC_INITIALIZED;

	serdev_device_set_drvdata(serdev, &ec->receiver);
	surfacegen5_ec_release(ec);

	return 0;

err_probe_busy:
	kfree(write_buf);
err_probe_alloc_write:
	serdev_device_close(serdev);
	return status;
}

static void surfacegen5_acpi_notify_ssh_remove(struct serdev_device *serdev)
{
	struct surfacegen5_ec *ec;
	unsigned long flags;

	dev_info(&serdev->dev, "surfacegen5_acpi_notify_ssh_remove\n");

	ec = surfacegen5_ec_acquire_init();
	if (ec && ec->serdev == serdev) {
		ec->state  = SG5_EC_UNINITIALIZED;
		ec->serdev = NULL;

		kfree(ec->writer.data);
		ec->writer.data = NULL;
		ec->writer.ptr  = NULL;

		spin_lock_irqsave(&ec->receiver.lock, flags);
		ec->receiver.state = SG5_RCV_DISCARD;
		// TODO: free receive buffer
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

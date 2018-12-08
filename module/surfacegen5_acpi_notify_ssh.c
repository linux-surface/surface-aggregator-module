#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/serdev.h>
#include <linux/crc-ccitt.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/kfifo.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/refcount.h>
#include <linux/dmaengine.h>
#include <linux/pm.h>
#include <asm/unaligned.h>

#include "surfacegen5_acpi_notify_ssh.h"


#define RQST_PREFIX			"surfacegen5_ec_rqst: "
#define RQST_INFO			KERN_INFO RQST_PREFIX
#define RQST_WARN			KERN_WARNING RQST_PREFIX
#define RQST_ERR			KERN_ERR RQST_PREFIX

#define RECV_PREFIX			"surfacegen5_ssh_receive_buf: "
#define RECV_INFO			KERN_INFO RECV_PREFIX
#define RECV_WARN			KERN_WARNING RECV_PREFIX
#define RECV_ERR			KERN_ERR RECV_PREFIX

#define EVENT_PREFIX			"surfacegen5_ssh_handle_event: "
#define EVENT_WARN			KERN_WARNING EVENT_PREFIX
#define EVENT_ERR			KERN_ERR EVENT_PREFIX

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
#define SG5_NUM_RETRY			3

#define SG5_WRITE_BUF_LEN		SG5_MAX_WRITE
#define SG5_READ_BUF_LEN		512		// must be power of 2
#define SG5_EVAL_BUF_LEN		SG5_MAX_WRITE	// also works for reading

#define SG5_FRAME_TYPE_CMD		0x80
#define SG5_FRAME_TYPE_ACK		0x40
#define SG5_FRAME_TYPE_RETRY		0x04

#define SG5_FRAME_OFFS_CTRL		SG5_BYTELEN_SYNC
#define SG5_FRAME_OFFS_CTRL_CRC		(SG5_FRAME_OFFS_CTRL + SG5_BYTELEN_CTRL)
#define SG5_FRAME_OFFS_TERM		(SG5_FRAME_OFFS_CTRL_CRC + SG5_BYTELEN_CRC)
#define SG5_FRAME_OFFS_CMD		SG5_FRAME_OFFS_TERM	// either TERM or CMD
#define SG5_FRAME_OFFS_CMD_PLD		(SG5_FRAME_OFFS_CMD + SG5_BYTELEN_CMDFRAME)

// 0 is not a valid event RQID
#define SG5_NUM_EVENT_TYPES		((1 << SURFACEGEN5_RQID_EVENT_BITS) - 1)

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
	SG5_EC_SUSPENDED,
};

struct surfacegen5_ec_counters {
	u8  seq;		// control sequence id
	u16 rqid;		// id for request/response matching
};

struct surfacegen5_ec_writer {
	u8 *data;
	u8 *ptr;
} __packed;

enum surfacegen5_ec_receiver_state {
	SG5_RCV_DISCARD,
	SG5_RCV_CONTROL,
	SG5_RCV_COMMAND,
};

struct surfacegen5_ec_receiver {
	spinlock_t        lock;
	enum surfacegen5_ec_receiver_state state;
	struct completion signal;
	struct kfifo      fifo;
	struct {
		bool pld;
		u8   seq;
		u16  rqid;
	} expect;
	struct {
		u16 cap;
		u16 len;
		u8 *ptr;
	} eval_buf;
};

struct surfacegen5_ec_event_handler {
	surfacegen5_ec_event_handler_fn handler;
	surfacegen5_ec_event_handler_delay delay;
	void *data;
};

struct surfacegen5_ec_events {
	spinlock_t lock;
	struct workqueue_struct *queue_ack;		// TODO: move to system workqueue/don't use any at all?
	struct workqueue_struct *queue_evt;		// TODO: move to system workqueue/don't use any at all?
	struct surfacegen5_ec_event_handler handler[SG5_NUM_EVENT_TYPES];
};

struct surfacegen5_ec {
	struct mutex                   lock;
	enum surfacegen5_ec_state      state;
	struct serdev_device          *serdev;
	struct surfacegen5_ec_counters counter;
	struct surfacegen5_ec_writer   writer;
	struct surfacegen5_ec_receiver receiver;
	struct surfacegen5_ec_events   events;
};

struct surfacegen5_fifo_packet {
	u8 type;	// packet type (ACK/RETRY/CMD)
	u8 seq;
	u8 len;
};

struct surfacegen5_event_work {
	refcount_t               refcount;
	struct surfacegen5_ec   *ec;
	struct work_struct       work_ack;
	struct delayed_work      work_evt;
	struct surfacegen5_event event;
	u8 seq;
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
	.events = {
		.lock = __SPIN_LOCK_UNLOCKED(),
		.handler = {},
	}
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

	if (ec->state == SG5_EC_UNINITIALIZED) {
		surfacegen5_ec_release(ec);
		return NULL;
	}

	return ec;
}

struct device_link *surfacegen5_ec_consumer_add(struct device *consumer, u32 flags)
{
	struct surfacegen5_ec *ec;
	struct device_link *link;

	ec = surfacegen5_ec_acquire_init();
	if (!ec) {
		return ERR_PTR(-ENXIO);
	}

	link = device_link_add(consumer, &ec->serdev->dev, flags);

	surfacegen5_ec_release(ec);
	return link;
}

int surfacegen5_ec_consumer_remove(struct device_link *link)
{
	struct surfacegen5_ec *ec = surfacegen5_ec_acquire_init();
	if (!ec) { return -ENXIO; }

	device_link_del(link);

	surfacegen5_ec_release(ec);
	return 0;
}


inline static u16 surfacegen5_rqid_to_rqst(u16 rqid) {
	return rqid << SURFACEGEN5_RQID_EVENT_BITS;
}

inline static bool surfacegen5_rqid_is_event(u16 rqid) {
	const u16 mask = (1 << SURFACEGEN5_RQID_EVENT_BITS) - 1;
	return rqid != 0 && (rqid | mask) == mask;
}

int surfacegen5_ec_enable_event_source(u8 tc, u8 unknown, u16 rqid)
{
	u8 pld[4] = { tc, unknown, rqid & 0xff, rqid >> 8 };
	struct surfacegen5_rqst rqst = {
		.tc  = 0x01,
		.iid = 0x00,
		.cid = 0x0b,
		.snc = 0x00,
		.cdl = 0x04,
		.pld = pld,
	};

	// only allow RQIDs that lie within event spectrum
	if (!surfacegen5_rqid_is_event(rqid)) {
		return -EINVAL;
	}

	// TODO: make sure there actually is no response for this request

	return surfacegen5_ec_rqst(&rqst, NULL);
}

int surfacegen5_ec_disable_event_source(u8 tc, u8 unknown, u16 rqid)
{
	u8 pld[4] = { tc, unknown, rqid & 0xff, rqid >> 8 };
	struct surfacegen5_rqst rqst = {
		.tc  = 0x01,
		.iid = 0x00,
		.cid = 0x0c,
		.snc = 0x00,
		.cdl = 0x04,
		.pld = pld,
	};

	// only allow RQIDs that lie within event spectrum
	if (!surfacegen5_rqid_is_event(rqid)) {
		return -EINVAL;
	}

	// TODO: make sure there actually is no response for this request

	return surfacegen5_ec_rqst(&rqst, NULL);
}

int surfacegen5_ec_set_delayed_event_handler(
		u16 rqid, surfacegen5_ec_event_handler_fn fn,
		surfacegen5_ec_event_handler_delay delay,
		void *data)
{
	struct surfacegen5_ec *ec;
	unsigned long flags;

	if (!surfacegen5_rqid_is_event(rqid)) {
		return -EINVAL;
	}

	ec = surfacegen5_ec_acquire_init();
	if (!ec) {
		return -ENXIO;
	}

	spin_lock_irqsave(&ec->events.lock, flags);

	// 0 is not a valid event RQID
	ec->events.handler[rqid - 1].handler = fn;
	ec->events.handler[rqid - 1].delay = delay;
	ec->events.handler[rqid - 1].data = data;

	spin_unlock_irqrestore(&ec->events.lock, flags);
	surfacegen5_ec_release(ec);

	return 0;
}

int surfacegen5_ec_set_event_handler(
		u16 rqid, surfacegen5_ec_event_handler_fn fn, void *data)
{
	return surfacegen5_ec_set_delayed_event_handler(rqid, fn, NULL, data);
}

int surfacegen5_ec_remove_event_handler(u16 rqid)
{
	struct surfacegen5_ec *ec;
	unsigned long flags;

	if (!surfacegen5_rqid_is_event(rqid)) {
		return -EINVAL;
	}

	ec = surfacegen5_ec_acquire_init();
	if (!ec) {
		return -ENXIO;
	}

	spin_lock_irqsave(&ec->events.lock, flags);

	// 0 is not a valid event RQID
	ec->events.handler[rqid - 1].handler = NULL;
	ec->events.handler[rqid - 1].data = NULL;

	spin_unlock_irqrestore(&ec->events.lock, flags);
	surfacegen5_ec_release(ec);

 	/*
	 * Make sure that the handler is not in use any more after we've
	 * removed it.
	 */
	 // TODO: make sure that work is actually finished after a flush
	flush_workqueue(ec->events.queue_evt);

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

	u16 rqid = surfacegen5_rqid_to_rqst(ec->counter.rqid);
	u8 rqid_lo = rqid & 0xFF;
	u8 rqid_hi = rqid >> 8;

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

	print_hex_dump(KERN_INFO, "send: ", DUMP_PREFIX_OFFSET, 16, 1,
	               writer->data, writer->ptr - writer->data, false);

	return serdev_device_write(serdev, writer->data, len, SG5_WRITE_TIMEOUT);
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
	ec->receiver.expect.rqid = surfacegen5_rqid_to_rqst(ec->counter.rqid);
	ec->receiver.eval_buf.len = 0;
	spin_unlock_irqrestore(&ec->receiver.lock, flags);
}

inline static void surfacegen5_ssh_receiver_discard(struct surfacegen5_ec *ec)
{
	unsigned long flags;

	spin_lock_irqsave(&ec->receiver.lock, flags);
	ec->receiver.state = SG5_RCV_DISCARD;
	ec->receiver.eval_buf.len = 0;
	kfifo_reset(&ec->receiver.fifo);
	spin_unlock_irqrestore(&ec->receiver.lock, flags);
}

static int surfacegen5_ec_rqst_unlocked(struct surfacegen5_ec *ec,
                                 struct surfacegen5_rqst *rqst,
				 struct surfacegen5_buf *result)
{
	struct surfacegen5_fifo_packet packet = {};
	int status;
	int try;
	unsigned int rem;

	if (rqst->cdl > SURFACEGEN5_MAX_RQST_PAYLOAD) {
		printk(RQST_ERR "request payload too large\n");
		return -EINVAL;
	}

	// write command in buffer, we may need it multiple times
	surfacegen5_ssh_write_msg_cmd(ec, rqst);
	surfacegen5_ssh_receiver_restart(ec, rqst);

	// send command, try to get an ack response
	for (try = 0; try < SG5_NUM_RETRY; try++) {
		status = surfacegen5_ssh_writer_flush(ec);
		if (status) {
			goto ec_rqst_out;
		}

		rem = wait_for_completion_timeout(&ec->receiver.signal, SG5_READ_TIMEOUT);
		if (rem) {
			kfifo_out(&ec->receiver.fifo, &packet, sizeof(packet));

			if (packet.type == SG5_FRAME_TYPE_ACK) {
				break;
			}
		}
	}

	// check if we ran out of tries?
	if (try >= SG5_NUM_RETRY) {
		printk(RQST_ERR "communication failed %d times, giving up\n", try);
		status = -EIO;
		goto ec_rqst_out;
	}

	ec->counter.seq  += 1;
	ec->counter.rqid += 1;

	// get command response/payload
	if (rqst->snc && result) {
		rem = wait_for_completion_timeout(&ec->receiver.signal, SG5_READ_TIMEOUT);
		if (rem) {
			kfifo_out(&ec->receiver.fifo, &packet, sizeof(packet));

			if (result->cap < packet.len) {
				status = -EINVAL;
				goto ec_rqst_out;
			}

			kfifo_out(&ec->receiver.fifo, result->data, packet.len);
			result->len = packet.len;
		} else {
			printk(RQST_ERR "communication timed out\n");
			status = -EIO;
			goto ec_rqst_out;
		}

		// send ACK
		surfacegen5_ssh_write_msg_ack(ec, packet.seq);
		status = surfacegen5_ssh_writer_flush(ec);
		if (status) {
			goto ec_rqst_out;
		}
	}

ec_rqst_out:
	surfacegen5_ssh_receiver_discard(ec);
	return status;
}

int surfacegen5_ec_rqst(struct surfacegen5_rqst *rqst, struct surfacegen5_buf *result)
{
	struct surfacegen5_ec *ec;
	int status;

	ec = surfacegen5_ec_acquire_init();
	if (!ec) {
		printk(RQST_WARN "embedded controller is uninitialized\n");
		return -ENXIO;
	}

	if (ec->state == SG5_EC_SUSPENDED) {
		surfacegen5_ec_release(ec);

		printk(RQST_WARN "embedded controller is suspended\n");
		return -EPERM;
	}

	status = surfacegen5_ec_rqst_unlocked(ec, rqst, result);

	surfacegen5_ec_release(ec);

	return status;
}


static int surfacegen5_ssh_ec_resume(struct surfacegen5_ec *ec)
{
	struct surfacegen5_rqst rqst = {
		.tc  = 0x01,
		.iid = 0x00,
		.cid = 0x16,
		.snc = 0x00,
		.cdl = 0x00,
		.pld = NULL,
	};

	// TODO: according to windows logs, this should return something.
	// Based on linux-testing, it doesn't.
	// -> make sure there actially is no response here (not even empty)

	return surfacegen5_ec_rqst_unlocked(ec, &rqst, NULL);
}

static int surfacegen5_ssh_ec_suspend(struct surfacegen5_ec *ec)
{
	/* Note:
	 * On the Surface Book 2, this also disables keyboard lighting.
	 */

	u8 buf[1];

	struct surfacegen5_rqst rqst = {
		.tc  = 0x01,
		.iid = 0x00,
		.cid = 0x15,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surfacegen5_buf result = {
		result.cap = ARRAY_SIZE(buf),
		result.len = 0,
		result.data = buf,
	};

	// TODO: check result.data?

	return surfacegen5_ec_rqst_unlocked(ec, &rqst, &result);
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


static int surfacegen5_ssh_send_ack(struct surfacegen5_ec *ec, u8 seq)
{
	u8 buf[SG5_MSG_LEN_CTRL];
	u16 crc;

	buf[0] = 0xaa;
	buf[1] = 0x55;
	buf[2] = 0x40;
	buf[3] = 0x00;
	buf[4] = 0x00;
	buf[5] = seq;

	crc = surfacegen5_ssh_crc(buf + SG5_FRAME_OFFS_CTRL, SG5_BYTELEN_CTRL);
	buf[6] = crc & 0xff;
	buf[7] = crc >> 8;

	buf[8] = 0xff;
	buf[9] = 0xff;

	dev_info(&ec->serdev->dev, "sending ACK for seq = 0x%02x\n", seq);

	return serdev_device_write(ec->serdev, buf, SG5_MSG_LEN_CTRL, SG5_WRITE_TIMEOUT);
}

static void surfacegen5_event_work_ack_handler(struct work_struct *_work)
{
	struct surfacegen5_event_work *work;
	struct surfacegen5_event *event;
	struct surfacegen5_ec *ec;
	int status;

 	work = container_of(_work, struct surfacegen5_event_work, work_ack);
	event = &work->event;
	ec = work->ec;

	// make sure we load a fresh ec state
	smp_mb();

	if (ec->state == SG5_EC_INITIALIZED) {
		status = surfacegen5_ssh_send_ack(ec, work->seq);
		if (status) {
			printk(EVENT_ERR "failed to send ACK: %d\n", status);
		}
	}

	if (refcount_dec_and_test(&work->refcount)) {
		kfree(work);
	}
}

static void surfacegen5_event_work_evt_handler(struct work_struct *_work)
{
	struct delayed_work *dwork = (struct delayed_work *)_work;
	struct surfacegen5_event_work *work;
	struct surfacegen5_event *event;
	struct surfacegen5_ec *ec;
	unsigned long flags;

	surfacegen5_ec_event_handler_fn handler;
	void *handler_data;

	int status = 0;

 	work = container_of(dwork, struct surfacegen5_event_work, work_evt);
	event = &work->event;
	ec = work->ec;

	spin_lock_irqsave(&ec->events.lock, flags);
	handler       = ec->events.handler[event->rqid - 1].handler;
	handler_data  = ec->events.handler[event->rqid - 1].data;
	spin_unlock_irqrestore(&ec->events.lock, flags);

	// TODO: this might go wrong when handler gets removed here...?

	if (handler) {
		status = handler(event, handler_data);
	}

	if (status) {
		printk(EVENT_ERR "error handling event: %d\n", status);
	} else if (!handler) {
		printk(EVENT_WARN "unhandled event (rqid: %04x)\n", event->rqid);
	}

	if (refcount_dec_and_test(&work->refcount)) {
		kfree(work);
	}
}

static void surfacegen5_ssh_handle_event(struct surfacegen5_ec *ec, const u8 *buf)
{
	const struct surfacegen5_frame_ctrl *ctrl;
	const struct surfacegen5_frame_cmd *cmd;
	struct surfacegen5_event_work *work;
	unsigned long flags;
	u16 pld_len;

	surfacegen5_ec_event_handler_delay delay_fn;
	void *handler_data;
	unsigned long delay = 0;

	ctrl = (const struct surfacegen5_frame_ctrl *)(buf + SG5_FRAME_OFFS_CTRL);
	cmd  = (const struct surfacegen5_frame_cmd  *)(buf + SG5_FRAME_OFFS_CMD);

	pld_len = ctrl->len - SG5_BYTELEN_CMDFRAME;

	work = kzalloc(sizeof(struct surfacegen5_event_work) + pld_len, GFP_ATOMIC);
	if (!work) {
		printk(EVENT_WARN "failed to allocate memory, dropping event\n");
		return;
	}

	refcount_set(&work->refcount, 2);

	INIT_WORK(&work->work_ack, surfacegen5_event_work_ack_handler);
	INIT_DELAYED_WORK(&work->work_evt, surfacegen5_event_work_evt_handler);

	work->ec         = ec;
	work->seq        = ctrl->seq;
	work->event.rqid = (cmd->rqid_hi << 8) | cmd->rqid_lo;
	work->event.tc   = cmd->tc;
	work->event.iid  = cmd->iid;
	work->event.cid  = cmd->cid;
	work->event.len  = pld_len;
	work->event.pld  = ((u8*) work) + sizeof(struct surfacegen5_event_work);

	memcpy(work->event.pld, buf + SG5_FRAME_OFFS_CMD_PLD, pld_len);

	queue_work(ec->events.queue_ack, &work->work_ack);

	spin_lock_irqsave(&ec->events.lock, flags);
	handler_data = ec->events.handler[work->event.rqid - 1].data;
	delay_fn     = ec->events.handler[work->event.rqid - 1].delay;
	if (delay_fn) {
		delay = delay_fn(&work->event, handler_data);
	}
	spin_unlock_irqrestore(&ec->events.lock, flags);

	queue_delayed_work(ec->events.queue_evt, &work->work_evt, delay);
}

static int surfacegen5_ssh_receive_msg_ctrl(struct surfacegen5_ec *ec,
                                            const u8 *buf, size_t size)
{
	struct surfacegen5_ec_receiver *rcv = &ec->receiver;
	const struct surfacegen5_frame_ctrl *ctrl;
	struct surfacegen5_fifo_packet packet;

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
		printk(RECV_ERR "invalid checksum (ctrl)\n");
		return SG5_MSG_LEN_CTRL;	// only discard message
	}

	// check if we expect the message
	if (rcv->state != SG5_RCV_CONTROL) {
		printk(RECV_INFO "discarding message: ctrl not expected\n");
		return SG5_MSG_LEN_CTRL;	// discard message
	}

	// check if it is for our request
	if (ctrl->type == SG5_FRAME_TYPE_ACK && ctrl->seq != rcv->expect.seq) {
		printk(RECV_INFO "discarding message: ack does not match\n");
		return SG5_MSG_LEN_CTRL;	// discard message
	}

	// we now have a valid & expected ACK/RETRY message
	printk(RECV_INFO "valid control message received (type: 0x%02x)\n", ctrl->type);

	packet.type = ctrl->type;
	packet.seq  = ctrl->seq;
	packet.len  = 0;

	if (kfifo_avail(&rcv->fifo) >= sizeof(packet)) {
		kfifo_in(&rcv->fifo, (u8 *) &packet, sizeof(packet));

	} else {
		printk(RECV_WARN "dropping frame: "
		       "not enough space in fifo (type = %d)\n", ctrl->type);

		return SG5_MSG_LEN_CTRL;	// discard message
	}

	// update decoder state
	if (ctrl->type == SG5_FRAME_TYPE_ACK) {
		rcv->state = rcv->expect.pld
			? SG5_RCV_COMMAND
			: SG5_RCV_DISCARD;
	}

	complete(&rcv->signal);
	return SG5_MSG_LEN_CTRL;		// handled message
}

static int surfacegen5_ssh_receive_msg_cmd(struct surfacegen5_ec *ec,
                                           const u8 *buf, size_t size)
{
	struct surfacegen5_ec_receiver *rcv = &ec->receiver;
	const struct surfacegen5_frame_ctrl *ctrl;
	const struct surfacegen5_frame_cmd *cmd;
	struct surfacegen5_fifo_packet packet;

	const u8 *ctrl_begin     = buf + SG5_FRAME_OFFS_CTRL;
	const u8 *ctrl_end       = buf + SG5_FRAME_OFFS_CTRL_CRC;
	const u8 *cmd_begin      = buf + SG5_FRAME_OFFS_CMD;
	const u8 *cmd_begin_pld  = buf + SG5_FRAME_OFFS_CMD_PLD;
	const u8 *cmd_end;

	size_t msg_len;

	ctrl = (const struct surfacegen5_frame_ctrl *)(ctrl_begin);
	cmd  = (const struct surfacegen5_frame_cmd  *)(cmd_begin);

	// validate associated control frame
	if (size < (SG5_BYTELEN_SYNC + SG5_BYTELEN_CTRL + SG5_BYTELEN_CRC)) {
		return 0;		// need more bytes
	}

	// validate control-frame CRC
	if (!surfacegen5_ssh_is_valid_crc(ctrl_begin, ctrl_end)) {
		printk(RECV_ERR "invalid checksum (cmd-ctrl)\n");
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
		printk(RECV_ERR "invalid checksum (cmd-pld)\n");

		/*
		 * The message length is provided in the control frame. As we
		 * already validated that, we can be sure here that it's
		 * correct, so we only need to discard the message.
		 */
		return msg_len;
	}

	// check if we received an event notification
	if (surfacegen5_rqid_is_event((cmd->rqid_hi << 8) | cmd->rqid_lo)) {
		surfacegen5_ssh_handle_event(ec, buf);
		return msg_len;			// handled message
	}

	// check if we expect the message
	if (rcv->state != SG5_RCV_COMMAND) {
		printk(RECV_INFO "discarding message: command not expected\n");
		return msg_len;			// discard message
	}

	// check if response is for our request
	if (rcv->expect.rqid != (cmd->rqid_lo | (cmd->rqid_hi << 8))) {
		printk(RECV_INFO "discarding message: command not a match\n");
		return msg_len;			// discard message
	}

	// we now have a valid & expected command message
	printk(RECV_INFO "valid command message received\n");

	packet.type = ctrl->type;
	packet.seq = ctrl->seq;
	packet.len = cmd_end - cmd_begin_pld;

	if (kfifo_avail(&rcv->fifo) >= sizeof(packet) + packet.len) {
		kfifo_in(&rcv->fifo, &packet, sizeof(packet));
		kfifo_in(&rcv->fifo, cmd_begin_pld, packet.len);

	} else {
		printk(RECV_WARN "dropping frame: "
		       "not enough space in fifo (type = %d)\n",
		        SG5_FRAME_TYPE_CMD);

		return SG5_MSG_LEN_CTRL;	// discard message
	}

	rcv->state = SG5_RCV_DISCARD;

	complete(&rcv->signal);
	return msg_len;				// handled message
}

static int surfacegen5_ssh_eval_buf(struct surfacegen5_ec *ec,
                                    const u8 *buf, size_t size)
{
	struct surfacegen5_frame_ctrl *ctrl;

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

	switch (ctrl->type) {
	case SG5_FRAME_TYPE_ACK:
	case SG5_FRAME_TYPE_RETRY:
		return surfacegen5_ssh_receive_msg_ctrl(ec, buf, size);

	case SG5_FRAME_TYPE_CMD:
		return surfacegen5_ssh_receive_msg_cmd(ec, buf, size);

	default:
		printk(RECV_WARN "unknown frame type 0x%02x\n", ctrl->type);
		return size;		// discard everything
	}
}

static int surfacegen5_ssh_receive_buf(struct serdev_device *serdev,
                                       const unsigned char *buf, size_t size)
{
	struct surfacegen5_ec *ec = serdev_device_get_drvdata(serdev);
	struct surfacegen5_ec_receiver *rcv = &ec->receiver;
	unsigned long flags;
	int offs = 0;
	int used, n;

	dev_info(&serdev->dev, "received buffer (size: %zu)\n", size);
	print_hex_dump(KERN_INFO, "recv: ", DUMP_PREFIX_OFFSET, 16, 1, buf, size, false);

	/*
         * The battery _BIX message gets a bit long, thus we have to add some
  	 * additional buffering here.
	 */

	spin_lock_irqsave(&rcv->lock, flags);

	// copy to eval-buffer
	used = min(size, (size_t)(rcv->eval_buf.cap - rcv->eval_buf.len));
	memcpy(rcv->eval_buf.ptr + rcv->eval_buf.len, buf, used);
	rcv->eval_buf.len += used;

	// evaluate buffer until we need more bytes or eval-buf is empty
	while (offs < rcv->eval_buf.len) {
		n = rcv->eval_buf.len - offs;
		n = surfacegen5_ssh_eval_buf(ec, rcv->eval_buf.ptr + offs, n);
		if (n <= 0) break;	// need more bytes

		offs += n;
	}

	// throw away the evaluated parts
	rcv->eval_buf.len -= offs;
	memmove(rcv->eval_buf.ptr, rcv->eval_buf.ptr + offs, rcv->eval_buf.len);

	spin_unlock_irqrestore(&rcv->lock, flags);

	return used;
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


static bool surfacegen5_idma_filter(struct dma_chan *chan, void *param)
{
	// see dw8250_idma_filter
	return param == chan->device->dev->parent;
}

static int surfacegen5_ssh_check_dma(struct serdev_device *serdev)
{
	struct device *dev = serdev->ctrl->dev.parent;
	struct dma_chan *rx, *tx;
	dma_cap_mask_t mask;
	int status = 0;

	/*
	 * The EC UART requires DMA for proper communication. If we don't use DMA,
	 * we'll drop bytes when the system has high load, e.g. during boot. This
	 * causes some ugly behaviour, i.e. battery information (_BIX) messages
	 * failing frequently. We're making sure the required DMA channels are
	 * available here so serial8250_do_startup is able to grab them later
	 * instead of silently falling back to a non-DMA approach.
	 */

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	rx = dma_request_slave_channel_compat(mask, surfacegen5_idma_filter, dev->parent, dev, "rx");
	if (IS_ERR_OR_NULL(rx)) {
		status = rx ? PTR_ERR(rx) : -EPROBE_DEFER;
		if (status != -EPROBE_DEFER) {
			dev_err(&serdev->dev, "sg5_dma: error requesting rx channel: %d\n", status);
		} else {
			dev_info(&serdev->dev, "sg5_dma: rx channel not found, deferring probe\n");
		}
		goto check_dma_out;
	}

	tx = dma_request_slave_channel_compat(mask, surfacegen5_idma_filter, dev->parent, dev, "tx");
	if (IS_ERR_OR_NULL(tx)) {
		status = tx ? PTR_ERR(tx) : -EPROBE_DEFER;
		if (status != -EPROBE_DEFER) {
			dev_err(&serdev->dev, "sg5_dma: error requesting tx channel: %d\n", status);
		} else {
			dev_info(&serdev->dev, "sg5_dma: tx channel not found, deferring probe\n");
		}
		goto check_dma_release_rx;
	}

	dev_info(&serdev->dev, "sg5_dma: rx and tx channels found\n");

	dma_release_channel(tx);
check_dma_release_rx:
	dma_release_channel(rx);
check_dma_out:
	return status;
}


static int surfacegen5_ssh_suspend(struct device *dev)
{
	struct surfacegen5_ec *ec;
	int status = 0;

	printk(KERN_INFO "sg5_pm_ssh_suspend\n");

	/*
	 * On the Surface Book 2, "disabling events" also disables the keyboard
	 * backlight (respecitvely "enabling events" enables the keyboard backlight
	 * again). Thus we always disable events regardless if they have been
	 * enabled.
	 *
	 * TODO: Make this more consistent. Either disable/enable events only in the
	 * _SAN or only in the _SSH driver, but not both.
	 */

	// TODO: move to set state method
	ec = surfacegen5_ec_acquire_init();
	if (ec) {
		status = surfacegen5_ssh_ec_suspend(ec);
		if (status) {
			// TODO
		}

		ec->state = SG5_EC_SUSPENDED;
		surfacegen5_ec_release(ec);
	}

	return status;
}

static int surfacegen5_ssh_resume(struct device *dev)
{
	struct surfacegen5_ec *ec;
	int status = 0;

	printk(KERN_INFO "sg5_pm_ssh_resume\n");

	// TODO: move to set state method
	ec = surfacegen5_ec_acquire_init();
	if (ec) {
		ec->state = SG5_EC_INITIALIZED;

		status = surfacegen5_ssh_ec_resume(ec);
		if (status) {
			printk(KERN_ERR "sg5_pm_ssh_resume: failed to enable events: %d\n", status);
		}

		surfacegen5_ec_release(ec);
	}

	return status;
}

static SIMPLE_DEV_PM_OPS(surfacegen5_ssh_pm_ops, surfacegen5_ssh_suspend, surfacegen5_ssh_resume);


static const struct serdev_device_ops surfacegen5_ssh_device_ops = {
	.receive_buf  = surfacegen5_ssh_receive_buf,
	.write_wakeup = serdev_device_write_wakeup,
};

static int surfacegen5_acpi_notify_ssh_probe(struct serdev_device *serdev)
{
	struct surfacegen5_ec *ec;
	unsigned long flags;
	struct workqueue_struct *event_queue_ack;
	struct workqueue_struct *event_queue_evt;
	u8 *write_buf;
	u8 *read_buf;
	u8 *eval_buf;
	acpi_handle *ssh = ACPI_HANDLE(&serdev->dev);
	acpi_status status;

	dev_info(&serdev->dev, "surfacegen5_acpi_notify_ssh_probe\n");

	status = surfacegen5_ssh_check_dma(serdev);
	if (status) {
		return status;
	}

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

	write_buf = kzalloc(SG5_WRITE_BUF_LEN, GFP_KERNEL);
	if (!write_buf) {
		status = -ENOMEM;
		goto err_probe_alloc_write;
	}

	read_buf = kzalloc(SG5_READ_BUF_LEN, GFP_KERNEL);
	if (!read_buf) {
		status = -ENOMEM;
		goto err_probe_alloc_read;
	}

	eval_buf = kzalloc(SG5_EVAL_BUF_LEN, GFP_KERNEL);
	if (!eval_buf) {
		status = -ENOMEM;
		goto err_probe_alloc_eval;
	}

	event_queue_ack = create_singlethread_workqueue("sg5_ackq");
	if (!event_queue_ack) {
		status = -ENOMEM;
		goto err_probe_alloc_queue_ack;
	}

	event_queue_evt = create_workqueue("sg5_evtq");
	if (!event_queue_evt) {
		status = -ENOMEM;
		goto err_probe_alloc_queue_evt;
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

	// initialize receiver
	spin_lock_irqsave(&ec->receiver.lock, flags);
	init_completion(&ec->receiver.signal);
	kfifo_init(&ec->receiver.fifo, read_buf, SG5_READ_BUF_LEN);
	ec->receiver.eval_buf.ptr = eval_buf;
	ec->receiver.eval_buf.cap = SG5_EVAL_BUF_LEN;
	ec->receiver.eval_buf.len = 0;
	spin_unlock_irqrestore(&ec->receiver.lock, flags);

	// initialize event handling
	// TODO: do we need the locks here?
	spin_lock_irqsave(&ec->events.lock, flags);
	ec->events.queue_ack = event_queue_ack;
	ec->events.queue_evt = event_queue_evt;
	spin_unlock_irqrestore(&ec->events.lock, flags);

	ec->state = SG5_EC_INITIALIZED;

	serdev_device_set_drvdata(serdev, ec);

	status = surfacegen5_ssh_ec_resume(ec);
	if (status) {
		// TODO
	}
	surfacegen5_ec_release(ec);

	acpi_walk_dep_device_list(ssh);

	return 0;

err_probe_busy:
	destroy_workqueue(event_queue_evt);
err_probe_alloc_queue_evt:
	destroy_workqueue(event_queue_ack);
err_probe_alloc_queue_ack:
	kfree(eval_buf);
err_probe_alloc_eval:
	kfree(read_buf);
err_probe_alloc_read:
	kfree(write_buf);
err_probe_alloc_write:
	serdev_device_close(serdev);
	return status;
}

static void surfacegen5_acpi_notify_ssh_remove(struct serdev_device *serdev)
{
	struct surfacegen5_ec *ec;
	unsigned long flags;
	int status;

	ec = surfacegen5_ec_acquire_init();
	if (!ec) {
		return;
	}

	// suspend EC and disable events
	status = surfacegen5_ssh_ec_suspend(ec);
	if (status) {
		dev_err(&serdev->dev, "failed to suspend EC: %d\n", status);
	}

	// make sure all events (received up to now) have been properly handled
	flush_workqueue(ec->events.queue_ack);
	flush_workqueue(ec->events.queue_evt);

	// remove event handlers
	spin_lock_irqsave(&ec->events.lock, flags);
	memset(ec->events.handler, 0,
	       sizeof(struct surfacegen5_ec_event_handler)
	        * SG5_NUM_EVENT_TYPES);
	spin_unlock_irqrestore(&ec->events.lock, flags);

	// set device to deinitialized state and close
	ec->state  = SG5_EC_UNINITIALIZED;
	ec->serdev = NULL;

	// ensure state and serdev get set before continuing
	smp_mb();

	serdev_device_close(serdev);

	/*
         * Only at this point, no new events can be received. Destroying the
         * workqueue here flushes all remaining events, but does not ensure that
	 * the proper handlers get called, i.e. here we just ignore those events.
	 */
	destroy_workqueue(ec->events.queue_ack);
	destroy_workqueue(ec->events.queue_evt);

	// free writer
	kfree(ec->writer.data);
	ec->writer.data = NULL;
	ec->writer.ptr  = NULL;

	// free receiver
	spin_lock_irqsave(&ec->receiver.lock, flags);
	ec->receiver.state = SG5_RCV_DISCARD;
	kfifo_free(&ec->receiver.fifo);

	kfree(ec->receiver.eval_buf.ptr);
	ec->receiver.eval_buf.ptr = NULL;
	ec->receiver.eval_buf.cap = 0;
	ec->receiver.eval_buf.len = 0;
	spin_unlock_irqrestore(&ec->receiver.lock, flags);

	serdev_device_set_drvdata(serdev, NULL);
	surfacegen5_ec_release(ec);
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
		.pm = &surfacegen5_ssh_pm_ops,
	},
};

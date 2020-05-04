// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface Serial Hub (SSH) driver for communication with the Surface/System
 * Aggregator Module.
 */

#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/completion.h>
#include <linux/crc-ccitt.h>
#include <linux/dmaengine.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pm.h>
#include <linux/refcount.h>
#include <linux/serdev.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include "surface_sam_ssh.h"


#define SSH_RQST_TAG_FULL			"surface_sam_ssh_rqst: "
#define SSH_RQST_TAG				"rqst: "
#define SSH_EVENT_TAG				"event: "

#define SSH_SUPPORTED_FLOW_CONTROL_MASK		(~((u8) ACPI_UART_FLOW_CONTROL_HW))

#define SSH_BYTELEN_SYNC			2	// [0xAA, 0x55]
#define SSH_BYTELEN_TERM			2	// [0xFF, 0xFF]
#define SSH_BYTELEN_CRC				2
#define SSH_BYTELEN_CTRL			4	// command-header, ACK, or RETRY
#define SSH_BYTELEN_CMDFRAME			8	// without payload

// TODO: this doesn't hold any more
#define SSH_MAX_WRITE (				\
	  SSH_BYTELEN_SYNC			\
	+ SSH_BYTELEN_CTRL			\
	+ SSH_BYTELEN_CRC			\
	+ SSH_BYTELEN_CMDFRAME			\
	+ SURFACE_SAM_SSH_MAX_RQST_PAYLOAD	\
	+ SSH_BYTELEN_CRC			\
)

#define SSH_TX_TIMEOUT			MAX_SCHEDULE_TIMEOUT
#define SSH_RX_TIMEOUT			msecs_to_jiffies(1000)
#define SSH_NUM_RETRY			3

#define SSH_READ_BUF_LEN		4096		// must be power of 2
#define SSH_EVAL_BUF_LEN		SSH_MAX_WRITE	// also works for reading


#define SSH_MAX_PACKETS_PENDING			1


/* -- Data structures for SAM-over-SSH communication. ----------------------- */

/**
 * enum ssh_frame_type - Frame types for SSH frames.
 * @SSH_FRAME_TYPE_DATA_SEQ: Indicates a data frame, followed by a payload with
 *                      the length specified in the ssh_frame.len field. This
 *                      frame is sequenced, meaning that an ACK is required.
 * @SSH_FRAME_TYPE_DATA_NSQ: Same as SSH_FRAME_TYPE_DATA_SEQ, but unsequenced,
 *                      meaning that the message does not have to be ACKed.
 * @SSH_FRAME_TYPE_ACK: Indicates an ACK message.
 * @SSH_FRAME_TYPE_NAK: Indicates an error response for previously sent
 *                      frame. In general, this means that the frame and/or
 *                      payload is malformed, e.g. a CRC is wrong. For command-
 *                      type payloads, this can also mean that the command is
 *                      invalid.
 */
enum ssh_frame_type {
	SSH_FRAME_TYPE_DATA_SEQ = 0x80,
	SSH_FRAME_TYPE_DATA_NSQ = 0x00,
	SSH_FRAME_TYPE_ACK	= 0x40,
	SSH_FRAME_TYPE_NAK	= 0x04,
};

/**
 * struct ssh_frame - SSH communication frame.
 * @type: The type of the frame. See &enum ssh_frame_type.
 * @len:  The length of the frame payload directly following the CRC for this
 *        frame. Does not include the final CRC for that payload.
 * @seq:  The sequence number for this message/exchange.
 */
struct ssh_frame {
	u8 type;
	__le16 len;
	u8 seq;
} __packed;

static_assert(sizeof(struct ssh_frame) == 4);

/**
 * enum ssh_payload_type - Type indicator for the SSH payload.
 * @SSH_PLD_TYPE_CMD: The payload is a command structure with optional command
 *                    payload.
 */
enum ssh_payload_type {
	SSH_PLD_TYPE_CMD = 0x80,
};

/**
 * struct ssh_command - Payload of a command-type frame.
 * @type:    The type of the payload. See &enum ssh_payload_type. Should be
 *           SSH_PLD_TYPE_CMD for this struct.
 * @tc:      Command target category.
 * @pri_out: Output priority. Should be zero if this an incoming (EC to host)
 *           message.
 * @pri_in:  Input priority. Should be zero if this is an outgoing (hos to EC)
 *           message.
 * @iid:     Instance ID.
 * @rqid:    Request ID. Used to match requests with responses and differentiate
 *           between responses and events.
 * @cid:     Command ID.
 */
struct ssh_command {
	u8 type;
	u8 tc;
	u8 pri_out;
	u8 pri_in;
	u8 iid;
	__le16 rqid;
	u8 cid;
} __packed;

static_assert(sizeof(struct ssh_command) == 8);

/**
 * Syncrhonization (SYN) bytes.
 */
#define SSH_MSG_SYN		((u16)0x55aa)

/**
 * Base-length of a SSH message. This is the minimum number of bytes required
 * to form a message. The actual message length is SSH_MSG_LEN_BASE plus the
 * length of the frame payload.
 */
#define SSH_MSG_LEN_BASE	(sizeof(struct ssh_frame) + 3 * sizeof(u16))

/**
 * Length of a control message.
 */
#define SSH_MSG_LEN_CTRL	SSH_MSG_LEN_BASE


/* -- TODO ------------------------------------------------------------------ */

enum ssh_ec_state {
	SSH_EC_UNINITIALIZED,
	SSH_EC_INITIALIZED,
	SSH_EC_SUSPENDED,
};

struct ssh_counters {
	u8  seq;		// control sequence id
	u16 rqid;		// id for request/response matching
};

enum ssh_receiver_state {
	SSH_RCV_DISCARD,
	SSH_RCV_CONTROL,
	SSH_RCV_COMMAND,
};

struct ssh_receiver {
	spinlock_t lock;
	enum ssh_receiver_state state;
	struct completion signal;
	struct kfifo fifo;
	struct {
		bool pld;
		u8 seq;
		u16 rqid;
	} expect;
	struct {
		u16 cap;
		u16 len;
		u8 *ptr;
	} eval_buf;
};

struct ssh_events {
	struct workqueue_struct *queue_ack;
	struct workqueue_struct *queue_evt;
	struct srcu_notifier_head notifier[SURFACE_SAM_SSH_MAX_EVENT_ID];
	int notifier_count[SURFACE_SAM_SSH_MAX_EVENT_ID];
};

struct sam_ssh_ec {
	struct mutex lock;
	enum ssh_ec_state state;
	struct serdev_device *serdev;
	struct ssh_counters counter;
	struct ssh_receiver receiver;
	struct ssh_events events;
	int irq;
	bool irq_wakeup_enabled;
};

struct ssh_fifo_packet {
	u8 type;	// packet type (ACK/RETRY/CMD)
	u8 seq;
	u8 len;
};

struct ssh_event_work {
	refcount_t refcount;
	struct sam_ssh_ec *ec;
	struct work_struct work_ack;
	struct work_struct work_evt;
	struct surface_sam_ssh_event event;
	u8 seq;
};


static struct sam_ssh_ec ssh_ec = {
	.lock   = __MUTEX_INITIALIZER(ssh_ec.lock),
	.state  = SSH_EC_UNINITIALIZED,
	.serdev = NULL,
	.counter = {
		.seq  = 0,
		.rqid = 0,
	},
	.receiver = {
		.lock = __SPIN_LOCK_UNLOCKED(),
		.state = SSH_RCV_DISCARD,
		.expect = {},
	},
	.events = {
		.notifier_count = { 0 },
	},
	.irq = -1,
};


/* -- Common/utility functions. --------------------------------------------- */

#define ssh_dbg(ec, fmt, ...)  dev_dbg(&ec->serdev->dev, fmt, ##__VA_ARGS__)
#define ssh_warn(ec, fmt, ...) dev_warn(&ec->serdev->dev, fmt, ##__VA_ARGS__)
#define ssh_err(ec, fmt, ...)  dev_err(&ec->serdev->dev, fmt, ##__VA_ARGS__)

static inline u16 ssh_crc(const u8 *buf, size_t len)
{
	return crc_ccitt_false(0xffff, buf, len);
}

static inline u16 ssh_rqid_next(u16 rqid)
{
	return rqid > 0 ? rqid + 1 : rqid + SURFACE_SAM_SSH_MAX_EVENT_ID + 1;
}

static inline u16 ssh_event_to_rqid(u16 event)
{
	return event + 1;
}

static inline u16 ssh_rqid_to_event(u16 rqid)
{
	return rqid - 1;
}

static inline bool ssh_rqid_is_event(u16 rqid)
{
	return ssh_rqid_to_event(rqid) < SURFACE_SAM_SSH_MAX_EVENT_ID;
}

static inline int ssh_tc_to_event(u8 tc)
{
	/*
	 * TC=0x08 represents the input subsystem on Surface Laptop 1 and 2.
	 * This is mapped on Windows to RQID=0x0001. As input events seem to be
	 * somewhat special with regards to enabling/disabling (they seem to be
	 * enabled by default with a fixed RQID), let's do the same here.
	 */
	if (tc == 0x08)
		return ssh_rqid_to_event(0x0001);

	/* Default path: Set RQID = TC. */
	return ssh_rqid_to_event(tc);
}

static inline u32 ssh_message_length(u16 payload_size)
{
	return SSH_MSG_LEN_BASE + payload_size;
}


/* -- Builder functions for SAM-over-SSH messages. -------------------------- */

struct msgbuf {
	u8 *buffer;
	u8 *end;
	u8 *ptr;
};

static inline void msgb_init(struct msgbuf *msgb, u8 *buffer, size_t cap)
{
	msgb->buffer = buffer;
	msgb->end = buffer + cap;
	msgb->ptr = buffer;
}

static inline int msgb_alloc(struct msgbuf *msgb, size_t cap, gfp_t flags)
{
	u8 *buf;

	buf = kzalloc(cap, flags);
	if (!buf)
		return -ENOMEM;

	msgb_init(msgb, buf, cap);
	return 0;
}

static inline void msgb_free(struct msgbuf *msgb)
{
	kfree(msgb->buffer);
	msgb->buffer = NULL;
	msgb->end = NULL;
	msgb->ptr = NULL;
}

static inline void msgb_reset(struct msgbuf *msgb)
{
	msgb->ptr = msgb->buffer;
}

static inline size_t msgb_bytes_used(const struct msgbuf *msgb)
{
	return msgb->ptr - msgb->buffer;
}

static inline void msgb_push_u16(struct msgbuf *msgb, u16 value)
{
	BUG_ON(msgb->ptr + sizeof(u16) > msgb->end);

	put_unaligned_le16(value, msgb->ptr);
	msgb->ptr += sizeof(u16);
}

static inline void msgb_push_syn(struct msgbuf *msgb)
{
	msgb_push_u16(msgb, SSH_MSG_SYN);
}

static inline void msgb_push_buf(struct msgbuf *msgb, const u8 *buf, size_t len)
{
	msgb->ptr = memcpy(msgb->ptr, buf, len) + len;
}

static inline void msgb_push_crc(struct msgbuf *msgb, const u8 *buf, size_t len)
{
	msgb_push_u16(msgb, ssh_crc(buf, len));
}

static inline void msgb_push_frame(struct msgbuf *msgb, u8 ty, u16 len, u8 seq)
{
	struct ssh_frame *frame = (struct ssh_frame *)msgb->ptr;
	const u8 *const begin = msgb->ptr;

	BUG_ON(msgb->ptr + sizeof(*frame) > msgb->end);

	frame->type = ty;
	put_unaligned_le16(len, &frame->len);
	frame->seq  = seq;

	msgb->ptr += sizeof(*frame);
	msgb_push_crc(msgb, begin, msgb->ptr - begin);
}

static inline void msgb_push_ack(struct msgbuf *msgb, u8 seq)
{
	// SYN
	msgb_push_syn(msgb);

	// ACK-type frame + CRC
	msgb_push_frame(msgb, SSH_FRAME_TYPE_ACK, 0x00, seq);

	// payload CRC (ACK-type frames do not have a payload)
	msgb_push_crc(msgb, msgb->ptr, 0);
}

static inline void msgb_push_cmd(struct msgbuf *msgb, u8 seq,
				 const struct surface_sam_ssh_rqst *rqst,
				 u16 rqid)
{
	struct ssh_command *cmd;
	const u8 *cmd_begin;
	const u8 type = SSH_FRAME_TYPE_DATA_SEQ;

	// SYN
	msgb_push_syn(msgb);

	// command frame + crc
	msgb_push_frame(msgb, type, sizeof(*cmd) + rqst->cdl, seq);

	// frame payload: command struct + payload
	BUG_ON(msgb->ptr + sizeof(*cmd) > msgb->end);
	cmd_begin = msgb->ptr;
	cmd = (struct ssh_command *)msgb->ptr;

	cmd->type    = SSH_PLD_TYPE_CMD;
	cmd->tc      = rqst->tc;
	cmd->pri_out = rqst->pri;
	cmd->pri_in  = 0x00;
	cmd->iid     = rqst->iid;
	put_unaligned_le16(rqid, &cmd->rqid);
	cmd->cid     = rqst->cid;

	msgb->ptr += sizeof(*cmd);

	// command payload
	msgb_push_buf(msgb, rqst->pld, rqst->cdl);

	// crc for command struct + payload
	msgb_push_crc(msgb, cmd_begin, msgb->ptr - cmd_begin);
}


/* -- Parser functions for SAM-over-SSH messages. --------------------------- */

struct bufspan {
	u8    *ptr;
	size_t len;
};

static inline bool sshp_validate_crc(const struct bufspan *data, const u8 *crc)
{
	u16 actual = ssh_crc(data->ptr, data->len);
	u16 expected = get_unaligned_le16(crc);

	return actual == expected;
}

static bool sshp_find_syn(const struct bufspan *src, struct bufspan *rem)
{
	size_t i;

	for (i = 0; i < src->len - 1; i++) {
		if (likely(get_unaligned_le16(src->ptr + i) == SSH_MSG_SYN)) {
			rem->ptr = src->ptr + i;
			rem->len = src->len - i;
			return true;
		}
	}

	if (unlikely(src->ptr[src->len - 1] == (SSH_MSG_SYN & 0xff))) {
		rem->ptr = src->ptr + src->len - 1;
		rem->len = 1;
		return false;
	} else {
		rem->ptr = src->ptr + src->len;
		rem->len = 0;
		return false;
	}
}

static size_t sshp_parse_frame(const struct sam_ssh_ec *ec,
			       const struct bufspan *source,
			       struct ssh_frame **frame,
			       struct bufspan *payload)
{
	struct bufspan aligned;
	struct bufspan sf;
	struct bufspan sp;
	bool syn_found;

	// initialize output
	*frame = NULL;
	payload->ptr = NULL;
	payload->len = 0;

	// find SYN
	syn_found = sshp_find_syn(source, &aligned);

	if (unlikely(aligned.ptr - source->ptr) > 0)
		ssh_warn(ec, "rx: parser: invalid start of frame, skipping \n");

	if (unlikely(!syn_found))
		return aligned.ptr - source->ptr;

	// check for minumum packet length
	if (unlikely(aligned.len < ssh_message_length(0))) {
		ssh_dbg(ec, "rx: parser: not enough data for frame\n");
		return aligned.ptr - source->ptr;
	}

	// pin down frame
	sf.ptr = aligned.ptr + sizeof(u16);
	sf.len = sizeof(struct ssh_frame);

	// validate frame CRC
	if (unlikely(!sshp_validate_crc(&sf, sf.ptr + sf.len))) {
		ssh_warn(ec, "rx: parser: invalid frame CRC\n");

		// skip enough bytes to try and find next SYN
		return aligned.ptr - source->ptr + sizeof(u16);
	}

	// pin down payload
	sp.ptr = sf.ptr + sf.len + sizeof(u16);
	sp.len = get_unaligned_le16(&((struct ssh_frame *)sf.ptr)->len);

	// check for frame + payload length
	if (aligned.len < ssh_message_length(sp.len)) {
		ssh_dbg(ec, "rx: parser: not enough data for payload\n");
		return aligned.ptr - source->ptr;
	}

	// validate payload crc
	if (unlikely(!sshp_validate_crc(&sp, sp.ptr + sp.len))) {
		ssh_warn(ec, "rx: parser: invalid payload CRC\n");

		// skip enough bytes to try and find next SYN
		return aligned.ptr - source->ptr + sizeof(u16);
	}

	*frame = (struct ssh_frame *)sf.ptr;
	*payload = sp;

	ssh_dbg(ec, "rx: parser: valid frame found (type: 0x%02x, len: %u)\n",
		(*frame)->type, (*frame)->len);

	return aligned.ptr - source->ptr;
}

static void sshp_parse_command(const struct sam_ssh_ec *ec,
			       const struct bufspan *source,
			       struct ssh_command **command,
			       struct bufspan *command_data)
{
	// check for minimum length
	if (unlikely(source->len < sizeof(struct ssh_command))) {
		*command = NULL;
		command_data->ptr = NULL;
		command_data->len = 0;

		ssh_err(ec, "rx: parser: command payload is too short\n");
		return;
	}

	*command = (struct ssh_command *)source->ptr;
	command_data->ptr = source->ptr + sizeof(struct ssh_command);
	command_data->len = source->len - sizeof(struct ssh_command);

	ssh_dbg(ec, "rx: parser: valid command found (tc: 0x%02x,"
		" cid: 0x%02x)\n", (*command)->tc, (*command)->cid);
}


/* -- Packet transmission system (ptx). ------------------------------------- */
/*
 * To simplify reasoning about the code below, we define a state-machine. As
 * there are a lot of potential states, we do not explicitly define states,
 * but describe them by a combination of flags. To apply a transition,
 * triggered by an action, the flags required by it must be set/cleared. If
 * these requirements are not fulfilled, the transition is not applied and the
 * state does not change. Applying a transition changes the state by changing
 * the specified flags.
 *
 * >> Actions <<
 *
 * - submit
 * - transmission start (process next item in queue)
 * - transmission finished (guaranteed to never be parallel to transmission
 *   start)
 * - ACK received
 * - NAK received (this is equivalent to issuing re-submit for all pending
 *   packets)
 * - timeout (this is equivalent to re-issuing a submit or canceling)
 * - cancel (non-pending and pending)
 *
 * >> States <<
 *
 * - queued (corresponds to being in submission queue)
 * - pending (corresponds to being in set of pending packets)
 * - transmitting
 * - transmitted
 * - acked
 * - completed
 * - canceling
 *
 * Note that "queued" and pending always must be set/cleared in conjunction
 * with addition of/removing the packet from the corresponding data structure.
 *
 * If "completed" has been set, no state changes are allowed to happen. This
 * is done, so that the process which has successfully managed to set the
 * "completed" flag is the sole owner of the packet and can then safely remove
 * it from all data structures. To ensure that no use-after-free errors
 * happen, no other process is allowed to access references without holding
 * the packet lock once the "completed" flag has been set, and transition
 * rules must ensure that the packet cannot be set to "completed" when it can
 * be accessed in an exclusive context (e.g. "transmitting" is set). The
 * process setting the "completed" flag is responsible for ensuring that those
 * references are no longer available to other processes.
 *
 * When a packet reference in the transfer system is taken outside the scope
 * of packet and/or queue locks (queue/pending), the packet must first be
 * (successfully) transitioned to an exclusive state (i.e. "completed" or
 * "transmitting"). The reference held by the packet timer is an exception to
 * this, but this reference must not be passed outside of the timer callback.
 *
 * >> Transitions <<
 *
 * Note: `|#` as suffix means alternative transition. The coice of transition
 * depends on the flags currently set on the packet and the flags required by
 * the transition.
 *
 * - submit
 *   required: -queued, -completed, -canceling
 *   changed: +queued
 *
 * - pop_from_queue
 *   required: +queued, -transmitting, -completed, -canceling
 *   changed: -queued, +transmitting
 *
 *   Note: This is only called when no packet is being transmitted. Thus
 *   checking for "transmitting" is redundant.
 *
 * - add_to_pending
 *   required: -pending, -completed, -canceling, +IS_SEQ
 *   changed: +pending
 *
 *   Note: Logically coupled with pop_from_queue to form "transmission start",
 *   but separated into two transitions so that we don't have to hold both
 *   queue and pending data structure locks at the same time. As this is
 *   coupled with pop_from_queue, which adds the "transmitting" flag, a check
 *   for completed is redundant as "completed" and "transmitting" are mutually
 *   exclusive.
 *
 * - transmit_done|1
 *   required: +transmitting, -completed, -canceling, -acked, +IS_SEQ
 *   changed: -transmitting, +transmitted
 *
 * - transmit_done|2
 *   required: +transmitting, -completed, -canceling, +acked, +IS_SEQ
 *   changed: -transmitting, +transmitted, +completed
 *
 *   Note: Check "transmitted" before applyign flag changes to determine if the
 *   ACK came before the first full transmission. In that case, complete with
 *   error.
 *
 * - transmit_done|3
 *   required: +transmitting, -completed, -canceling, -IS_SEQ
 *   changed: -transmitting, +transmitted, +completed
 *
 *   Note: Successful completion (normal end-point for unsequenced packets).
 *
 * - transmit_done|4
 *   required: +transmitting, -completed, +canceling
 *   changed: -transmitting, +transmitted, +completed
 *
 *   Note: Check "acked" and "IS_SEQ" to determine between success/canceled
 *   result.
 *
 * - transmit_done|5 (in case of transmit error)
 *   required: +transmitting, -completed
 *   changed: -transmitting, +completed
 *
 *   Note: Completion caused by transmit error.
 *
 * - ack|1
 *   required: +pending, -transmitting, -completed
 *   changed: +acked, +completed, -pending
 *
 *   Note: Successful completion (normal end-point for sequenced packets). It
 *   theoretically is possible that an ACK for this packet has been received
 *   before the transmit completed. This indicates an error in communication
 *   and the packet should be completed with an error (check transmitted).
 *
 * - ack|2
 *   required: +pending, +transmitting, -completed
 *   changed: +acked, -pending
 *
 * - cancel_nonpending
 *   required: -completed, -canceling, -transmitting, -pending
 *   changed: +canceling, +completed
 *
 * - cancel_pending|1
 *   required: -completed, -canceling, -transmitting
 *   changed: +canceling, +completed
 *
 * - cancel_pending|2
 *   required: -completed, -canceling, +transmitting
 *   changed: +canceling
 *
 * To avoid deadlocks, data structure locks (queue/pending) must always be
 * acquired before the packet lock and released after.
 */

/**
 * Maximum number transmission attempts per sequenced packet in case of
 * time-outs.
 */
#define SSH_PTX_MAX_PKT_TIMEOUTS	3

/**
 * Timeout in jiffies for ACKs. If we have not received an ACK in this
 * time-frame after starting transmission, the packet will be re-submitted.
 */
#define SSH_PTX_PKT_TIMEOUT		msecs_to_jiffies(1000)

enum ssh_packet_priority {
	SSH_PACKET_PRIORITY_MIN = 0,
	SSH_PACKET_PRIORITY_DATA = SSH_PACKET_PRIORITY_MIN,
	SSH_PACKET_PRIORITY_DATA_RESUB,
	SSH_PACKET_PRIORITY_NAK,
	SSH_PACKET_PRIORITY_ACK,
};

enum ssh_packet_type_flags {
	SSH_PACKET_TY_SEQUENCED_BIT,
	SSH_PACKET_TY_BLOCKING_BIT,

	SSH_PACKET_TY_SEQUENCED = BIT(SSH_PACKET_TY_SEQUENCED_BIT),
	SSH_PACKET_TY_BLOCKING  = BIT(SSH_PACKET_TY_BLOCKING_BIT),
};

enum ssh_packet_state_flags {
	SSH_PACKET_SF_QUEUED_BIT,
	SSH_PACKET_SF_PENDING_BIT,
	SSH_PACKET_SF_TRANSMITTING_BIT,
	SSH_PACKET_SF_TRANSMITTED_BIT,
	SSH_PACKET_SF_ACKED_BIT,
	SSH_PACKET_SF_COMPLETED_BIT,
	SSH_PACKET_SF_CANCELING_BIT,
	SSH_PACKET_SF_CANCELED_BIT,
	SSH_PACKET_SF_TIMEDOUT_BIT,

	SSH_PACKET_SF_QUEUED       = BIT(SSH_PACKET_SF_QUEUED_BIT),
	SSH_PACKET_SF_PENDING      = BIT(SSH_PACKET_SF_PENDING_BIT),
	SSH_PACKET_SF_TRANSMITTING = BIT(SSH_PACKET_SF_TRANSMITTING_BIT),
	SSH_PACKET_SF_TRANSMITTED  = BIT(SSH_PACKET_SF_TRANSMITTED_BIT),
	SSH_PACKET_SF_ACKED        = BIT(SSH_PACKET_SF_ACKED_BIT),
	SSH_PACKET_SF_COMPLETED    = BIT(SSH_PACKET_SF_COMPLETED_BIT),
	SSH_PACKET_SF_CANCELING    = BIT(SSH_PACKET_SF_CANCELING_BIT),
	SSH_PACKET_SF_CANCELED     = BIT(SSH_PACKET_SF_CANCELED_BIT),
	SSH_PACKET_SF_TIMEDOUT     = BIT(SSH_PACKET_SF_TIMEDOUT_BIT),
};

struct ssh_ptx;

struct ssh_packet {
	struct ssh_ptx *ptx;

	spinlock_t lock;
	unsigned int type;
	unsigned int state;
	struct list_head queue_node;
	struct list_head pending_node;

	enum ssh_packet_priority priority;
	u8 sequence_id;
	int status;

	struct {
		unsigned int count;
		struct timer_list timer;
		struct work_struct work;
	} timeout;

	struct {
		unsigned char *ptr;
		size_t length;
	} buffer;
};

struct ssh_ptx {
	struct serdev_device *serdev;

	struct {
		spinlock_t lock;
		struct list_head head;
	} queue;

	struct {
		spinlock_t lock;
		struct list_head head;
		atomic_t count;
	} pending;

	struct {
		struct work_struct work;
		struct ssh_packet *packet;
		size_t offset;
	} tx;
};

#define ptx_dbg(ptx, fmt, ...)  dev_dbg(&ptx->serdev->dev, fmt, ##__VA_ARGS__)
#define ptx_warn(ptx, fmt, ...) dev_warn(&ptx->serdev->dev, fmt, ##__VA_ARGS__)
#define ptx_err(ptx, fmt, ...)  dev_err(&ptx->serdev->dev, fmt, ##__VA_ARGS__)

static inline
int ssh_ptx_queue_insert_before(struct ssh_packet *p, struct list_head *h)
{
	spin_lock(&p->lock);

	// avoid further transitions when cancelling
	if (p->state & SSH_PACKET_SF_CANCELING) {
		spin_unlock(&p->lock);
		return -EINVAL;
	}

	// if this packet has already been completed, do not add it
	if (p->state & SSH_PACKET_SF_COMPLETED) {
		spin_unlock(&p->lock);
		return -EINVAL;
	}

	// if this packet has already been queued, do not add it
	if (p->state & SSH_PACKET_SF_QUEUED) {
		spin_unlock(&p->lock);
		return -EALREADY;
	}

	p->state |= SSH_PACKET_SF_QUEUED;
	list_add_tail(&p->queue_node, h);

	spin_unlock(&p->lock);
	return 0;
}

static int ssh_ptx_queue_push(struct ssh_packet *packet)
{
	enum ssh_packet_priority priority = smp_load_acquire(&packet->priority);
	struct ssh_ptx *ptx = packet->ptx;
	struct list_head *head;
	struct ssh_packet *p;
	int status;

	spin_lock(&ptx->queue.lock);

	// fast path: minimum priority packets are always added at the end
	if (priority == SSH_PACKET_PRIORITY_MIN) {
		status = ssh_ptx_queue_insert_before(packet, &ptx->queue.head);

	// regular path
	} else {
		// find first node with lower priority
		list_for_each(head, &ptx->queue.head) {
			p = list_entry(head, struct ssh_packet, queue_node);

			if (priority > smp_load_acquire(&p->priority))
				break;
		}

		// insert before
		status = ssh_ptx_queue_insert_before(packet, &ptx->queue.head);
	}

	spin_unlock(&ptx->queue.lock);
	return status;
}

static inline void ssh_ptx_queue_remove(struct ssh_packet *packet)
{
	struct ssh_ptx *ptx = packet->ptx;

	spin_lock(&ptx->queue.lock);
	spin_lock(&packet->lock);

	if (packet->state & SSH_PACKET_SF_QUEUED) {
		packet->state &= ~SSH_PACKET_SF_QUEUED;
		list_del(&packet->queue_node);
	}

	spin_unlock(&packet->lock);
	spin_unlock(&ptx->queue.lock);
}

static inline bool ssh_ptx_can_process(struct ssh_packet *packet)
{
	struct ssh_ptx *ptx = packet->ptx;

	// we can alwas process non-blocking packets
	if (!(packet->type & SSH_PACKET_TY_BLOCKING))
		return true;

	// if we are already waiting for this packet, send it again
	if (packet->state & SSH_PACKET_SF_PENDING)
		return true;

	// otherwise: check if we have the capacity to send
	return atomic_read(&ptx->pending.count) < SSH_MAX_PACKETS_PENDING;
}

static struct ssh_packet *ssh_ptx_queue_pop(struct ssh_ptx *ptx)
{
	struct ssh_packet *packet = NULL;
	struct ssh_packet *p, *n;

	spin_lock(&ptx->queue.lock);
	list_for_each_entry_safe(p, n, &ptx->pending.head, pending_node) {
		spin_lock(&p->lock);

		/*
		 * Packets should be ordered non-blocking/to-be-resent first.
		 * If we cannot process this packet, assume that we can't
		 * process any following packet either and abort.
		 */
		if (!ssh_ptx_can_process(p)) {
			spin_unlock(&p->lock);
			break;
		}

		/*
		 * If we are cancelling this packet, ignore it. It's going to be
		 * removed from this queue shortly.
		 */
		if (p->state & SSH_PACKET_SF_CANCELING) {
			spin_unlock(&p->lock);
			continue;
		}

		/*
		 * If this packet has already been completed, ignore it. It's
		 * going to be removed from this queue shortly.
		 */
		if (p->state & SSH_PACKET_SF_COMPLETED) {
			spin_unlock(&p->lock);
			continue;
		}

		/*
		 * We are allowed to change the state now. Remove it from the
		 * queue and mark it as being transmitted. Note that we cannot
		 * add it to the set of pending packets yet, as queue locks must
		 * always be acquired before packet locks (otherwise we might
		 * run into a deadlock).
		 */

		list_del(&p->queue_node);
		p->state &= ~SSH_PACKET_SF_QUEUED;
		p->state |= SSH_PACKET_SF_TRANSMITTING;

		spin_unlock(&p->lock);

		packet = p;
		break;
	}
	spin_unlock(&ptx->queue.lock);

	return packet;
}

static void ssh_ptx_pending_push(struct ssh_packet *packet)
{
	struct ssh_ptx *ptx = packet->ptx;

	spin_lock(&ptx->pending.lock);
	spin_lock(&packet->lock);

	// if we are cancelling this packet, do not add it
	if (packet->state & SSH_PACKET_SF_CANCELING)
		goto out;

	// in case it is already pending (e.g. re-submission), do not add it
	if (packet->state & SSH_PACKET_SF_PENDING)
		goto out;

	atomic_inc(&ptx->pending.count);
	list_add_tail(&packet->pending_node, &ptx->pending.head);

out:
	spin_unlock(&packet->lock);
	spin_unlock(&ptx->pending.lock);
}

static struct ssh_packet *ssh_ptx_pending_pop(struct ssh_ptx *ptx, u8 seq_id)
{
	struct ssh_packet *packet = ERR_PTR(-ENOENT);
	struct ssh_packet *p, *n;

	spin_lock(&ptx->pending.lock);
	list_for_each_entry_safe(p, n, &ptx->pending.head, pending_node) {
		if (unlikely(p->sequence_id != seq_id))
			continue;

		spin_lock(&p->lock);

		/*
		 * In case we receive an ACK while handling a transmission error
		 * completion. The packet will be removed shortly.
		 */
		if (unlikely(p->state & SSH_PACKET_SF_COMPLETED)) {
			packet = ERR_PTR(-EPERM);
			spin_unlock(&p->lock);
			break;
		}

		p->state &= ~SSH_PACKET_SF_PENDING;
		p->state |= SSH_PACKET_SF_ACKED;

		atomic_dec(&ptx->pending.count);
		list_del(&p->pending_node);

		/*
		 * This packet may currently be transmitting (e.g. as it may
		 * have been re-submitted). In that case, we are not allowed to
		 * return it, only mark it as ACKed and remove it from pending.
		 */
		if (unlikely(p->state & SSH_PACKET_SF_TRANSMITTING)) {
			packet = ERR_PTR(-EPERM);
			spin_unlock(&p->lock);
			break;
		}

		p->state |= SSH_PACKET_SF_COMPLETED;
		packet = p;

		spin_unlock(&p->lock);
		break;
	}
	spin_unlock(&ptx->pending.lock);

	return packet;
}

static inline void ssh_ptx_pending_remove(struct ssh_packet *packet)
{
	struct ssh_ptx *ptx = packet->ptx;

	spin_lock(&ptx->pending.lock);
	spin_lock(&packet->lock);

	if (packet->state & SSH_PACKET_SF_PENDING) {
		packet->state &= ~SSH_PACKET_SF_PENDING;
		list_del(&packet->pending_node);
		atomic_dec(&ptx->pending.count);
	}

	spin_unlock(&packet->lock);
	spin_unlock(&ptx->pending.lock);
}

static inline void ssh_ptx_packet_complete(struct ssh_packet *p, int status)
{
	ptx_dbg(p->ptx, "ptx: completing packet %p\n", p);
	p->status = status;

	// TODO: call completion callback of packet
}

static void ssh_ptx_packet_remove_and_complete(struct ssh_packet *p, int status)
{
	// remove packet from all places that could have references
	del_timer_sync(&p->timeout.timer);
	cancel_work_sync(&p->timeout.work);
	ssh_ptx_queue_remove(p);
	ssh_ptx_pending_remove(p);

	// set status and call completion callback
	ssh_ptx_packet_complete(p, status);
}

static inline struct ssh_packet *ssh_ptx_transmit_next(struct ssh_ptx *ptx)
{
	struct ssh_packet *packet;

	packet = ssh_ptx_queue_pop(ptx);
	if (!packet)
		return packet;

	if (packet->type & SSH_PACKET_TY_SEQUENCED) {
		ptx_dbg(ptx, "transmitting sequenced packet %p\n", packet);

		ssh_ptx_pending_push(packet);
		mod_timer(&packet->timeout.timer,
			  jiffies + SSH_PTX_PKT_TIMEOUT);

	} else {
		ptx_dbg(ptx, "transmitting non-sequenced packet %p\n", packet);
	}

	return packet;
}

/*
 * Needs to be called with packet lock, unlocks and potentially completes
 * packet.
 */
static inline void ssh_ptx_transmit_done(struct ssh_packet *packet)
{
	struct ssh_ptx *ptx = packet->ptx;
	bool completed;
	int status = 0;

	if (packet->type & SSH_PACKET_TY_SEQUENCED) {
		if (unlikely(packet->state & SSH_PACKET_SF_ACKED)) {
			/*
			 * Packet has been ACKed before this transmission
			 * finished. In case we have not transmitted the packet
			 * before, this indicates a communication error. In both
			 * cases, the packet should be completed.
			 */
			completed = true;
			packet->state |= SSH_PACKET_SF_COMPLETED;

			if (!(packet->state & SSH_PACKET_SF_TRANSMITTED)) {
				ptx_err(ptx, "ptx: received ACK before packet"
					" had been fully transmitted\n");
				status = -EIO;
			}

		} else if (unlikely(packet->state & SSH_PACKET_SF_CANCELING)) {
			/*
			 * We would now wait for an ACK but have received a
			 * request to cancel this packet while we were
			 * transmitting it. Thus cancel the packet.
			 */
			completed = true;
			packet->state |= SSH_PACKET_SF_COMPLETED;
			packet->state |= SSH_PACKET_SF_CANCELED;

			// check if cancellation was caused by timeout
			if (packet->state & SSH_PACKET_SF_TIMEDOUT)
				status = -ETIMEDOUT;
			else
				status = -EINTR;

		} else {
			completed = false;	// need to wait for ACK
		}

	} else {
		// this is a non-sequenced packet, no need to wait for ACK
		completed = true;
		packet->state |= SSH_PACKET_SF_COMPLETED;
		status = 0;
	}

	packet->state &= ~SSH_PACKET_SF_TRANSMITTING;
	packet->state |= SSH_PACKET_SF_TRANSMITTED;

	spin_unlock(&packet->lock);

	ptx_dbg(ptx, "ptx: transmitted packet %p\n", packet);
	if (packet->state & SSH_PACKET_SF_CANCELED)
		ptx_dbg(ptx, "ptx: canceled packet %p\n", packet);

	if (completed)
		ssh_ptx_packet_remove_and_complete(packet, status);
}

/* Needs to be called with packet lock, unlocks and completes packet */
static inline void ssh_ptx_transmit_error(struct ssh_packet *packet, int status)
{
	packet->state &= ~SSH_PACKET_SF_TRANSMITTING;
	packet->state |= SSH_PACKET_SF_COMPLETED;

	spin_unlock(&packet->lock);

	ptx_err(packet->ptx, "ptx: transmission error: %d\n", status);
	ssh_ptx_packet_remove_and_complete(packet, status);
}

static void ssh_ptx_process_work(struct work_struct *work)
{
	struct ssh_ptx *ptx = container_of(work, struct ssh_ptx, tx.work);
	unsigned char *buf;
	size_t len;
	int i, status;

	for (i = 0; i < 25; i++) {
		// if we don't have a packet, get the next and add it to pending
		if (!ptx->tx.packet) {
			ptx->tx.packet = ssh_ptx_transmit_next(ptx);
			ptx->tx.offset = 0;

			// if no packet is available, we are done
			if (!ptx->tx.packet)
				return;
		}

		/*
		 * We need to hold the lock while sending to accurately detect
		 * ACKed-before-sent cases. Otherwise we could run into false
		 * positives.
		 */
		spin_lock(&ptx->tx.packet->lock);

		buf = ptx->tx.packet->buffer.ptr + ptx->tx.offset;
		len = ptx->tx.packet->buffer.length - ptx->tx.offset;
		status = serdev_device_write_buf(ptx->serdev, buf, len);

		if (status < 0) {
			// complete packet with error and unlock
			ssh_ptx_transmit_error(ptx->tx.packet, status);
			ptx->tx.packet = NULL;

		} else if (status == len) {
			// complete packet and/or mark as transmitted and unlock
			ssh_ptx_transmit_done(ptx->tx.packet);
			ptx->tx.packet = NULL;

		} else {	// need more buffer space
			ptx->tx.offset += status;
			spin_unlock(&ptx->tx.packet->lock);
			return;
		}
	}

	/*
	 * In the unlikely case that we don't run out of new packets to process
	 * or buffer space for sending any time soon, let's be a good work item
	 * and give others a chance. Break here and re-schedule ourselves.
	 */
	schedule_work(&ptx->tx.work);
}

static inline void ssh_ptx_process_queue(struct ssh_ptx *ptx, bool force)
{
	if (force || atomic_read(&ptx->pending.count) < SSH_MAX_PACKETS_PENDING)
		schedule_work(&ptx->tx.work);
}

static inline int ssh_ptx_resubmit(struct ssh_packet *packet)
{
	bool force_work;
	int status;

	status = ssh_ptx_queue_push(packet);
	if (status)
		return status;

	force_work = READ_ONCE(packet->state) & SSH_PACKET_SF_PENDING;
	force_work |= packet->type != SSH_PACKET_TY_BLOCKING;

	ssh_ptx_process_queue(packet->ptx, force_work);
	return 0;
}

static void ssh_ptx_timeout_wfn(struct work_struct *work)
{
	struct ssh_packet *packet;

	packet = container_of(work, struct ssh_packet, timeout.work);
	packet->timeout.count += 1;

	if (likely(packet->timeout.count <= SSH_PTX_MAX_PKT_TIMEOUTS)) {
		// update priority to
		smp_store_release(&packet->priority,
				  SSH_PACKET_PRIORITY_DATA_RESUB);

		ssh_ptx_resubmit(packet);
		return;
	}

	// we have reached the max number of timeouts: cancel this packet

	spin_lock(&packet->lock);

	if (packet->state & SSH_PACKET_SF_COMPLETED) {
		spin_unlock(&packet->lock);
		return;
	}

	if (packet->state & SSH_PACKET_SF_CANCELING) {
		spin_unlock(&packet->lock);
		return;
	}

	if (packet->state & SSH_PACKET_SF_TRANSMITTING) {
		packet->state |= SSH_PACKET_SF_TIMEDOUT;
		packet->state |= SSH_PACKET_SF_CANCELING;
		spin_unlock(&packet->lock);
		return;
	}

	/*
	 * We need to make sure that this work_struct is not pending again, as,
	 * if we want to complete this packet, we need to ensure that we are the
	 * only ones holding a reference to it. We can't guarantee that if there
	 * is still a work item queued which references this and we can't cancel
	 * that from here.
	 *
	 * Without external re-submission of the packet, this can only happen in
	 * one, very specific "the starts align just right and hell freezes over
	 * at the same time as you're getting struck by lightning while falling
	 * down a cliff" kind-of way: The receiver receives a NAK, re-submits
	 * the packet, which eventually gets transmitted and at the same re-arms
	 * the timeout timer, which triggers before we are done with this
	 * function and queus this work_struct _while_ we're already executing
	 * it. The timing for this is only possible if this work struct gets
	 * delayed unreasonably long (at least as long as the timeout), and on
	 * top of it the package needs to be either re-submitted, externally or
	 * via a NAK.
	 *
	 * As we have chosen not to sacrifice our favorite goat and the most
	 * expensive wine to Tyche/Fortuna and are strict believers in Murphy's
	 * Law, let's deal with this. So cancel the timer synchronously here
	 * (which we're _very_ likely not going to have to wait on) and in the
	 * unlikely case that it has already triggered another time and queued
	 * this work_struct again, let the second instance take care of it.
	 */
	del_timer_sync(&packet->timeout.timer);
	if (unlikely(work_pending(&packet->timeout.work))) {
		spin_unlock(&packet->lock);
		return;
	}

	packet->state |= SSH_PACKET_SF_TIMEDOUT;
	packet->state |= SSH_PACKET_SF_CANCELING;
	packet->state |= SSH_PACKET_SF_CANCELED;
	packet->state |= SSH_PACKET_SF_COMPLETED;

	spin_unlock(&packet->lock);

	// remove from rest of system
	ssh_ptx_queue_remove(packet);
	ssh_ptx_pending_remove(packet);

	ssh_ptx_packet_complete(packet, -ETIMEDOUT);

	// we may have freed up some capacity to send
	ssh_ptx_process_queue(packet->ptx, false);
}

static void ssh_ptx_timeout_tfn(struct timer_list *tl)
{
	struct ssh_packet *packet;

	packet = container_of(tl, struct ssh_packet, timeout.timer);
	schedule_work(&packet->timeout.work);
}

static inline int ssh_ptx_submit(struct ssh_ptx *ptx, struct ssh_packet *packet)
{
	int status;

	/*
	 * This function is currently not intended for re-submission. The ptx
	 * reference only gets set on the first submission. After the first
	 * submission, it has to be read-only.
	 */
	BUG_ON(packet->ptx != NULL);
	packet->ptx = ptx;

	status = ssh_ptx_queue_push(packet);
	if (status)
		return status;

	ssh_ptx_process_queue(ptx, packet->type != SSH_PACKET_TY_BLOCKING);
	return 0;
}

static void ssh_ptx_resubmit_pending(struct ssh_ptx *ptx)
{
	struct ssh_packet *p;
	struct list_head *head;

	spin_lock(&ptx->queue.lock);
	spin_lock(&ptx->pending.lock);

	// find first node with lower than data resubmission priority
	list_for_each(head, &ptx->queue.head) {
		p = list_entry(head, struct ssh_packet, queue_node);

		if (smp_load_acquire(&p->priority)
		    < SSH_PACKET_PRIORITY_DATA_RESUB)
			break;
	}

	// re-queue all pending packets
	list_for_each_entry(p, &ptx->pending.head, pending_node) {
		spin_lock(&p->lock);

		// avoid further transitions when cancelling
		if (p->state & SSH_PACKET_SF_CANCELING) {
			spin_unlock(&p->lock);
			continue;
		}

		// if this packet has already been completed, do not add it
		if (p->state & SSH_PACKET_SF_COMPLETED) {
			spin_unlock(&p->lock);
			continue;
		}

		// if this packet has already been queued, do not add it
		if (p->state & SSH_PACKET_SF_QUEUED) {
			spin_unlock(&p->lock);
			continue;
		}

		/*
		 * Note: All packets here are guaranteed to be pending
		 * (non-ACKed) data packets.
		 */

		smp_store_release(&p->priority, SSH_PACKET_PRIORITY_DATA_RESUB);
		list_add_tail(&p->queue_node, head);

		spin_unlock(&p->lock);
	}

	spin_lock(&ptx->pending.lock);
	spin_lock(&ptx->queue.lock);

	ssh_ptx_process_queue(ptx, true);
}

static void ssh_ptx_acknowledge(struct ssh_ptx *ptx, u8 seq)
{
	struct ssh_packet *packet;
	int status = 0;

	packet = ssh_ptx_pending_pop(ptx, seq);
	if (IS_ERR(packet)) {
		if (PTR_ERR(packet) == -ENOENT) {
			/*
			 * The packet has not been found in the set of pending
			 * packets.
			 */
			ptx_warn(ptx, "ptx: received ACK for non-pending"
				 " packet\n");
		} else {
			/*
			 * The packet is pending, but we are not allowed to take
			 * it. This could be because the packet is currently
			 * transmitting or a transmission error may have been
			 * encountered and is currently being handled. Others
			 * will take care of completion
			 */
		}

		return;
	}

	ptx_dbg(ptx, "ACK received for packet %p\n", packet);

	/*
	 * We might have received an ACK for this packet before we have even
	 * transmitted it. In this case, set an error.
	 *
	 * NB: No locking required here, we have already blocket all write
	 * access to the packet state by marking it as "completed" in
	 * ssh_ptx_pending_pop.
	 */
	if (unlikely(!(packet->state & SSH_PACKET_SF_TRANSMITTED))) {
		status = -EIO;
		ptx_err(ptx, "ptx: received ACK before packet had been fully"
			" transmitted\n");
	}

	ssh_ptx_packet_remove_and_complete(packet, status);

	// we've completed a pendig packet, there may be new capacity to send
	ssh_ptx_process_queue(ptx, false);
}

static bool ssh_ptx_cancel(struct ssh_packet *packet, bool pending)
{
	struct ssh_ptx *ptx = packet->ptx;

	spin_lock(&packet->lock);

	if (packet->state & SSH_PACKET_SF_COMPLETED) {
		spin_unlock(&packet->lock);
		return true;
	}

	if (packet->state & SSH_PACKET_SF_CANCELING) {
		spin_unlock(&packet->lock);
		return true;
	}

	if (pending) {
		/*
		 * If packet is currently transmitting, we cannot take
		 * ownership of it. Instead mark it as canceling and let the
		 * transmission function take care of it once it's done.
		 */
		if (packet->state & SSH_PACKET_SF_TRANSMITTING) {
			packet->state |= SSH_PACKET_SF_CANCELING;
			spin_unlock(&packet->lock);
			ptx_dbg(ptx, "ptx: canceling packet %p\n", packet);
			return true;
		}
	} else {
		if (packet->state & SSH_PACKET_SF_TRANSMITTING) {
			spin_unlock(&packet->lock);
			return false;
		}

		if (packet->state & SSH_PACKET_SF_PENDING) {
			spin_unlock(&packet->lock);
			return false;
		}
	}

	packet->state |= SSH_PACKET_SF_CANCELING;
	packet->state |= SSH_PACKET_SF_CANCELED;
	packet->state |= SSH_PACKET_SF_COMPLETED;

	spin_unlock(&packet->lock);

	ptx_dbg(ptx, "ptx: canceled packet %p\n", packet);
	ssh_ptx_packet_remove_and_complete(packet, -EINTR);

	// cancellation may have freed up some capacity to send
	if (!pending)
		ssh_ptx_process_queue(ptx, false);

	return true;
}

static void ssh_ptx_init(struct ssh_ptx *ptx, struct serdev_device *serdev)
{
	ptx->serdev = serdev;

	spin_lock_init(&ptx->queue.lock);
	INIT_LIST_HEAD(&ptx->queue.head);

	spin_lock_init(&ptx->pending.lock);
	INIT_LIST_HEAD(&ptx->pending.head);
	atomic_set(&ptx->pending.count, 0);

	INIT_WORK(&ptx->tx.work, ssh_ptx_process_work);
	ptx->tx.packet = NULL;
	ptx->tx.offset = 0;
}

static void ssh_ptx_init_packet(struct ssh_packet *packet,
				enum ssh_packet_type_flags type,
				enum ssh_packet_priority priority,
				u8 sequence_id, unsigned char *buffer,
				size_t buffer_length)
{
	packet->ptx = NULL;
	packet->type = type;
	packet->state = 0;
	packet->priority = priority;
	packet->sequence_id = sequence_id;
	packet->status = 0;

	spin_lock_init(&packet->lock);
	INIT_LIST_HEAD(&packet->queue_node);
	INIT_LIST_HEAD(&packet->pending_node);

	packet->timeout.count = 0;
	timer_setup(&packet->timeout.timer, ssh_ptx_timeout_tfn, TIMER_IRQSAFE);
	INIT_WORK(&packet->timeout.work, ssh_ptx_timeout_wfn);

	packet->buffer.ptr = buffer;
	packet->buffer.length = buffer_length;
}


/* -- TODO ------------------------------------------------------------------ */

static inline struct sam_ssh_ec *surface_sam_ssh_acquire(void)
{
	struct sam_ssh_ec *ec = &ssh_ec;

	mutex_lock(&ec->lock);
	return ec;
}

static inline void surface_sam_ssh_release(struct sam_ssh_ec *ec)
{
	mutex_unlock(&ec->lock);
}

static inline struct sam_ssh_ec *surface_sam_ssh_acquire_init(void)
{
	struct sam_ssh_ec *ec = surface_sam_ssh_acquire();

	if (smp_load_acquire(&ec->state) == SSH_EC_UNINITIALIZED) {
		surface_sam_ssh_release(ec);
		return NULL;
	}

	return ec;
}

int surface_sam_ssh_consumer_register(struct device *consumer)
{
	u32 flags = DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER;
	struct sam_ssh_ec *ec;
	struct device_link *link;

	ec = surface_sam_ssh_acquire_init();
	if (!ec)
		return -ENXIO;

	link = device_link_add(consumer, &ec->serdev->dev, flags);
	if (!link)
		return -EFAULT;

	surface_sam_ssh_release(ec);
	return 0;
}
EXPORT_SYMBOL_GPL(surface_sam_ssh_consumer_register);


static int surface_sam_ssh_rqst_unlocked(struct sam_ssh_ec *ec,
					 const struct surface_sam_ssh_rqst *rqst,
					 struct surface_sam_ssh_buf *result);

static int surface_sam_ssh_event_enable(struct sam_ssh_ec *ec, u8 tc,
					u8 unknown, u16 rqid)
{
	u8 pld[4] = { tc, unknown, rqid & 0xff, rqid >> 8 };
	u8 buf[1] = { 0x00 };
	int status;

	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x01,
		.cid = 0x0b,
		.iid = 0x00,
		.pri = SURFACE_SAM_PRIORITY_NORMAL,
		.snc = 0x01,
		.cdl = 0x04,
		.pld = pld,
	};

	struct surface_sam_ssh_buf result = {
		result.cap = ARRAY_SIZE(buf),
		result.len = 0,
		result.data = buf,
	};

	// only allow RQIDs that lie within event spectrum
	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	status = surface_sam_ssh_rqst_unlocked(ec, &rqst, &result);

	if (status) {
		dev_err(&ec->serdev->dev, "failed to enable event source"
			" (tc: 0x%02x, rqid: 0x%04x)\n", tc, rqid);
	}

	if (buf[0] != 0x00) {
		pr_warn(SSH_RQST_TAG_FULL
			"unexpected result while enabling event source: "
			"0x%02x\n", buf[0]);
	}

	return status;

}

static int surface_sam_ssh_event_disable(struct sam_ssh_ec *ec, u8 tc,
					 u8 unknown, u16 rqid)
{
	u8 pld[4] = { tc, unknown, rqid & 0xff, rqid >> 8 };
	u8 buf[1] = { 0x00 };
	int status;

	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x01,
		.cid = 0x0c,
		.iid = 0x00,
		.pri = SURFACE_SAM_PRIORITY_NORMAL,
		.snc = 0x01,
		.cdl = 0x04,
		.pld = pld,
	};

	struct surface_sam_ssh_buf result = {
		result.cap = ARRAY_SIZE(buf),
		result.len = 0,
		result.data = buf,
	};

	// only allow RQIDs that lie within event spectrum
	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	status = surface_sam_ssh_rqst_unlocked(ec, &rqst, &result);

	if (status) {
		dev_err(&ec->serdev->dev, "failed to disable event source"
			" (tc: 0x%02x, rqid: 0x%04x)\n", tc, rqid);
	}

	if (buf[0] != 0x00) {
		dev_warn(&ec->serdev->dev,
			"unexpected result while disabling event source: "
			"0x%02x\n", buf[0]);
	}

	return status;
}


int surface_sam_ssh_notifier_register(u8 tc, struct notifier_block *nb)
{
	struct sam_ssh_ec *ec;
	struct srcu_notifier_head *nh;
	u16 event = ssh_tc_to_event(tc);
	u16 rqid = ssh_event_to_rqid(event);
	int status;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	ec = surface_sam_ssh_acquire_init();
	if (!ec)
		return -ENXIO;

	nh = &ec->events.notifier[event];
	status = srcu_notifier_chain_register(nh, nb);
	if (status) {
		surface_sam_ssh_release(ec);
		return status;
	}

	if (ec->events.notifier_count[event] == 0) {
		status = surface_sam_ssh_event_enable(ec, tc, 0x01, rqid);
		if (status) {
			srcu_notifier_chain_unregister(nh, nb);
			surface_sam_ssh_release(ec);
			return status;
		}
	}
	ec->events.notifier_count[event] += 1;

	surface_sam_ssh_release(ec);
	return 0;
}
EXPORT_SYMBOL_GPL(surface_sam_ssh_notifier_register);

int surface_sam_ssh_notifier_unregister(u8 tc, struct notifier_block *nb)
{
	struct sam_ssh_ec *ec;
	struct srcu_notifier_head *nh;
	u16 event = ssh_tc_to_event(tc);
	u16 rqid = ssh_event_to_rqid(event);
	int status;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	ec = surface_sam_ssh_acquire_init();
	if (!ec)
		return -ENXIO;

	nh = &ec->events.notifier[event];
	status = srcu_notifier_chain_unregister(nh, nb);
	if (status) {
		surface_sam_ssh_release(ec);
		return status;
	}

	ec->events.notifier_count[event] -= 1;
	if (ec->events.notifier_count == 0)
		status = surface_sam_ssh_event_disable(ec, tc, 0x01, rqid);

	surface_sam_ssh_release(ec);
	return status;
}
EXPORT_SYMBOL_GPL(surface_sam_ssh_notifier_unregister);


static int ssh_send_msgbuf(struct sam_ssh_ec *ec, const struct msgbuf *msgb,
			   long timeout)
{
	struct serdev_device *serdev = ec->serdev;
	size_t len = msgb_bytes_used(msgb);
	int status;

	ssh_dbg(ec, "tx: sending data (length: %zu)\n", len);
	print_hex_dump_debug("tx: ", DUMP_PREFIX_OFFSET, 16, 1, msgb->buffer,
			     len, false);

	status = serdev_device_write(serdev, msgb->buffer, len, timeout);
	if (status < 0)
		return status;
	if ((size_t)status < len)
		return -EINTR;

	serdev_device_wait_until_sent(serdev, 0);
	return 0;
}

static inline void ssh_receiver_restart(struct sam_ssh_ec *ec,
					const struct surface_sam_ssh_rqst *rqst)
{
	unsigned long flags;

	spin_lock_irqsave(&ec->receiver.lock, flags);
	reinit_completion(&ec->receiver.signal);
	ec->receiver.state = SSH_RCV_CONTROL;
	ec->receiver.expect.pld = rqst->snc;
	ec->receiver.expect.seq = ec->counter.seq;
	ec->receiver.expect.rqid = ec->counter.rqid;
	ec->receiver.eval_buf.len = 0;
	spin_unlock_irqrestore(&ec->receiver.lock, flags);
}

static inline void ssh_receiver_discard(struct sam_ssh_ec *ec)
{
	unsigned long flags;

	spin_lock_irqsave(&ec->receiver.lock, flags);
	ec->receiver.state = SSH_RCV_DISCARD;
	ec->receiver.eval_buf.len = 0;
	kfifo_reset(&ec->receiver.fifo);
	spin_unlock_irqrestore(&ec->receiver.lock, flags);
}

static int surface_sam_ssh_rqst_unlocked(struct sam_ssh_ec *ec,
					 const struct surface_sam_ssh_rqst *rqst,
					 struct surface_sam_ssh_buf *result)
{
	struct ssh_fifo_packet packet = {};
	struct msgbuf msgb;
	u16 rqid = ec->counter.rqid;
	int status, try;
	unsigned int rem;

	// TODO: assumption doesn't hold any more, allow larger payloads
	if (rqst->cdl > SURFACE_SAM_SSH_MAX_RQST_PAYLOAD) {
		ssh_err(ec, SSH_RQST_TAG "request payload too large\n");
		return -EINVAL;
	}

	// TODO: calculate actual message length
	status = msgb_alloc(&msgb, SSH_MAX_WRITE, GFP_KERNEL);
	if (status)
		return status;

	// write command in buffer, we may need it multiple times
	msgb_push_cmd(&msgb, ec->counter.seq, rqst, rqid);

	ssh_receiver_restart(ec, rqst);

	// send command, try to get an ack response
	for (try = 0; try < SSH_NUM_RETRY; try++) {
		status = ssh_send_msgbuf(ec, &msgb, SSH_TX_TIMEOUT);
		if (status)
			goto out;

		rem = wait_for_completion_timeout(&ec->receiver.signal, SSH_RX_TIMEOUT);
		if (rem) {
			// completion assures valid packet, thus ignore returned length
			(void) !kfifo_out(&ec->receiver.fifo, &packet, sizeof(packet));

			if (packet.type == SSH_FRAME_TYPE_ACK)
				break;
		}
	}

	// check if we ran out of tries?
	if (try >= SSH_NUM_RETRY) {
		ssh_err(ec, SSH_RQST_TAG "communication failed %d times, giving up\n", try);
		status = -EIO;
		goto out;
	}

	ec->counter.seq += 1;
	ec->counter.rqid = ssh_rqid_next(ec->counter.rqid);

	// get command response/payload
	if (rqst->snc && result) {
		rem = wait_for_completion_timeout(&ec->receiver.signal, SSH_RX_TIMEOUT);
		if (rem) {
			// completion assures valid packet, thus ignore returned length
			(void) !kfifo_out(&ec->receiver.fifo, &packet, sizeof(packet));

			if (result->cap < packet.len) {
				status = -EINVAL;
				goto out;
			}

			// completion assures valid packet, thus ignore returned length
			(void) !kfifo_out(&ec->receiver.fifo, result->data, packet.len);
			result->len = packet.len;
		} else {
			ssh_err(ec, SSH_RQST_TAG "communication timed out\n");
			status = -EIO;
			goto out;
		}

		// send ACK
		if (packet.type == SSH_FRAME_TYPE_DATA_SEQ) {
			// TODO: add send_ack function?
			msgb_reset(&msgb);
			msgb_push_ack(&msgb, packet.seq);

			status = ssh_send_msgbuf(ec, &msgb, SSH_TX_TIMEOUT);
			if (status)
				goto out;
		}
	}

out:
	ssh_receiver_discard(ec);
	msgb_free(&msgb);
	return status;
}

int surface_sam_ssh_rqst(const struct surface_sam_ssh_rqst *rqst, struct surface_sam_ssh_buf *result)
{
	struct sam_ssh_ec *ec;
	int status;

	ec = surface_sam_ssh_acquire_init();
	if (!ec) {
		pr_warn(SSH_RQST_TAG_FULL "embedded controller is uninitialized\n");
		return -ENXIO;
	}

	if (smp_load_acquire(&ec->state) == SSH_EC_SUSPENDED) {
		ssh_warn(ec, SSH_RQST_TAG "embedded controller is suspended\n");

		surface_sam_ssh_release(ec);
		return -EPERM;
	}

	status = surface_sam_ssh_rqst_unlocked(ec, rqst, result);

	surface_sam_ssh_release(ec);
	return status;
}
EXPORT_SYMBOL_GPL(surface_sam_ssh_rqst);


/**
 * surface_sam_ssh_ec_resume - Resume the EC if it is in a suspended mode.
 * @ec: the EC to resume
 *
 * Moves the EC from a suspended state to a normal state. See the
 * `surface_sam_ssh_ec_suspend` function what the specific differences of
 * these states are. Multiple repeated calls to this function seem to be
 * handled fine by the EC, after the first call, the state will remain
 * "normal".
 *
 * Must be called with the EC initialized and its lock held.
 */
static int surface_sam_ssh_ec_resume(struct sam_ssh_ec *ec)
{
	u8 buf[1] = { 0x00 };
	int status;

	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x01,
		.cid = 0x16,
		.iid = 0x00,
		.pri = SURFACE_SAM_PRIORITY_NORMAL,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surface_sam_ssh_buf result = {
		result.cap = ARRAY_SIZE(buf),
		result.len = 0,
		result.data = buf,
	};

	ssh_dbg(ec, "pm: resuming system aggregator module\n");
	status = surface_sam_ssh_rqst_unlocked(ec, &rqst, &result);
	if (status)
		return status;

	/*
	 * The purpose of the return value of this request is unknown. Based on
	 * logging and experience, we expect it to be zero. No other value has
	 * been observed so far.
	 */
	if (buf[0] != 0x00) {
		ssh_warn(ec, "unexpected result while trying to resume EC: "
			 "0x%02x\n", buf[0]);
	}

	return 0;
}

/**
 * surface_sam_ssh_ec_suspend - Put the EC in a suspended mode:
 * @ec: the EC to suspend
 *
 * Tells the EC to enter a suspended mode. In this mode, events are quiesced
 * and the wake IRQ is armed (note that the wake IRQ does not fire if the EC
 * has not been suspended via this request). On some devices, the keyboard
 * backlight is turned off. Apart from this, the EC seems to continue to work
 * as normal, meaning requests sent to it are acknowledged and seem to be
 * correctly handled, including potential responses. Multiple repeated calls
 * to this function seem to be handled fine by the EC, after the first call,
 * the state will remain "suspended".
 *
 * Must be called with the EC initialized and its lock held.
 */
static int surface_sam_ssh_ec_suspend(struct sam_ssh_ec *ec)
{
	u8 buf[1] = { 0x00 };
	int status;

	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x01,
		.cid = 0x15,
		.iid = 0x00,
		.pri = SURFACE_SAM_PRIORITY_NORMAL,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surface_sam_ssh_buf result = {
		result.cap = ARRAY_SIZE(buf),
		result.len = 0,
		result.data = buf,
	};

	ssh_dbg(ec, "pm: suspending system aggregator module\n");
	status = surface_sam_ssh_rqst_unlocked(ec, &rqst, &result);
	if (status)
		return status;

	/*
	 * The purpose of the return value of this request is unknown. Based on
	 * logging and experience, we expect it to be zero. No other value has
	 * been observed so far.
	 */
	if (buf[0] != 0x00) {
		ssh_warn(ec, "unexpected result while trying to suspend EC: "
			 "0x%02x\n", buf[0]);
	}

	return 0;
}


static int surface_sam_ssh_get_controller_version(struct sam_ssh_ec *ec, u32 *version)
{
	struct surface_sam_ssh_rqst rqst = {
		.tc  = 0x01,
		.cid = 0x13,
		.iid = 0x00,
		.pri = SURFACE_SAM_PRIORITY_NORMAL,
		.snc = 0x01,
		.cdl = 0x00,
		.pld = NULL,
	};

	struct surface_sam_ssh_buf result = {
		result.cap = sizeof(*version),
		result.len = 0,
		result.data = (u8 *)version,
	};

	*version = 0;
	return surface_sam_ssh_rqst_unlocked(ec, &rqst, &result);
}

static int surface_sam_ssh_log_controller_version(struct sam_ssh_ec *ec)
{
	u32 version, a, b, c;
	int status;

	status = surface_sam_ssh_get_controller_version(ec, &version);
	if (status)
		return status;

	a = (version >> 24) & 0xff;
	b = le16_to_cpu((version >> 8) & 0xffff);
	c = version & 0xff;

	dev_info(&ec->serdev->dev, "SAM controller version: %u.%u.%u\n",
		 a, b, c);
	return 0;
}


static inline bool ssh_is_valid_syn(const u8 *ptr)
{
	return ptr[0] == 0xaa && ptr[1] == 0x55;
}

static inline bool ssh_is_valid_ter(const u8 *ptr)
{
	return ptr[0] == 0xff && ptr[1] == 0xff;
}

static inline bool ssh_is_valid_crc(const u8 *begin, const u8 *end)
{
	u16 crc;

	crc = ssh_crc(begin, end - begin);
	return (end[0] == (crc & 0xff)) && (end[1] == (crc >> 8));
}


static void surface_sam_ssh_event_work_ack_handler(struct work_struct *_work)
{
	u8 buf[SSH_MSG_LEN_CTRL];
	struct msgbuf msgb;
	struct surface_sam_ssh_event *event;
	struct ssh_event_work *work;
	struct sam_ssh_ec *ec;
	struct device *dev;
	int status;

	work = container_of(_work, struct ssh_event_work, work_ack);
	event = &work->event;
	ec = work->ec;
	dev = &ec->serdev->dev;

	if (smp_load_acquire(&ec->state) == SSH_EC_INITIALIZED) {
		msgb_init(&msgb, buf, ARRAY_SIZE(buf));
		msgb_push_ack(&msgb, work->seq);

		status = ssh_send_msgbuf(ec, &msgb, SSH_TX_TIMEOUT);
		if (status)
			ssh_err(ec, SSH_EVENT_TAG "failed to send ACK: %d\n", status);
	}

	if (refcount_dec_and_test(&work->refcount))
		kfree(work);
}

static void surface_sam_ssh_event_work_evt_handler(struct work_struct *_work)
{
	struct ssh_event_work *work;
	struct srcu_notifier_head *nh;
	struct surface_sam_ssh_event *event;
	struct sam_ssh_ec *ec;
	struct device *dev;
	int status = 0, ncalls = 0;

	work = container_of(_work, struct ssh_event_work, work_evt);
	event = &work->event;
	ec = work->ec;
	dev = &ec->serdev->dev;

	nh = &ec->events.notifier[ssh_rqid_to_event(event->rqid)];
	status = __srcu_notifier_call_chain(nh, event->tc, event, -1, &ncalls);
	status = notifier_to_errno(status);

	if (status < 0)
		ssh_err(ec, "event: error handling event: %d\n", status);

	if (ncalls == 0) {
		ssh_warn(ec, "event: unhandled event"
			 " (rqid: 0x%04x, tc: 0x%02x, cid: 0x%02x)\n",
			 event->rqid, event->tc, event->cid);
	}

	if (refcount_dec_and_test(&work->refcount))
		kfree(work);
}

static void ssh_rx_handle_event(struct sam_ssh_ec *ec,
				const struct ssh_frame *frame,
				const struct ssh_command *command,
				const struct bufspan *command_data)
{
	struct ssh_event_work *work;

	work = kzalloc(sizeof(struct ssh_event_work) + command_data->len, GFP_ATOMIC);
	if (!work)
		return;

	refcount_set(&work->refcount, 1);
	work->ec         = ec;
	work->seq        = frame->seq;
	work->event.rqid = get_unaligned_le16(&command->rqid),
	work->event.tc   = command->tc;
	work->event.cid  = command->cid;
	work->event.iid  = command->iid;
	work->event.pri  = command->pri_in;
	work->event.len  = command_data->len;
	work->event.pld  = ((u8 *)work) + sizeof(struct ssh_event_work);
	memcpy(work->event.pld, command_data->ptr, command_data->len);

	// queue ACK for if required
	if (frame->type == SSH_FRAME_TYPE_DATA_SEQ) {
		refcount_set(&work->refcount, 2);
		INIT_WORK(&work->work_ack, surface_sam_ssh_event_work_ack_handler);
		queue_work(ec->events.queue_ack, &work->work_ack);
	}

	INIT_WORK(&work->work_evt, surface_sam_ssh_event_work_evt_handler);
	queue_work(ec->events.queue_evt, &work->work_evt);
}

static void ssh_rx_complete_command(struct sam_ssh_ec *ec,
				    const struct ssh_frame *frame,
				    const struct ssh_command *command,
				    const struct bufspan *command_data)
{
	struct ssh_receiver *rcv = &ec->receiver;
	struct ssh_fifo_packet packet;

	// check if we expect the message
	if (unlikely(rcv->state != SSH_RCV_COMMAND)) {
		ssh_dbg(ec, "rx: discarding message: command not expected\n");
		return;
	}

	// check if response is for our request
	if (unlikely(rcv->expect.rqid != get_unaligned_le16(&command->rqid))) {
		ssh_dbg(ec, "rx: discarding message: command not a match\n");
		return;
	}

	// we now have a valid & expected command message
	ssh_dbg(ec, "rx: valid command message received\n");

	packet.type = frame->type;
	packet.seq = frame->seq;
	packet.len = command_data->len;

	if (unlikely(kfifo_avail(&rcv->fifo) < sizeof(packet) + packet.len)) {
		ssh_warn(ec, "rx: dropping frame: not enough space in fifo (type = %d)\n",
			 frame->type);
		return;
	}

	kfifo_in(&rcv->fifo, &packet, sizeof(packet));
	kfifo_in(&rcv->fifo, command_data->ptr, command_data->len);

	rcv->state = SSH_RCV_DISCARD;
	complete(&rcv->signal);
}

static void ssh_receive_control_frame(struct sam_ssh_ec *ec,
				      const struct ssh_frame *frame)
{
	struct ssh_receiver *rcv = &ec->receiver;
	struct ssh_fifo_packet packet;

	// check if we expect the message
	if (unlikely(rcv->state != SSH_RCV_CONTROL)) {
		ssh_err(ec, "rx: discarding message: control not expected\n");
		return;
	}

	// check if it is for our request
	if (unlikely(frame->type == SSH_FRAME_TYPE_ACK && frame->seq != rcv->expect.seq)) {
		ssh_err(ec, "rx: discarding message: ACK does not match\n");
		return;
	}

	// we now have a valid & expected ACK/RETRY message
	ssh_dbg(ec, "rx: valid control message received (type: 0x%02x)\n", frame->type);

	packet.type = frame->type;
	packet.seq  = frame->seq;
	packet.len  = 0;

	if (unlikely(kfifo_avail(&rcv->fifo) < sizeof(packet))) {
		ssh_warn(ec, "rx: dropping frame: not enough space in fifo (type = %d)\n",
			 frame->type);
		return;
	}

	kfifo_in(&rcv->fifo, (u8 *) &packet, sizeof(packet));

	// update decoder state
	if (frame->type == SSH_FRAME_TYPE_ACK)
		rcv->state = rcv->expect.pld ? SSH_RCV_COMMAND : SSH_RCV_DISCARD;

	complete(&rcv->signal);
}

static void ssh_receive_command_frame(struct sam_ssh_ec *ec,
				      const struct ssh_frame *frame,
				      const struct ssh_command *command,
				      const struct bufspan *command_data)
{
	// check if we received an event notification
	if (ssh_rqid_is_event(get_unaligned_le16(&command->rqid))) {
		ssh_rx_handle_event(ec, frame, command, command_data);
	} else {
		ssh_rx_complete_command(ec, frame, command, command_data);
	}
}

static void ssh_receive_data_frame(struct sam_ssh_ec *ec,
				   const struct ssh_frame *frame,
				   const struct bufspan *payload)
{
	struct ssh_command *command;
	struct bufspan command_data;

	if (likely(payload->ptr[0] == SSH_PLD_TYPE_CMD)) {
		sshp_parse_command(ec, payload, &command, &command_data);
		if (unlikely(!command))
			return;

		ssh_receive_command_frame(ec, frame, command, &command_data);
	} else {
		ssh_err(ec, "rx: unknown frame payload type (type: 0x%02x)\n",
			payload->ptr[0]);
	}
}

static size_t ssh_eval_buf(struct sam_ssh_ec *ec, u8 *buf, size_t size)
{
	struct ssh_frame *frame;
	struct bufspan source = { .ptr = buf, .len = size };
	struct bufspan payload;
	size_t n;

	// parse and validate frame
	n = sshp_parse_frame(ec, &source, &frame, &payload);
	if (!frame)
		return n;

	switch (frame->type) {
	case SSH_FRAME_TYPE_ACK:
	case SSH_FRAME_TYPE_NAK:
		ssh_receive_control_frame(ec, frame);
		break;

	case SSH_FRAME_TYPE_DATA_SEQ:
	case SSH_FRAME_TYPE_DATA_NSQ:
		ssh_receive_data_frame(ec, frame, &payload);
		break;

	default:
		ssh_warn(ec, "rx: unknown frame type 0x%02x\n", frame->type);
	}

	return n + ssh_message_length(frame->len);
}

static int ssh_receive_buf(struct serdev_device *serdev,
			   const unsigned char *buf, size_t size)
{
	struct sam_ssh_ec *ec = serdev_device_get_drvdata(serdev);
	struct ssh_receiver *rcv = &ec->receiver;
	unsigned long flags;
	size_t n, offs = 0, used;

	ssh_dbg(ec, "rx: received data (size: %zu)\n", size);
	print_hex_dump_debug("rx: ", DUMP_PREFIX_OFFSET, 16, 1, buf, size, false);

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
		n = ssh_eval_buf(ec, rcv->eval_buf.ptr + offs, n);
		if (n == 0)
			break;	// need more bytes

		offs += n;
	}

	// throw away the evaluated parts
	rcv->eval_buf.len -= offs;
	memmove(rcv->eval_buf.ptr, rcv->eval_buf.ptr + offs, rcv->eval_buf.len);

	spin_unlock_irqrestore(&rcv->lock, flags);

	return used;
}


static const struct acpi_gpio_params gpio_ssh_wakeup_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_ssh_wakeup     = { 1, 0, false };

static const struct acpi_gpio_mapping ssh_acpi_gpios[] = {
	{ "ssh_wakeup-int-gpio", &gpio_ssh_wakeup_int, 1 },
	{ "ssh_wakeup-gpio",     &gpio_ssh_wakeup,     1 },
	{ },
};

static irqreturn_t ssh_wake_irq_handler(int irq, void *dev_id)
{
	struct serdev_device *serdev = dev_id;

	dev_dbg(&serdev->dev, "pm: wake irq triggered\n");

	// TODO: Send GPIO callback command repeatedly to EC until callback
	//       returns 0x00. Return flag of callback is "has more events".
	//       Each time the command is sent, one event is "released". Once
	//       all events have been released (return = 0x00), the GPIO is
	//       re-armed.

	return IRQ_HANDLED;
}

static int ssh_setup_irq(struct serdev_device *serdev)
{
	const int irqf = IRQF_SHARED | IRQF_ONESHOT | IRQF_TRIGGER_RISING;
	struct gpio_desc *gpiod;
	int irq;
	int status;

	gpiod = gpiod_get(&serdev->dev, "ssh_wakeup-int", GPIOD_ASIS);
	if (IS_ERR(gpiod))
		return PTR_ERR(gpiod);

	irq = gpiod_to_irq(gpiod);
	gpiod_put(gpiod);

	if (irq < 0)
		return irq;

	status = request_threaded_irq(irq, NULL, ssh_wake_irq_handler,
				      irqf, "surface_sam_sh_wakeup", serdev);
	if (status)
		return status;

	return irq;
}


static acpi_status ssh_setup_from_resource(struct acpi_resource *rsc, void *ctx)
{
	struct serdev_device *serdev = ctx;
	struct acpi_resource_common_serialbus *serial;
	struct acpi_resource_uart_serialbus *uart;
	bool flow_control;
	int status = 0;

	if (rsc->type != ACPI_RESOURCE_TYPE_SERIAL_BUS)
		return AE_OK;

	serial = &rsc->data.common_serial_bus;
	if (serial->type != ACPI_RESOURCE_SERIAL_TYPE_UART)
		return AE_OK;

	uart = &rsc->data.uart_serial_bus;

	// set up serdev device
	serdev_device_set_baudrate(serdev, uart->default_baud_rate);

	// serdev currently only supports RTSCTS flow control
	if (uart->flow_control & SSH_SUPPORTED_FLOW_CONTROL_MASK) {
		dev_warn(&serdev->dev, "setup: unsupported flow control"
			 " (value: 0x%02x)\n", uart->flow_control);
	}

	// set RTSCTS flow control
	flow_control = uart->flow_control & ACPI_UART_FLOW_CONTROL_HW;
	serdev_device_set_flow_control(serdev, flow_control);

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
		dev_warn(&serdev->dev, "setup: unsupported parity"
			 " (value: 0x%02x)\n", uart->parity);
		break;
	}

	if (status) {
		dev_err(&serdev->dev, "setup: failed to set parity"
			" (value: 0x%02x)\n", uart->parity);
		return status;
	}

	return AE_CTRL_TERMINATE;       // we've found the resource and are done
}


static int surface_sam_ssh_suspend(struct device *dev)
{
	struct sam_ssh_ec *ec;
	int status;

	dev_dbg(dev, "pm: suspending\n");

	ec = surface_sam_ssh_acquire_init();
	if (ec) {
		status = surface_sam_ssh_ec_suspend(ec);
		if (status) {
			surface_sam_ssh_release(ec);
			return status;
		}

		if (device_may_wakeup(dev)) {
			status = enable_irq_wake(ec->irq);
			if (status) {
				surface_sam_ssh_release(ec);
				return status;
			}

			ec->irq_wakeup_enabled = true;
		} else {
			ec->irq_wakeup_enabled = false;
		}

		smp_store_release(&ec->state, SSH_EC_SUSPENDED);
		surface_sam_ssh_release(ec);
	}

	return 0;
}

static int surface_sam_ssh_resume(struct device *dev)
{
	struct sam_ssh_ec *ec;
	int status;

	dev_dbg(dev, "pm: resuming\n");

	ec = surface_sam_ssh_acquire_init();
	if (ec) {
		smp_store_release(&ec->state, SSH_EC_INITIALIZED);

		if (ec->irq_wakeup_enabled) {
			status = disable_irq_wake(ec->irq);
			if (status) {
				surface_sam_ssh_release(ec);
				return status;
			}

			ec->irq_wakeup_enabled = false;
		}

		status = surface_sam_ssh_ec_resume(ec);
		if (status) {
			surface_sam_ssh_release(ec);
			return status;
		}

		surface_sam_ssh_release(ec);
	}

	return 0;
}

static SIMPLE_DEV_PM_OPS(surface_sam_ssh_pm_ops, surface_sam_ssh_suspend,
			 surface_sam_ssh_resume);


static const struct serdev_device_ops ssh_device_ops = {
	.receive_buf  = ssh_receive_buf,
	.write_wakeup = serdev_device_write_wakeup,
};

static int surface_sam_ssh_probe(struct serdev_device *serdev)
{
	struct sam_ssh_ec *ec;
	struct workqueue_struct *event_queue_ack;
	struct workqueue_struct *event_queue_evt;
	u8 *read_buf;
	u8 *eval_buf;
	acpi_handle *ssh = ACPI_HANDLE(&serdev->dev);
	acpi_status status;
	int irq, i;

	if (gpiod_count(&serdev->dev, NULL) < 0)
		return -ENODEV;

	status = devm_acpi_dev_add_driver_gpios(&serdev->dev, ssh_acpi_gpios);
	if (status)
		return status;

	// allocate buffers
	read_buf = kzalloc(SSH_READ_BUF_LEN, GFP_KERNEL);
	if (!read_buf) {
		status = -ENOMEM;
		goto err_read_buf;
	}

	eval_buf = kzalloc(SSH_EVAL_BUF_LEN, GFP_KERNEL);
	if (!eval_buf) {
		status = -ENOMEM;
		goto err_eval_buf;
	}

	event_queue_ack = create_singlethread_workqueue("surface_sh_ackq");
	if (!event_queue_ack) {
		status = -ENOMEM;
		goto err_ackq;
	}

	event_queue_evt = create_workqueue("surface_sh_evtq");
	if (!event_queue_evt) {
		status = -ENOMEM;
		goto err_evtq;
	}

	irq = ssh_setup_irq(serdev);
	if (irq < 0) {
		status = irq;
		goto err_irq;
	}

	// set up EC
	ec = surface_sam_ssh_acquire();
	if (smp_load_acquire(&ec->state) != SSH_EC_UNINITIALIZED) {
		dev_err(&serdev->dev, "embedded controller already initialized\n");
		surface_sam_ssh_release(ec);

		status = -EBUSY;
		goto err_busy;
	}

	ec->serdev = serdev;
	ec->irq    = irq;

	// initialize receiver
	init_completion(&ec->receiver.signal);
	kfifo_init(&ec->receiver.fifo, read_buf, SSH_READ_BUF_LEN);
	ec->receiver.eval_buf.ptr = eval_buf;
	ec->receiver.eval_buf.cap = SSH_EVAL_BUF_LEN;
	ec->receiver.eval_buf.len = 0;

	// initialize event handling
	ec->events.queue_ack = event_queue_ack;
	ec->events.queue_evt = event_queue_evt;

	for (i = 0; i < SURFACE_SAM_SSH_MAX_EVENT_ID; i++) {
		srcu_init_notifier_head(&ec->events.notifier[i]);
		ec->events.notifier_count[i] = 0;
	}

	serdev_device_set_drvdata(serdev, ec);

	smp_store_release(&ec->state, SSH_EC_INITIALIZED);

	serdev_device_set_client_ops(serdev, &ssh_device_ops);
	status = serdev_device_open(serdev);
	if (status)
		goto err_open;

	status = acpi_walk_resources(ssh, METHOD_NAME__CRS,
				     ssh_setup_from_resource, serdev);
	if (ACPI_FAILURE(status))
		goto err_devinit;

	status = surface_sam_ssh_log_controller_version(ec);
	if (status)
		goto err_devinit;

	status = surface_sam_ssh_ec_resume(ec);
	if (status)
		goto err_devinit;

	surface_sam_ssh_release(ec);

	// TODO: The EC can wake up the system via the associated GPIO interrupt in
	// multiple situations. One of which is the remaining battery capacity
	// falling below a certain threshold. Normally, we should use the
	// device_init_wakeup function, however, the EC also seems to have other
	// reasons for waking up the system and it seems that Windows has
	// additional checks whether the system should be resumed. In short, this
	// causes some spourious unwanted wake-ups. For now let's thus default
	// power/wakeup to false.
	device_set_wakeup_capable(&serdev->dev, true);
	acpi_walk_dep_device_list(ssh);

	return 0;

err_devinit:
	serdev_device_close(serdev);
err_open:
	smp_store_release(&ec->state, SSH_EC_UNINITIALIZED);
	serdev_device_set_drvdata(serdev, NULL);
	surface_sam_ssh_release(ec);
err_busy:
	free_irq(irq, serdev);
err_irq:
	destroy_workqueue(event_queue_evt);
err_evtq:
	destroy_workqueue(event_queue_ack);
err_ackq:
	kfree(eval_buf);
err_eval_buf:
	kfree(read_buf);
err_read_buf:
	return status;
}

static void surface_sam_ssh_remove(struct serdev_device *serdev)
{
	struct sam_ssh_ec *ec;
	unsigned long flags;
	int status, i;

	ec = surface_sam_ssh_acquire_init();
	if (!ec)
		return;

	free_irq(ec->irq, serdev);

	// suspend EC and disable events
	status = surface_sam_ssh_ec_suspend(ec);
	if (status)
		dev_err(&serdev->dev, "failed to suspend EC: %d\n", status);

	// make sure all events (received up to now) have been properly handled
	flush_workqueue(ec->events.queue_ack);
	flush_workqueue(ec->events.queue_evt);

	// remove event handlers
	for (i = 0; i < SURFACE_SAM_SSH_MAX_EVENT_ID; i++) {
		srcu_cleanup_notifier_head(&ec->events.notifier[i]);
		ec->events.notifier_count[i] = 0;
	}

	// set device to deinitialized state
	smp_store_release(&ec->state, SSH_EC_UNINITIALIZED);
	ec->serdev = NULL;

	/*
	 * Flush any event that has not been processed yet to ensure we're not going to
	 * use the serial device any more (e.g. for ACKing).
	 */
	flush_workqueue(ec->events.queue_ack);
	flush_workqueue(ec->events.queue_evt);

	serdev_device_close(serdev);

	/*
	 * Only at this point, no new events can be received. Destroying the
	 * workqueue here flushes all remaining events. Those events will be
	 * silently ignored and neither ACKed nor any handler gets called.
	 */
	destroy_workqueue(ec->events.queue_ack);
	destroy_workqueue(ec->events.queue_evt);

	// free receiver
	spin_lock_irqsave(&ec->receiver.lock, flags);
	ec->receiver.state = SSH_RCV_DISCARD;
	kfifo_free(&ec->receiver.fifo);

	kfree(ec->receiver.eval_buf.ptr);
	ec->receiver.eval_buf.ptr = NULL;
	ec->receiver.eval_buf.cap = 0;
	ec->receiver.eval_buf.len = 0;
	spin_unlock_irqrestore(&ec->receiver.lock, flags);

	device_set_wakeup_capable(&serdev->dev, false);
	serdev_device_set_drvdata(serdev, NULL);
	surface_sam_ssh_release(ec);
}


static const struct acpi_device_id surface_sam_ssh_match[] = {
	{ "MSHW0084", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_ssh_match);

static struct serdev_device_driver surface_sam_ssh = {
	.probe = surface_sam_ssh_probe,
	.remove = surface_sam_ssh_remove,
	.driver = {
		.name = "surface_sam_ssh",
		.acpi_match_table = surface_sam_ssh_match,
		.pm = &surface_sam_ssh_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


static int __init surface_sam_ssh_init(void)
{
	return serdev_device_driver_register(&surface_sam_ssh);
}

static void __exit surface_sam_ssh_exit(void)
{
	serdev_device_driver_unregister(&surface_sam_ssh);
}

/*
 * Ensure that the driver is loaded late due to some issues with the UART
 * communication. Specifically, we want to ensure that DMA is ready and being
 * used. Not using DMA can result in spurious communication failures,
 * especially during boot, which among other things will result in wrong
 * battery information (via ACPI _BIX) being displayed. Using a late init_call
 * instead of the normal module_init gives the DMA subsystem time to
 * initialize and via that results in a more stable communication, avoiding
 * such failures.
 */
late_initcall(surface_sam_ssh_init);
module_exit(surface_sam_ssh_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface Serial Hub Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");

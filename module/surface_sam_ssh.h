/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Interface for Surface Serial Hub (SSH).
 *
 * The SSH is the main communication hub for communication between host and
 * the Surface/System Aggregator Module (SAM) on newer Microsoft Surface
 * devices (Book 2, Pro 5, Laptops, ...). Also referred to as SAM-over-SSH.
 * Older devices (Book 1, Pro 4) use SAM-over-HID (via I2C).
 */

#ifndef _SURFACE_SAM_SSH_H
#define _SURFACE_SAM_SSH_H

#include <linux/types.h>
#include <linux/device.h>

/* -- Main data types and definitions --------------------------------------- */

enum ssam_ssh_tc {
	SSAM_SSH_TC_SAM = 0x01,	// generic system functionality, real-time clock
	SSAM_SSH_TC_BAT = 0x02,	// battery/power subsystem
	SSAM_SSH_TC_TMP = 0x03,	// thermal subsystem
	SSAM_SSH_TC_PMC = 0x04,
	SSAM_SSH_TC_FAN = 0x05,
	SSAM_SSH_TC_PoM = 0x06,
	SSAM_SSH_TC_DBG = 0x07,
	SSAM_SSH_TC_KBD = 0x08,	// legacy keyboard (Laptop 1/2)
	SSAM_SSH_TC_FWU = 0x09,
	SSAM_SSH_TC_UNI = 0x0a,
	SSAM_SSH_TC_LPC = 0x0b,
	SSAM_SSH_TC_TCL = 0x0c,
	SSAM_SSH_TC_SFL = 0x0d,
	SSAM_SSH_TC_KIP = 0x0e,
	SSAM_SSH_TC_EXT = 0x0f,
	SSAM_SSH_TC_BLD = 0x10,
	SSAM_SSH_TC_BAS = 0x11,	// detachment system (Surface Book 2/3)
	SSAM_SSH_TC_SEN = 0x12,
	SSAM_SSH_TC_SRQ = 0x13,
	SSAM_SSH_TC_MCU = 0x14,
	SSAM_SSH_TC_HID = 0x15,	// generic HID input subsystem
	SSAM_SSH_TC_TCH = 0x16,
	SSAM_SSH_TC_BKL = 0x17,
	SSAM_SSH_TC_TAM = 0x18,
	SSAM_SSH_TC_ACC = 0x19,
	SSAM_SSH_TC_UFI = 0x1a,
	SSAM_SSH_TC_USC = 0x1b,
	SSAM_SSH_TC_PEN = 0x1c,
	SSAM_SSH_TC_VID = 0x1d,
	SSAM_SSH_TC_AUD = 0x1e,
	SSAM_SSH_TC_SMC = 0x1f,
	SSAM_SSH_TC_KPD = 0x20,
	SSAM_SSH_TC_REG = 0x21,
};

/**
 * struct ssam_event_flags - Flags for enabling/disabling SAM-over-SSH events
 * @SSAM_EVENT_SEQUENCED: The event will be sent via a sequenced data frame.
 */
enum ssam_event_flags {
	SSAM_EVENT_SEQUENCED = BIT(0),
};

struct ssam_event {
	u8 target_category;
	u8 command_id;
	u8 instance_id;
	u8 channel;
	u16 length;
	u8 data[0];
};


/* -- Event notifier/callbacks. --------------------------------------------- */

#define SSAM_NOTIF_STATE_SHIFT		2
#define SSAM_NOTIF_STATE_MASK		((1 << SSAM_NOTIF_STATE_SHIFT) - 1)

#define SSAM_NOTIF_HANDLED		BIT(0)
#define SSAM_NOTIF_STOP			BIT(1)


struct ssam_notifier_block;

typedef u32 (*ssam_notifier_fn_t)(struct ssam_notifier_block *nb,
				  const struct ssam_event *event);

struct ssam_notifier_block {
	struct ssam_notifier_block __rcu *next;
	ssam_notifier_fn_t fn;
	int priority;
};


static inline u32 ssam_notifier_from_errno(int err)
{
	WARN_ON(err > 0);

	if (err >= 0)
		return 0;
	else
		return ((-err) << SSAM_NOTIF_STATE_SHIFT) | SSAM_NOTIF_STOP;
}

static inline int ssam_notifier_to_errno(u32 ret)
{
	return -(ret >> SSAM_NOTIF_STATE_SHIFT);
}


/* -- Event/notification registry. ------------------------------------------ */

struct ssam_event_registry {
	u8 target_category;
	u8 channel;
	u8 cid_enable;
	u8 cid_disable;
};

struct ssam_event_id {
	u8 target_category;
	u8 instance;
};


#define SSAM_EVENT_REGISTRY(tc, chn, cid_en, cid_dis)	\
	((struct ssam_event_registry) {			\
		.target_category = (tc),		\
		.channel = (chn),			\
		.cid_enable = (cid_en),			\
		.cid_disable = (cid_dis),		\
	})

#define SSAM_EVENT_ID(tc, iid)				\
	((struct ssam_event_id) {			\
		.target_category = tc,			\
		.instance = iid,			\
	})


#define SSAM_EVENT_REGISTRY_SAM	\
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_SAM, 0x01, 0x0b, 0x0c)

#define SSAM_EVENT_REGISTRY_KIP	\
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_KIP, 0x02, 0x27, 0x28)

#define SSAM_EVENT_REGISTRY_REG \
	SSAM_EVENT_REGISTRY(SSAM_SSH_TC_REG, 0x02, 0x01, 0x02)


struct ssam_event_notifier {
	struct ssam_notifier_block base;

	struct {
		struct ssam_event_registry reg;
		struct ssam_event_id id;
		u8 flags;
	} event;
};


/* -- TODO -------------------------------------------------------------------*/

/*
 * Maximum request payload size in bytes.
 * Value based on ACPI (255 bytes minus header/status bytes).
 */
#define SURFACE_SAM_SSH_MAX_RQST_PAYLOAD	(255 - 10)

/*
 * Maximum response payload size in bytes.
 * Value based on ACPI (255 bytes minus header/status bytes).
 */
#define SURFACE_SAM_SSH_MAX_RQST_RESPONSE	(255 - 4)

/*
 * The number of reserved event IDs, used for registering an SSH event
 * handler. Valid event IDs are numbers below or equal to this value, with
 * exception of zero, which is not an event ID. Thus, this is also the
 * absolute maximum number of event handlers that can be registered.
 */
#define SURFACE_SAM_SSH_NUM_EVENTS		32

/*
 * The number of communication channels used in the protocol.
 */
#define SURFACE_SAM_SSH_NUM_CHANNELS		2

/*
 * Special event-handler delay value indicating that the corresponding event
 * should be handled immediately in the interrupt and not be relayed through
 * the workqueue. Intended for low-latency events, such as keyboard events.
 */
#define SURFACE_SAM_SSH_EVENT_IMMEDIATE		((unsigned long) -1)


struct surface_sam_ssh_buf {
	u8 cap;
	u8 len;
	u8 *data;
};

struct surface_sam_ssh_rqst {
	u8 tc;				// target category
	u8 cid;				// command ID
	u8 iid;				// instance ID
	u8 chn;				// channel
	u8 snc;				// expect response flag (bool: 0/1)
	u16 cdl;			// command data length (length of payload)
	u8 *pld;			// pointer to payload of length cdl
};

// TODO: remove rqid on external api
struct surface_sam_ssh_event {
	u16 rqid;			// event type/source ID
	u8  tc;				// target category
	u8  cid;			// command ID
	u8  iid;			// instance ID
	u8  chn;			// channel
	u8  len;			// length of payload
	u8 *pld;			// payload of length len
};


int surface_sam_ssh_consumer_register(struct device *consumer);

int surface_sam_ssh_notifier_register(struct ssam_event_notifier *n);
int surface_sam_ssh_notifier_unregister(struct ssam_event_notifier *n);

int surface_sam_ssh_rqst(const struct surface_sam_ssh_rqst *rqst, struct surface_sam_ssh_buf *result);

#endif /* _SURFACE_SAM_SSH_H */

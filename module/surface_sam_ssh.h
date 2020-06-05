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
#include <linux/notifier.h>


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
 * Special event-handler delay value indicating that the corresponding event
 * should be handled immediately in the interrupt and not be relayed through
 * the workqueue. Intended for low-latency events, such as keyboard events.
 */
#define SURFACE_SAM_SSH_EVENT_IMMEDIATE		((unsigned long) -1)


enum surface_sam_rqst_priority {
	SURFACE_SAM_PRIORITY_NORMAL = 1,
	SURFACE_SAM_PRIORITY_HIGH   = 2,
};


struct surface_sam_ssh_buf {
	u8 cap;
	u8 len;
	u8 *data;
};

struct surface_sam_ssh_rqst {
	u8 tc;				// target category
	u8 cid;				// command ID
	u8 iid;				// instance ID
	u8 pri;				// priority
	u8 snc;				// expect response flag (bool: 0/1)
	u8 cdl;				// command data length (length of payload)
	u8 *pld;			// pointer to payload of length cdl
};

struct surface_sam_ssh_event {
	u16 rqid;			// event type/source ID
	u8  tc;				// target category
	u8  cid;			// command ID
	u8  iid;			// instance ID
	u8  pri;			// priority
	u8  len;			// length of payload
	u8 *pld;			// payload of length len
};


int surface_sam_ssh_consumer_register(struct device *consumer);

int surface_sam_ssh_notifier_register(u8 tc, struct notifier_block *nb);
int surface_sam_ssh_notifier_unregister(u8 tc, struct notifier_block *nb);

int surface_sam_ssh_rqst(const struct surface_sam_ssh_rqst *rqst, struct surface_sam_ssh_buf *result);

#endif /* _SURFACE_SAM_SSH_H */

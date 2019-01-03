#ifndef _SURFACEGEN5_ACPI_SSH_H
#define _SURFACEGEN5_ACPI_SSH_H

#include <linux/types.h>
#include <linux/device.h>


/*
 * Maximum request payload size in bytes.
 * Value based on ACPI (255 bytes minus header/status bytes).
 */
#define SURFACEGEN5_MAX_RQST_PAYLOAD	(255 - 10)

/*
 * Maximum response payload size in bytes.
 * Value based on ACPI (255 bytes minus header/status bytes).
 */
#define SURFACEGEN5_MAX_RQST_RESPONSE	(255 - 4)

#define SURFACEGEN5_RQID_EVENT_BITS	5

#define SURFACEGEN5_EVENT_IMMEDIATE	((unsigned long) -1)


struct surfacegen5_buf {
	u8 cap;
	u8 len;
	u8 *data;
};

struct surfacegen5_rqst {
	u8 tc;
	u8 iid;
	u8 cid;
	u8 snc;
	u8 cdl;
	u8 *pld;
};

struct surfacegen5_event {
	u16 rqid;
	u8  tc;
	u8  iid;
	u8  cid;
	u8  len;
	u8 *pld;
};


typedef int (*surfacegen5_ec_event_handler_fn)(struct surfacegen5_event *event, void *data);
typedef unsigned long (*surfacegen5_ec_event_handler_delay)(struct surfacegen5_event *event, void *data);

struct device_link *surfacegen5_ec_consumer_add(struct device *consumer, u32 flags);
int surfacegen5_ec_consumer_remove(struct device_link *link);

int surfacegen5_ec_rqst(const struct surfacegen5_rqst *rqst, struct surfacegen5_buf *result);

int surfacegen5_ec_enable_event_source(u8 tc, u8 unknown, u16 rqid);
int surfacegen5_ec_disable_event_source(u8 tc, u8 unknown, u16 rqid);
int surfacegen5_ec_remove_event_handler(u16 rqid);
int surfacegen5_ec_set_event_handler(u16 rqid, surfacegen5_ec_event_handler_fn fn, void *data);
int surfacegen5_ec_set_delayed_event_handler(u16 rqid,
		surfacegen5_ec_event_handler_fn fn,
		surfacegen5_ec_event_handler_delay delay,
		void *data);

#endif /* _SURFACEGEN5_ACPI_SSH_H */

#ifndef _SURFACEGEN5_ACPI_NOTIFY_EC_H
#define _SURFACEGEN5_ACPI_NOTIFY_EC_H


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

int surfacegen5_ec_consumer_set(struct device *consumer);
int surfacegen5_ec_consumer_remove(struct device *consumer);

int surfacegen5_ec_rqst(struct surfacegen5_rqst *rqst, struct surfacegen5_buf *result);

#endif /* _SURFACEGEN5_ACPI_NOTIFY_EC_H */

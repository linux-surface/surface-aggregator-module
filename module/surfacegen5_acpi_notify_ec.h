#ifndef _SURFACEGEN5_ACPI_NOTIFY_EC_H
#define _SURFACEGEN5_ACPI_NOTIFY_EC_H


#define SURFACEGEN5_MAX_RQST_RESPONSE	251	// 255 bytes minus header/status bytes


struct surfacegen5_buf {
	int cap;
	int len;
	u8 *pld;
};

struct surfacegen5_rqst {
	u8 tc;
	u8 iid;
	u8 cid;
	u8 snc;
	u8 cdl;
	u8 *pld;
};

int surfacegen5_ec_rqst(struct surfacegen5_rqst *rqst, struct surfacegen5_buf *result);

#endif /* _SURFACEGEN5_ACPI_NOTIFY_EC_H */

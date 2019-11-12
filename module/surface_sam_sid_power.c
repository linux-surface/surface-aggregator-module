#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include "surface_sam_ssh.h"


/*
 * Common Power-Subsystem Interface.
 */ 

struct sid_power_subsystem {
	struct mutex lock;
	// TODO
};

static struct sid_power_subsystem sid_power_subsystem = {
	.lock   = __MUTEX_INITIALIZER(sid_power_subsystem.lock),
	// TODO
};

// TODO: power-subsystem/event handler interface


/*
 * Battery Driver.
 */

#define SAM_RQST_BAT_TC			0x02

#define SAM_RQST_BAT_CID_STA		0x01
#define SAM_RQST_BAT_CID_BIX		0x02
#define SAM_RQST_BAT_CID_BST		0x03
#define SAM_RQST_BAT_CID_BTP		0x04

#define SAM_RQST_BAT_CID_PMAX		0x0b
#define SAM_RQST_BAT_CID_PSOC		0x0c
#define SAM_RQST_BAT_CID_PSRC		0x0d
#define SAM_RQST_BAT_CID_CHGI		0x0e
#define SAM_RQST_BAT_CID_ARTG		0x0f


/* Equivalent to data returned in ACPI _BIX method */
struct sid_bix {
	u8  revision;
	u32 power_unit;
	u32 design_cap;
	u32 last_full_charge_cap;
	u32 technology;
	u32 design_voltage;
	u32 design_cap_warn;
	u32 design_cap_low;
	u32 cycle_count;
	u32 measurement_accuracy;
	u32 max_sampling_time;
	u32 min_sampling_time;
	u32 max_avg_interval;
	u32 min_avg_interval;
	u32 bat_cap_granularity_1;
	u32 bat_cap_granularity_2;
	u8  model[21];
	u8  serial[11];
	u8  type[5];
	u8  oem_info[21];
} __packed;

/* Equivalent to data returned in ACPI _BST method */
struct sid_bst {
	u32 state;
	u32 present_rate;
	u32 remaining_cap;
	u32 present_voltage;
} __packed;


/* Get battery status (_STA) */
static int sam_psy_get_sta(u8 iid, u32 *sta)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_STA;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x01;
	rqst.cdl = 0x00;
	rqst.pld = NULL;

	result.cap = sizeof(u32);
	result.len = 0;
	result.data = (u8 *)sta;

	return surface_sam_ssh_rqst(&rqst, &result);
}

/* Get battery static information (_BIX) */
static int sam_psy_get_bix(u8 iid, struct sid_bix *bix)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_BIX;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x01;
	rqst.cdl = 0x00;
	rqst.pld = NULL;

	result.cap = sizeof(struct sid_bix);
	result.len = 0;
	result.data = (u8 *)bix;

	return surface_sam_ssh_rqst(&rqst, &result);
}

/* Get battery dynamic information (_BST) */
static int sam_psy_get_bst(u8 iid, struct sid_bst *bst)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_BST;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x01;
	rqst.cdl = 0x00;
	rqst.pld = NULL;

	result.cap = sizeof(struct sid_bst);
	result.len = 0;
	result.data = (u8 *)bst;

	return surface_sam_ssh_rqst(&rqst, &result);
}

/* Set battery trip point (_BTP) */
static int sam_psy_set_btp(u8 iid, u32 btp)
{
	struct surface_sam_ssh_rqst rqst;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_BTP;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x00;
	rqst.cdl = sizeof(u32);
	rqst.pld = (u8 *)&btp;

	return surface_sam_ssh_rqst(&rqst, NULL);
}

/* Get maximum platform power for battery (DPTF PMAX) */
static int sam_psy_get_pmax(u8 iid, u32 *pmax)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_PMAX;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x01;
	rqst.cdl = 0x00;
	rqst.pld = NULL;

	result.cap = sizeof(u32);
	result.len = 0;
	result.data = (u8 *)pmax;

	return surface_sam_ssh_rqst(&rqst, &result);
}

/* Get platform power soruce for battery (DPTF PSRC) */
static int sam_psy_get_psrc(u8 iid, u32 *psrc)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_PSRC;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x01;
	rqst.cdl = 0x00;
	rqst.pld = NULL;

	result.cap = sizeof(u32);
	result.len = 0;
	result.data = (u8 *)psrc;

	return surface_sam_ssh_rqst(&rqst, &result);
}

/* Get adapter rating (DPTF ARTG) */
static int sam_psy_get_artg(u8 iid, u32 *artg)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_ARTG;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x01;
	rqst.cdl = 0x00;
	rqst.pld = NULL;

	result.cap = sizeof(u32);
	result.len = 0;
	result.data = (u8 *)artg;

	return surface_sam_ssh_rqst(&rqst, &result);
}


/* Unknown (DPTF PSOC) */
static int sam_psy_get_psoc(u8 iid, u32 *psoc)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_PSOC;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x01;
	rqst.cdl = 0x00;
	rqst.pld = NULL;

	result.cap = sizeof(u32);
	result.len = 0;
	result.data = (u8 *)psoc;

	return surface_sam_ssh_rqst(&rqst, &result);
}

/* Unknown (DPTF CHGI/ INT3403 SPPC) */
static int sam_psy_set_chgi(u8 iid, u32 chgi)
{
	struct surface_sam_ssh_rqst rqst;

	rqst.tc  = SAM_RQST_BAT_TC;
	rqst.cid = SAM_RQST_BAT_CID_CHGI;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x00;
	rqst.cdl = sizeof(u32);
	rqst.pld = (u8 *)&chgi;

	return surface_sam_ssh_rqst(&rqst, NULL);
}


// To be removed...
static int test(u8 iid)
{
	struct sid_bix bix;
	struct sid_bst bst;
	u32 sta;
	int status;
	int percentage;

	status = sam_psy_get_sta(iid, &sta);
	if (status < 0) {
		printk(KERN_WARNING "sid_psy: sam_psy_get_sta failed with %d\n", status);
		return status;
	}
	printk(KERN_WARNING "sid_psy: sam_psy_get_sta returned 0x%x\n", status);

	status = sam_psy_get_bix(iid, &bix);
	if (status < 0) {
		printk(KERN_WARNING "sid_psy: sam_psy_get_bix failed with %d\n", status);
		return status;
	}

	status = sam_psy_get_bst(iid, &bst);
	if (status < 0) {
		printk(KERN_WARNING "sid_psy: sam_psy_get_bst failed with %d\n", status);
		return status;
	}

	printk(KERN_WARNING "sid_psy[%d]: bix: model: %s\n", iid, bix.model);
	printk(KERN_WARNING "sid_psy[%d]: bix: serial: %s\n", iid, bix.serial);
	printk(KERN_WARNING "sid_psy[%d]: bix: type: %s\n", iid, bix.type);
	printk(KERN_WARNING "sid_psy[%d]: bix: oem_info: %s\n", iid, bix.oem_info);

	printk(KERN_WARNING "sid_psy[%d]: bix: last_full_charge_cap: %d\n", iid, bix.last_full_charge_cap);
	printk(KERN_WARNING "sid_psy[%d]: bix: remaining_cap: %d\n", iid, bst.remaining_cap);

	percentage = (100 * bst.remaining_cap) / bix.last_full_charge_cap;
	printk(KERN_WARNING "sid_psy[%d]: remaining capacity: %d%%\n", iid, percentage);

	return 0;
}


static int surface_sam_sid_battery_probe(struct platform_device *pdev)
{
	int status;

	// link to ec
	status = surface_sam_ssh_consumer_register(&pdev->dev);
	if (status) {
		return status == -ENXIO ? -EPROBE_DEFER : status;
	}

	return test(pdev->id);	// TODO
}

static int surface_sam_sid_battery_remove(struct platform_device *pdev)
{
	return 0;	// TODO
}

struct platform_driver surface_sam_sid_battery = {
	.probe = surface_sam_sid_battery_probe,
	.remove = surface_sam_sid_battery_remove,
	.driver = {
		.name = "surface_sam_sid_battery",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


/*
 * AC Driver.
 */

static int surface_sam_sid_ac_probe(struct platform_device *pdev)
{
	int status;

	// link to ec
	status = surface_sam_ssh_consumer_register(&pdev->dev);
	if (status) {
		return status == -ENXIO ? -EPROBE_DEFER : status;
	}

	return 0;	// TODO
}

static int surface_sam_sid_ac_remove(struct platform_device *pdev)
{
	return 0;	// TODO
}

struct platform_driver surface_sam_sid_ac = {
	.probe = surface_sam_sid_ac_probe,
	.remove = surface_sam_sid_ac_remove,
	.driver = {
		.name = "surface_sam_sid_ac",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

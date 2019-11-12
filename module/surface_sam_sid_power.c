#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>

#include "surface_sam_ssh.h"


/*
 * Common Power-Subsystem Interface.
 */

enum spwr_battery_id {
	SID_BAT1,
	SID_BAT2,
	__SID_NUM_BAT,
};

struct spwr_battery_device {
	struct platform_device *pdev;
	u8 iid;
	// TODO
};

struct spwr_ac_device {
	struct platform_device *pdev;
	// TODO
};

struct spwr_subsystem {
	struct mutex lock;

	unsigned refcount;
	struct spwr_ac_device *ac;
	struct spwr_battery_device *battery[__SID_NUM_BAT];

	// TODO
};

static struct spwr_subsystem spwr_subsystem = {
	.lock   = __MUTEX_INITIALIZER(spwr_subsystem.lock),
	// TODO
};


static int spwr_subsys_init_unlocked(void)
{
	// TODO
}

static int spwr_subsys_deinit_unlocked(void)
{
	// TODO
}

static inline int spwr_subsys_ref_unlocked(void)
{
	int status = 0;

	if (!spwr_subsystem.refcount)
		status = spwr_subsys_init_unlocked();

	spwr_subsystem.refcount += 1;
	return status;
}

static inline int spwr_subsys_unref_unlocked(void)
{
	int status = 0;

	if (spwr_subsystem.refcount)
		spwr_subsystem.refcount -= 1;

	if (!spwr_subsystem.refcount)
		status = spwr_subsys_deinit_unlocked();

	return status;
}


static int spwr_register_ac(struct spwr_ac_device *ac)
{
	int status;

	mutex_lock(&spwr_subsystem.lock);
	if (spwr_subsystem.ac) {
		mutex_unlock(&spwr_subsystem.lock);
		return -EEXIST;
	}

	spwr_subsystem.ac = ac;
	status = spwr_subsys_ref_unlocked();
	mutex_unlock(&spwr_subsystem.lock);

	return status;
}

static int spwr_deregister_ac(struct spwr_ac_device *ac)
{
	int status;

	mutex_lock(&spwr_subsystem.lock);
	if (spwr_subsystem.ac != ac) {
		mutex_unlock(&spwr_subsystem.lock);
		return -EINVAL;
	}

	spwr_subsystem.ac = NULL;
	status = spwr_subsys_unref_unlocked();
	mutex_unlock(&spwr_subsystem.lock);

	return status;
}

static int spwr_register_battery(struct spwr_battery_device *bat)
{
	int status;

	if (bat->iid < 1 || bat->iid > __SID_NUM_BAT + 1)
		return -EINVAL ;

	mutex_lock(&spwr_subsystem.lock);
	if (spwr_subsystem.battery[bat->iid - 1]) {
		mutex_unlock(&spwr_subsystem.lock);
		return -EEXIST;
	}

	spwr_subsystem.battery[bat->iid - 1] = bat;
	status = spwr_subsys_ref_unlocked();
	mutex_unlock(&spwr_subsystem.lock);

	return status;
}

static int spwr_deregister_battery(struct spwr_battery_device *bat)
{
	int status;

	if (bat->iid < 1 || bat->iid > __SID_NUM_BAT + 1)
		return -EINVAL ;

	mutex_lock(&spwr_subsystem.lock);
	if (spwr_subsystem.battery[bat->iid - 1] != bat) {
		mutex_unlock(&spwr_subsystem.lock);
		return -EINVAL;
	}

	spwr_subsystem.battery[bat->iid - 1] = NULL;
	status = spwr_subsys_unref_unlocked();
	mutex_unlock(&spwr_subsystem.lock);

	return status;
}

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
struct spwr_bix {
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
struct spwr_bst {
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

	result.cap = sizeof(struct spwr_bix);
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

	result.cap = sizeof(struct spwr_bst);
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


static int surface_sam_sid_battery_probe(struct platform_device *pdev)
{
	int status;
	struct spwr_battery_device *bat;

	// link to ec
	status = surface_sam_ssh_consumer_register(&pdev->dev);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	bat = devm_kzalloc(&pdev->dev, sizeof(struct spwr_battery_device), GFP_KERNEL);
	if (!bat)
		return -ENOMEM;

	bat->pdev = pdev;
	bat->iid = pdev->id;

	status = spwr_register_battery(bat);
	if (status)
		return status;

	platform_set_drvdata(pdev, bat);
	return 0;
}

static int surface_sam_sid_battery_remove(struct platform_device *pdev)
{
	struct spwr_battery_device *bat = platform_get_drvdata(pdev);
	return spwr_deregister_battery(bat);
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
	struct spwr_ac_device *ac;

	// link to ec
	status = surface_sam_ssh_consumer_register(&pdev->dev);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	ac = devm_kzalloc(&pdev->dev, sizeof(struct spwr_ac_device), GFP_KERNEL);
	if (!ac)
		return -ENOMEM;

	ac->pdev = pdev;

	status = spwr_register_ac(ac);
	if (status)
		return status;

	platform_set_drvdata(pdev, ac);
	return 0;
}

static int surface_sam_sid_ac_remove(struct platform_device *pdev)
{
	struct spwr_ac_device *ac = platform_get_drvdata(pdev);
	return spwr_deregister_ac(ac);
}

struct platform_driver surface_sam_sid_ac = {
	.probe = surface_sam_sid_ac_probe,
	.remove = surface_sam_sid_ac_remove,
	.driver = {
		.name = "surface_sam_sid_ac",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

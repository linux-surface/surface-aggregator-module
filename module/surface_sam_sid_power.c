#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/power_supply.h>

#include "surface_sam_ssh.h"

#define SPWR_WARN	KERN_WARNING KBUILD_MODNAME ": "


// TODO: (comm) error handling strategy
// TODO: caching
// TODO: eheck BIX/BST for unknown/unsupported 0xffffffff entries
// TODO: alarm/_BTP
// TODO: DPTF?
// TODO: other properties?


/*
 * SAM Interface.
 */

#define SAM_PWR_TC			0x02
#define SAM_PWR_RQID			0x0002

#define SAM_RQST_PWR_CID_STA		0x01
#define SAM_RQST_PWR_CID_BIX		0x02
#define SAM_RQST_PWR_CID_BST		0x03
#define SAM_RQST_PWR_CID_BTP		0x04

#define SAM_RQST_PWR_CID_PMAX		0x0b
#define SAM_RQST_PWR_CID_PSOC		0x0c
#define SAM_RQST_PWR_CID_PSRC		0x0d
#define SAM_RQST_PWR_CID_CHGI		0x0e
#define SAM_RQST_PWR_CID_ARTG		0x0f

#define SAM_EVENT_PWR_CID_BIX		0x15
#define SAM_EVENT_PWR_CID_BST		0x16
#define SAM_EVENT_PWR_CID_ADAPTER	0x17
#define SAM_EVENT_PWR_CID_DPTF		0x4f

#define SAM_BATTERY_STA_OK		0x0f
#define SAM_BATTERY_STA_PRESENT		0x10

#define SAM_BATTERY_STATE_DISCHARGING	0x01
#define SAM_BATTERY_STATE_CHARGING	0x02
#define SAM_BATTERY_STATE_CRITICAL	0x04


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

/* DPTF event payload */
struct spwr_event_dptf {
	u32 pmax;
	u32 _1;		/* currently unknown */
	u32 _2;		/* currently unknown */
} __packed;


/* Get battery status (_STA) */
static int sam_psy_get_sta(u8 iid, u32 *sta)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_STA;
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
static int sam_psy_get_bix(u8 iid, struct spwr_bix *bix)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_BIX;
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
static int sam_psy_get_bst(u8 iid, struct spwr_bst *bst)
{
	struct surface_sam_ssh_rqst rqst;
	struct surface_sam_ssh_buf result;

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_BST;
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

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_BTP;
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

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_PMAX;
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

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_PSRC;
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

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_ARTG;
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

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_PSOC;
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

	rqst.tc  = SAM_PWR_TC;
	rqst.cid = SAM_RQST_PWR_CID_CHGI;
	rqst.iid = iid;
	rqst.pri = SURFACE_SAM_PRIORITY_NORMAL;
	rqst.snc = 0x00;
	rqst.cdl = sizeof(u32);
	rqst.pld = (u8 *)&chgi;

	return surface_sam_ssh_rqst(&rqst, NULL);
}


/*
 * Common Power-Subsystem Interface.
 */

enum spwr_battery_id {
	SPWR_BAT1,
	SPWR_BAT2,
	__SPWR_NUM_BAT,
};
#define SPWR_BAT_SINGLE		PLATFORM_DEVID_NONE

struct spwr_battery_device {
	struct platform_device *pdev;
	enum spwr_battery_id id;

	char name[32];
	struct power_supply *psy;
	struct power_supply_desc psy_desc;

	// TODO: caching

	struct mutex lock;

	u32 sta;
	struct spwr_bix bix;
	struct spwr_bst bst;
};

struct spwr_ac_device {
	struct platform_device *pdev;

	char name[32];
	struct power_supply *psy;
	struct power_supply_desc psy_desc;

	struct mutex lock;

	u32 state;
};

struct spwr_subsystem {
	struct mutex lock;

	unsigned refcount;
	struct spwr_ac_device *ac;
	struct spwr_battery_device *battery[__SPWR_NUM_BAT];
};

static struct spwr_subsystem spwr_subsystem = {
	.lock = __MUTEX_INITIALIZER(spwr_subsystem.lock),
};

static enum power_supply_property spwr_ac_props[] = {
	POWER_SUPPLY_PROP_ONLINE,
};

static enum power_supply_property spwr_battery_props_chg[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_CYCLE_COUNT,
	POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN,
	POWER_SUPPLY_PROP_CHARGE_FULL,
	POWER_SUPPLY_PROP_CHARGE_NOW,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_CAPACITY_LEVEL,
	POWER_SUPPLY_PROP_MODEL_NAME,
	POWER_SUPPLY_PROP_MANUFACTURER,
	POWER_SUPPLY_PROP_SERIAL_NUMBER,
};

static enum power_supply_property spwr_battery_props_eng[] = {
	POWER_SUPPLY_PROP_STATUS,
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_TECHNOLOGY,
	POWER_SUPPLY_PROP_CYCLE_COUNT,
	POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_POWER_NOW,
	POWER_SUPPLY_PROP_ENERGY_FULL_DESIGN,
	POWER_SUPPLY_PROP_ENERGY_FULL,
	POWER_SUPPLY_PROP_ENERGY_NOW,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_CAPACITY_LEVEL,
	POWER_SUPPLY_PROP_MODEL_NAME,
	POWER_SUPPLY_PROP_MANUFACTURER,
	POWER_SUPPLY_PROP_SERIAL_NUMBER,
};


inline static bool spwr_battery_present(struct spwr_battery_device *bat)
{
	return bat->sta & SAM_BATTERY_STA_PRESENT;
}


inline static int spwr_battery_update_sta(struct spwr_battery_device *bat)
{
	return sam_psy_get_sta(bat->id + 1, &bat->sta);
}

inline static int spwr_battery_update_bix(struct spwr_battery_device *bat)
{
	if (!spwr_battery_present(bat))
		return 0;

	return sam_psy_get_bix(bat->id + 1, &bat->bix);
}

inline static int spwr_battery_update_bst(struct spwr_battery_device *bat)
{
	if (!spwr_battery_present(bat))
		return 0;

	return sam_psy_get_bst(bat->id + 1, &bat->bst);
}

inline static int spwr_ac_update(struct spwr_ac_device *ac)
{
	return sam_psy_get_psrc(0x00, &ac->state);
}


static int spwr_handle_event_bix(struct surface_sam_ssh_event *event)
{
	struct spwr_battery_device *bat;
	enum spwr_battery_id bat_id = event->iid - 1;
	int status = 0;

	if (bat_id < 0 || bat_id >= __SPWR_NUM_BAT) {
		printk(SPWR_WARN "invalid BIX event iid 0x%02x\n", event->iid);
		bat_id = SPWR_BAT1;
	}

	mutex_lock(&spwr_subsystem.lock);

	bat = spwr_subsystem.battery[bat_id];
	if (bat) {
		mutex_lock(&bat->lock);

		status = spwr_battery_update_sta(bat);
		if (status)
			goto out;

		status = spwr_battery_update_bix(bat);
		if (status)
			goto out;

		status = spwr_battery_update_bst(bat);
		if (status)
			goto out;

		power_supply_changed(bat->psy);
	}

out:
	if (bat)
		mutex_unlock(&bat->lock);
	mutex_unlock(&spwr_subsystem.lock);
	return status;
}

static int spwr_handle_event_bst(struct surface_sam_ssh_event *event)
{
	struct spwr_battery_device *bat;
	enum spwr_battery_id bat_id = event->iid - 1;
	int status = 0;

	if (bat_id < 0 || bat_id >= __SPWR_NUM_BAT) {
		printk(SPWR_WARN "invalid BST event iid 0x%02x\n", event->iid);
		bat_id = SPWR_BAT1;
	}

	mutex_lock(&spwr_subsystem.lock);

	bat = spwr_subsystem.battery[bat_id];
	if (bat) {
		mutex_lock(&bat->lock);

		status = spwr_battery_update_sta(bat);
		if (status)
			goto out;

		status = spwr_battery_update_bst(bat);
		if (status)
			goto out;

		power_supply_changed(bat->psy);
	}

out:
	if (bat)
		mutex_unlock(&bat->lock);
	mutex_unlock(&spwr_subsystem.lock);
	return status;
}

static int spwr_handle_event_adapter(struct surface_sam_ssh_event *event)
{
	struct spwr_battery_device *bat1 = NULL;
	struct spwr_battery_device *bat2 = NULL;
	struct spwr_ac_device *ac;
	int status = 0;

	msleep(1000);		// TODO FIXME: trigger async battery update instead

	mutex_lock(&spwr_subsystem.lock);

	ac = spwr_subsystem.ac;
	if (ac) {
		mutex_lock(&ac->lock);
		status = spwr_ac_update(ac);
		if (status)
			goto out;

		power_supply_changed(ac->psy);
	}

	bat1 = spwr_subsystem.battery[SPWR_BAT1];
	if (bat1) {
		mutex_lock(&bat1->lock);

		status = spwr_battery_update_sta(bat1);
		if (status)
			goto out;

		status = spwr_battery_update_bst(bat1);
		if (status)
			goto out;

		power_supply_changed(bat1->psy);
	}

	bat2 = spwr_subsystem.battery[SPWR_BAT2];
	if (bat2) {
		mutex_lock(&bat2->lock);

		status = spwr_battery_update_sta(bat2);
		if (status)
			goto out;

		status = spwr_battery_update_bst(bat2);
		if (status)
			goto out;

		power_supply_changed(bat2->psy);
	}

out:
	if (bat2)
		mutex_unlock(&bat2->lock);
	if (bat1)
		mutex_unlock(&bat1->lock);
	if (ac)
		mutex_unlock(&ac->lock);
	mutex_unlock(&spwr_subsystem.lock);
	return status;
}

static int spwr_handle_event_dptf(struct surface_sam_ssh_event *event)
{
	return 0;	// TODO: spwr_handle_event_dptf
}

static int spwr_handle_event(struct surface_sam_ssh_event *event, void *data)
{
	printk(SPWR_WARN "power event (cid = 0x%02x)\n", event->cid);

	switch (event->cid) {
	case SAM_EVENT_PWR_CID_BIX:
		return spwr_handle_event_bix(event);

	case SAM_EVENT_PWR_CID_BST:
		return spwr_handle_event_bst(event);

	case SAM_EVENT_PWR_CID_ADAPTER:
		return spwr_handle_event_adapter(event);

	case SAM_EVENT_PWR_CID_DPTF:
		return spwr_handle_event_dptf(event);

	default:
		printk(SPWR_WARN "unhandled power event (cid = 0x%02x)\n", event->cid);
		return 0;
	}
}


inline static int spwr_battery_prop_status(struct spwr_battery_device *bat)
{
	if (bat->bst.state & SAM_BATTERY_STATE_DISCHARGING)
		return POWER_SUPPLY_STATUS_DISCHARGING;

	if (bat->bst.state & SAM_BATTERY_STATE_CHARGING)
		return POWER_SUPPLY_STATUS_CHARGING;

	if (bat->bix.last_full_charge_cap == bat->bst.remaining_cap)
		return POWER_SUPPLY_STATUS_FULL;

	if (bat->bst.present_rate == 0)
		return POWER_SUPPLY_STATUS_NOT_CHARGING;

	return POWER_SUPPLY_STATUS_UNKNOWN;
}

inline static int spwr_battery_prop_technology(struct spwr_battery_device *bat)
{
	if (!strcasecmp("NiCd", bat->bix.type))
		return POWER_SUPPLY_TECHNOLOGY_NiCd;

	if (!strcasecmp("NiMH", bat->bix.type))
		return POWER_SUPPLY_TECHNOLOGY_NiMH;

	if (!strcasecmp("LION", bat->bix.type))
		return POWER_SUPPLY_TECHNOLOGY_LION;

	if (!strncasecmp("LI-ION", bat->bix.type, 6))
		return POWER_SUPPLY_TECHNOLOGY_LION;

	if (!strcasecmp("LiP", bat->bix.type))
		return POWER_SUPPLY_TECHNOLOGY_LIPO;

	return POWER_SUPPLY_TECHNOLOGY_UNKNOWN;
}

inline static int spwr_battery_prop_capacity(struct spwr_battery_device *bat)
{
	if (bat->bst.remaining_cap && bat->bix.last_full_charge_cap)
		return bat->bst.remaining_cap * 100 / bat->bix.last_full_charge_cap;
	else
		return 0;
}

inline static int spwr_battery_prop_capacity_level(struct spwr_battery_device *bat)
{
	if (bat->bst.state & SAM_BATTERY_STATE_CRITICAL)
		return POWER_SUPPLY_CAPACITY_LEVEL_CRITICAL;

	if (bat->bix.last_full_charge_cap == bat->bst.remaining_cap)
		return POWER_SUPPLY_CAPACITY_LEVEL_FULL;

	return POWER_SUPPLY_CAPACITY_LEVEL_NORMAL;
}

static int spwr_ac_get_property(struct power_supply *psy,
				enum power_supply_property psp,
				union power_supply_propval *val)
{
	struct spwr_ac_device *ac = power_supply_get_drvdata(psy);
	int status;

	mutex_lock(&ac->lock);

	status = spwr_ac_update(ac);
	if (status)
		goto out;

	switch (psp) {
	case POWER_SUPPLY_PROP_ONLINE:
		val->intval = ac->state == 1;
		break;

	default:
		status = -EINVAL;
		goto out;
	}

out:
	mutex_unlock(&ac->lock);
	return status;
}

static int spwr_battery_get_property(struct power_supply *psy,
				     enum power_supply_property psp,
				     union power_supply_propval *val)
{
	struct spwr_battery_device *bat = power_supply_get_drvdata(psy);
	int status;

	mutex_lock(&bat->lock);

	// TODO: caching

	status = spwr_battery_update_sta(bat);
	if (status)
		goto out;

	status = spwr_battery_update_bix(bat);
	if (status)
		goto out;

	status = spwr_battery_update_bst(bat);
	if (status)
		goto out;

	// abort if battery is not present
	if (!spwr_battery_present(bat) && psp != POWER_SUPPLY_PROP_PRESENT) {
		status = -ENODEV;
		goto out;
	}

	switch (psp) {
	case POWER_SUPPLY_PROP_STATUS:
		val->intval = spwr_battery_prop_status(bat);
		break;

	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = spwr_battery_present(bat);
		break;

	case POWER_SUPPLY_PROP_TECHNOLOGY:
		val->intval = spwr_battery_prop_technology(bat);
		break;

	case POWER_SUPPLY_PROP_CYCLE_COUNT:
		val->intval = bat->bix.cycle_count;
		break;

	case POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN:
		val->intval = bat->bix.design_voltage * 1000;
		break;

	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		val->intval = bat->bst.present_voltage * 1000;
		break;

	case POWER_SUPPLY_PROP_CURRENT_NOW:
	case POWER_SUPPLY_PROP_POWER_NOW:
		val->intval = bat->bst.present_rate * 1000;
		break;

	case POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN:
	case POWER_SUPPLY_PROP_ENERGY_FULL_DESIGN:
		val->intval = bat->bix.design_cap * 1000;
		break;

	case POWER_SUPPLY_PROP_CHARGE_FULL:
	case POWER_SUPPLY_PROP_ENERGY_FULL:
		val->intval = bat->bix.last_full_charge_cap * 1000;
		break;

	case POWER_SUPPLY_PROP_CHARGE_NOW:
	case POWER_SUPPLY_PROP_ENERGY_NOW:
		val->intval = bat->bst.remaining_cap * 1000;
		break;

	case POWER_SUPPLY_PROP_CAPACITY:
		val->intval = spwr_battery_prop_capacity(bat);
		break;

	case POWER_SUPPLY_PROP_CAPACITY_LEVEL:
		val->intval = spwr_battery_prop_capacity_level(bat);
		break;

	case POWER_SUPPLY_PROP_MODEL_NAME:
		val->strval = bat->bix.model;
		break;

	case POWER_SUPPLY_PROP_MANUFACTURER:
		val->strval = bat->bix.oem_info;
		break;

	case POWER_SUPPLY_PROP_SERIAL_NUMBER:
		val->strval = bat->bix.serial;
		break;

	default:
		status = -EINVAL;
		goto out;
	}

out:
	mutex_unlock(&bat->lock);
	return status;
}


static int spwr_subsys_init_unlocked(void)
{
	int status;

	status = surface_sam_ssh_set_event_handler(SAM_PWR_RQID, spwr_handle_event, NULL);
	if (status) {
		goto err_handler;
	}

	status = surface_sam_ssh_enable_event_source(SAM_PWR_TC, 0x01, SAM_PWR_RQID);
	if (status) {
		goto err_source;
	}

	return 0;

err_source:
	surface_sam_ssh_remove_event_handler(SAM_PWR_RQID);
err_handler:
	return status;
}

static int spwr_subsys_deinit_unlocked(void)
{
	surface_sam_ssh_disable_event_source(SAM_PWR_TC, 0x01, SAM_PWR_RQID);
	surface_sam_ssh_remove_event_handler(SAM_PWR_RQID);
	return 0;
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


static int spwr_ac_register(struct spwr_ac_device *ac, struct platform_device *pdev)
{
	struct power_supply_config psy_cfg = {};
	u32 sta;
	int status;

	// make sure the device is there and functioning properly
	status = sam_psy_get_sta(0x00, &sta);
	if (status)
		return status;

	if ((sta & SAM_BATTERY_STA_OK) != SAM_BATTERY_STA_OK)
		return -ENODEV;

	psy_cfg.drv_data = ac;

	ac->pdev = pdev;
	mutex_init(&ac->lock);

	snprintf(ac->name, ARRAY_SIZE(ac->name), "surface_adp");

	ac->psy_desc.name = ac->name;
	ac->psy_desc.type = POWER_SUPPLY_TYPE_MAINS;
	ac->psy_desc.properties = spwr_ac_props;
	ac->psy_desc.num_properties = ARRAY_SIZE(spwr_ac_props);
	ac->psy_desc.get_property = spwr_ac_get_property;

	mutex_lock(&spwr_subsystem.lock);
	if (spwr_subsystem.ac) {
		status = -EEXIST;
		goto err;
	}

	status = spwr_subsys_ref_unlocked();
	if (status)
		goto err;

	ac->psy = power_supply_register(&ac->pdev->dev, &ac->psy_desc, &psy_cfg);
	if (IS_ERR(ac->psy)) {
		status = PTR_ERR(ac->psy);
		goto err_unref;
	}

	spwr_subsystem.ac = ac;
	mutex_unlock(&spwr_subsystem.lock);
	return 0;

err_unref:
	spwr_subsys_unref_unlocked();
err:
	mutex_unlock(&spwr_subsystem.lock);
	mutex_destroy(&ac->lock);
	return status;
}

static int spwr_ac_unregister(struct spwr_ac_device *ac)
{
	int status;

	mutex_lock(&spwr_subsystem.lock);
	if (spwr_subsystem.ac != ac) {
		mutex_unlock(&spwr_subsystem.lock);
		return -EINVAL;
	}

	spwr_subsystem.ac = NULL;
	power_supply_unregister(ac->psy);

	status = spwr_subsys_unref_unlocked();
	mutex_unlock(&spwr_subsystem.lock);

	mutex_destroy(&ac->lock);
	return status;
}

static int spwr_battery_register(struct spwr_battery_device *bat, struct platform_device *pdev,
				 enum spwr_battery_id id)
{
	struct power_supply_config psy_cfg = {};
	u32 sta;
	int status;

	if ((id < 0 || id >= __SPWR_NUM_BAT) && id != SPWR_BAT_SINGLE)
		return -EINVAL;

	// make sure the device is there and functioning properly
	status = sam_psy_get_sta(id + 1, &sta);
	if (status)
		return status;

	if ((sta & SAM_BATTERY_STA_OK) != SAM_BATTERY_STA_OK)
		return -ENODEV;

	psy_cfg.drv_data = bat;

	bat->pdev = pdev;
	bat->id = id != SPWR_BAT_SINGLE ? id : SPWR_BAT1;
	mutex_init(&bat->lock);

	if (id == SPWR_BAT_SINGLE)
		snprintf(bat->name, ARRAY_SIZE(bat->name), "surface_bat");
	else
		snprintf(bat->name, ARRAY_SIZE(bat->name), "surface_bat%d", id);

	bat->psy_desc.name = bat->name;
	bat->psy_desc.type = POWER_SUPPLY_TYPE_BATTERY;

	// TODO: switch battery props based on units
	bat->psy_desc.properties = spwr_battery_props_eng;
	bat->psy_desc.num_properties = ARRAY_SIZE(spwr_battery_props_eng);

	bat->psy_desc.get_property = spwr_battery_get_property;

	mutex_lock(&spwr_subsystem.lock);
	if (spwr_subsystem.battery[bat->id]) {
		status = -EEXIST;
		goto err;
	}

	status = spwr_subsys_ref_unlocked();
	if (status)
		goto err;

	bat->psy = power_supply_register(&bat->pdev->dev, &bat->psy_desc, &psy_cfg);
	if (IS_ERR(bat->psy)) {
		status = PTR_ERR(bat->psy);
		goto err_unref;
	}

	spwr_subsystem.battery[bat->id] = bat;
	mutex_unlock(&spwr_subsystem.lock);
	return 0;

err_unref:
	spwr_subsys_unref_unlocked();
err:
	mutex_unlock(&spwr_subsystem.lock);
	return status;
}

static int spwr_battery_unregister(struct spwr_battery_device *bat)
{
	int status;

	if (bat->id < 0 || bat->id >= __SPWR_NUM_BAT)
		return -EINVAL ;

	mutex_lock(&spwr_subsystem.lock);
	if (spwr_subsystem.battery[bat->id] != bat) {
		mutex_unlock(&spwr_subsystem.lock);
		return -EINVAL;
	}

	spwr_subsystem.battery[bat->id] = NULL;
	power_supply_unregister(bat->psy);

	status = spwr_subsys_unref_unlocked();
	mutex_unlock(&spwr_subsystem.lock);

	mutex_destroy(&bat->lock);
	return status;
}


/*
 * Battery Driver.
 */

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

	status = spwr_battery_register(bat, pdev, pdev->id);
	if (status)
		return status;

	platform_set_drvdata(pdev, bat);
	return 0;
}

static int surface_sam_sid_battery_remove(struct platform_device *pdev)
{
	struct spwr_battery_device *bat = platform_get_drvdata(pdev);
	return spwr_battery_unregister(bat);
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

	status = spwr_ac_register(ac, pdev);
	if (status)
		return status;

	platform_set_drvdata(pdev, ac);
	return 0;
}

static int surface_sam_sid_ac_remove(struct platform_device *pdev)
{
	struct spwr_ac_device *ac = platform_get_drvdata(pdev);
	return spwr_ac_unregister(ac);
}

struct platform_driver surface_sam_sid_ac = {
	.probe = surface_sam_sid_ac_probe,
	.remove = surface_sam_sid_ac_remove,
	.driver = {
		.name = "surface_sam_sid_ac",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

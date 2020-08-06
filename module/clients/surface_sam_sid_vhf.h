
#ifndef _SURFACE_SAM_SID_VHF_H
#define _SURFACE_SAM_SID_VHF_H

#include <linux/surface_aggregator_module.h>
#include <linux/types.h>


struct ssam_hid_properties {
	struct ssam_event_registry registry;
	u8 instance;
};

#endif /* _SURFACE_SAM_SID_VHF_H */


#ifndef _SURFACE_SAM_SGCP_H
#define _SURFACE_SAM_SGCP_H

#include <linux/types.h>

typedef void (*surface_sam_sgcp_handler_fn)(int event, void *data);


void surface_sam_sgcp_register_notification(surface_sam_sgcp_handler_fn handler, void *data);


#endif /* _SURFACE_SAM_SGCP_H */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM surface_sam_ssh

#if !defined(_SURFACE_SAM_SSH_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SURFACE_SAM_SSH_TRACE_H

#include <linux/tracepoint.h>

#include "surface_sam_ssh.h"


#define SSAM_PTR_UID_LEN		9
#define SSAM_SEQ_NOT_APPLICABLE		((u16)-1)


#ifndef _SURFACE_SAM_SSH_TRACE_HELPERS
#define _SURFACE_SAM_SSH_TRACE_HELPERS

static inline void ssam_trace_ptr_uid(const void *ptr, char* uid_str)
{
	char buf[2 * sizeof(void*) + 1];

	snprintf(buf, ARRAY_SIZE(buf), "%p", ptr);
	memcpy(uid_str, &buf[ARRAY_SIZE(buf) - SSAM_PTR_UID_LEN],
	       SSAM_PTR_UID_LEN);
}

static inline u16 ssam_trace_get_packet_seq(const struct ssh_packet *packet)
{
	if (!packet->data || packet->data_length < SSH_MESSAGE_LENGTH(0))
		return SSAM_SEQ_NOT_APPLICABLE;

	return packet->data[SSH_MSGOFFSET_FRAME(seq)];
}

#endif /* _SURFACE_SAM_SSH_TRACE_HELPERS */


#define ssam_show_packet_type(type)				\
	__print_flags(type, "",					\
		{ SSH_PACKET_TY_FLUSH,			"F" },	\
		{ SSH_PACKET_TY_SEQUENCED,		"S" },	\
		{ SSH_PACKET_TY_BLOCKING,		"B" }	\
	)

#define ssam_show_packet_state(state)				\
	__print_flags(state, "",				\
		{ BIT(SSH_PACKET_SF_LOCKED_BIT), 	"L" },	\
		{ BIT(SSH_PACKET_SF_QUEUED_BIT), 	"Q" },	\
		{ BIT(SSH_PACKET_SF_PENDING_BIT), 	"P" },	\
		{ BIT(SSH_PACKET_SF_TRANSMITTING_BIT), 	"S" },	\
		{ BIT(SSH_PACKET_SF_TRANSMITTED_BIT), 	"T" },	\
		{ BIT(SSH_PACKET_SF_ACKED_BIT), 	"A" },	\
		{ BIT(SSH_PACKET_SF_CANCELED_BIT), 	"C" },	\
		{ BIT(SSH_PACKET_SF_COMPLETED_BIT), 	"F" }	\
	)

#define ssam_show_packet_seq(seq)				\
	__print_symbolic(seq,					\
		{ SSAM_SEQ_NOT_APPLICABLE, 		"N/A" }	\
	)

DECLARE_EVENT_CLASS(ssam_packet_class,
	TP_PROTO(const struct ssh_packet *packet),

	TP_ARGS(packet),

	TP_STRUCT__entry(
		__array(char, uid, SSAM_PTR_UID_LEN)
		__field(u8, type)
		__field(u8, priority)
		__field(u16, length)
		__field(unsigned long, state)
		__field(u16, seq)
	),

	TP_fast_assign(
		ssam_trace_ptr_uid(packet, __entry->uid);
		__entry->type = packet->type;
		__entry->priority = READ_ONCE(packet->priority);
		__entry->length = packet->data_length;
		__entry->state = READ_ONCE(packet->state);
		__entry->seq = ssam_trace_get_packet_seq(packet);
	),

	TP_printk("uid=%s, seq=%s, ty=%s, pri=0x%02x, len=%u, sta=%s",
		__entry->uid,
		ssam_show_packet_seq(__entry->seq),
		ssam_show_packet_type(__entry->type),
		__entry->priority,
		__entry->length,
		ssam_show_packet_state(__entry->state)
	)
);

#define DEFINE_SSAM_PACKET_EVENT(name)				\
	DEFINE_EVENT(ssam_packet_class, ssam_packet_##name,	\
		TP_PROTO(const struct ssh_packet *packet),	\
		TP_ARGS(packet)					\
	)


// TODO

#endif /* _SURFACE_SAM_SSH_TRACE_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE

#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE surface_sam_ssh_trace

#include <trace/define_trace.h>

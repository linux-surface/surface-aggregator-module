// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface Serial Hub (SSH) driver for communication with the Surface/System
 * Aggregator Module.
 */

#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pm.h>
#include <linux/refcount.h>
#include <linux/rwsem.h>
#include <linux/serdev.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include <linux/surface_aggregator_module.h>

#include "ssh_msgb.h"
#include "ssh_protocol.h"
#include "ssh_parser.h"
#include "ssh_packet_layer.h"

#define CREATE_TRACE_POINTS
#include "ssam_trace.h"


/* -- Safe counters. -------------------------------------------------------- */

struct ssh_seq_counter {
	u8 value;
};

struct ssh_rqid_counter {
	u16 value;
};

static inline void ssh_seq_reset(struct ssh_seq_counter *c)
{
	WRITE_ONCE(c->value, 0);
}

static inline u8 ssh_seq_next(struct ssh_seq_counter *c)
{
	u8 old = READ_ONCE(c->value);
	u8 new = old + 1;
	u8 ret;

	while (unlikely((ret = cmpxchg(&c->value, old, new)) != old)) {
		old = ret;
		new = old + 1;
	}

	return old;
}

static inline void ssh_rqid_reset(struct ssh_rqid_counter *c)
{
	WRITE_ONCE(c->value, 0);
}

static inline u16 ssh_rqid_next(struct ssh_rqid_counter *c)
{
	u16 old = READ_ONCE(c->value);
	u16 new = ssh_rqid_next_valid(old);
	u16 ret;

	while (unlikely((ret = cmpxchg(&c->value, old, new)) != old)) {
		old = ret;
		new = ssh_rqid_next_valid(old);
	}

	return old;
}


/* -- Request transport layer (rtl). ---------------------------------------- */

#define SSH_RTL_REQUEST_TIMEOUT			ms_to_ktime(3000)
#define SSH_RTL_REQUEST_TIMEOUT_RESOLUTION	ms_to_ktime(max(2000 / HZ, 50))

#define SSH_RTL_MAX_PENDING		3


enum ssh_rtl_state_flags {
	SSH_RTL_SF_SHUTDOWN_BIT,
};

struct ssh_rtl_ops {
	void (*handle_event)(struct ssh_rtl *rtl, const struct ssh_command *cmd,
			     const struct ssam_span *data);
};

struct ssh_rtl {
	struct ssh_ptl ptl;
	unsigned long state;

	struct {
		spinlock_t lock;
		struct list_head head;
	} queue;

	struct {
		spinlock_t lock;
		struct list_head head;
		atomic_t count;
	} pending;

	struct {
		struct work_struct work;
	} tx;

	struct {
		ktime_t timeout;
		ktime_t expires;
		struct delayed_work reaper;
	} rtx_timeout;

	struct ssh_rtl_ops ops;
};


#define rtl_dbg(r, fmt, ...)  ptl_dbg(&(r)->ptl, fmt, ##__VA_ARGS__)
#define rtl_info(p, fmt, ...) ptl_info(&(p)->ptl, fmt, ##__VA_ARGS__)
#define rtl_warn(r, fmt, ...) ptl_warn(&(r)->ptl, fmt, ##__VA_ARGS__)
#define rtl_err(r, fmt, ...)  ptl_err(&(r)->ptl, fmt, ##__VA_ARGS__)
#define rtl_dbg_cond(r, fmt, ...) __ssam_prcond(rtl_dbg, r, fmt, ##__VA_ARGS__)

#define to_ssh_rtl(ptr, member) \
	container_of(ptr, struct ssh_rtl, member)

#define to_ssh_request(ptr, member) \
	container_of(ptr, struct ssh_request, member)

static inline struct ssh_rtl *ssh_request_rtl(struct ssh_request *rqst)
{
	struct ssh_ptl *ptl = READ_ONCE(rqst->packet.ptl);
	return likely(ptl) ? to_ssh_rtl(ptl, ptl) : NULL;
}


#ifdef CONFIG_SURFACE_SAM_SSH_ERROR_INJECTION

/**
 * ssh_rtl_should_drop_response - error injection hook to drop request responses
 *
 * Useful to cause request transmission timeouts in the driver by dropping the
 * response to a request.
 */
static noinline bool ssh_rtl_should_drop_response(void)
{
	return false;
}
ALLOW_ERROR_INJECTION(ssh_rtl_should_drop_response, TRUE);

#else

static inline bool ssh_rtl_should_drop_response(void)
{
	return false;
}

#endif


static inline u16 ssh_request_get_rqid(struct ssh_request *rqst)
{
	return get_unaligned_le16(rqst->packet.data.ptr
				  + SSH_MSGOFFSET_COMMAND(rqid));
}

static inline u32 ssh_request_get_rqid_safe(struct ssh_request *rqst)
{
	if (!rqst->packet.data.ptr)
		return -1;

	return ssh_request_get_rqid(rqst);
}


static void ssh_rtl_queue_remove(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);
	bool remove;

	spin_lock(&rtl->queue.lock);

	remove = test_and_clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &rqst->state);
	if (remove)
		list_del(&rqst->node);

	spin_unlock(&rtl->queue.lock);

	if (remove)
		ssh_request_put(rqst);
}

static void ssh_rtl_pending_remove(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);
	bool remove;

	spin_lock(&rtl->pending.lock);

	remove = test_and_clear_bit(SSH_REQUEST_SF_PENDING_BIT, &rqst->state);
	if (remove) {
		atomic_dec(&rtl->pending.count);
		list_del(&rqst->node);
	}

	spin_unlock(&rtl->pending.lock);

	if (remove)
		ssh_request_put(rqst);
}


static void ssh_rtl_complete_with_status(struct ssh_request *rqst, int status)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);

	trace_ssam_request_complete(rqst, status);

	// rtl/ptl may not be set if we're cancelling before submitting
	rtl_dbg_cond(rtl, "rtl: completing request (rqid: 0x%04x,"
		     " status: %d)\n", ssh_request_get_rqid_safe(rqst), status);

	if (status && status != -ECANCELED)
		rtl_dbg_cond(rtl, "rtl: request error: %d\n", status);

	rqst->ops->complete(rqst, NULL, NULL, status);
}

static void ssh_rtl_complete_with_rsp(struct ssh_request *rqst,
				      const struct ssh_command *cmd,
				      const struct ssam_span *data)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);

	trace_ssam_request_complete(rqst, 0);

	rtl_dbg(rtl, "rtl: completing request with response"
		" (rqid: 0x%04x)\n", ssh_request_get_rqid(rqst));

	rqst->ops->complete(rqst, cmd, data, 0);
}


static bool ssh_rtl_tx_can_process(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);

	if (test_bit(SSH_REQUEST_TY_FLUSH_BIT, &rqst->state))
		return !atomic_read(&rtl->pending.count);

	return atomic_read(&rtl->pending.count) < SSH_RTL_MAX_PENDING;
}

static struct ssh_request *ssh_rtl_tx_next(struct ssh_rtl *rtl)
{
	struct ssh_request *rqst = ERR_PTR(-ENOENT);
	struct ssh_request *p, *n;

	spin_lock(&rtl->queue.lock);

	// find first non-locked request and remove it
	list_for_each_entry_safe(p, n, &rtl->queue.head, node) {
		if (unlikely(test_bit(SSH_REQUEST_SF_LOCKED_BIT, &p->state)))
			continue;

		if (!ssh_rtl_tx_can_process(p)) {
			rqst = ERR_PTR(-EBUSY);
			break;
		}

		/*
		 * Remove from queue and mark as transmitting. Ensure that the
		 * state does not get zero via memory barrier.
		 */
		set_bit(SSH_REQUEST_SF_TRANSMITTING_BIT, &p->state);
		smp_mb__before_atomic();
		clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &p->state);

		list_del(&p->node);

		rqst = p;
		break;
	}

	spin_unlock(&rtl->queue.lock);
	return rqst;
}

static int ssh_rtl_tx_pending_push(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);

	spin_lock(&rtl->pending.lock);

	if (test_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state)) {
		spin_unlock(&rtl->pending.lock);
		return -EINVAL;
	}

	if (test_and_set_bit(SSH_REQUEST_SF_PENDING_BIT, &rqst->state)) {
		spin_unlock(&rtl->pending.lock);
		return -EALREADY;
	}

	atomic_inc(&rtl->pending.count);
	ssh_request_get(rqst);
	list_add_tail(&rqst->node, &rtl->pending.head);

	spin_unlock(&rtl->pending.lock);
	return 0;
}

static int ssh_rtl_tx_try_process_one(struct ssh_rtl *rtl)
{
	struct ssh_request *rqst;
	int status;

	// get and prepare next request for transmit
	rqst = ssh_rtl_tx_next(rtl);
	if (IS_ERR(rqst))
		return PTR_ERR(rqst);

	// add to/mark as pending
	status = ssh_rtl_tx_pending_push(rqst);
	if (status) {
		ssh_request_put(rqst);
		return -EAGAIN;
	}

	// submit packet
	status = ssh_ptl_submit(&rtl->ptl, &rqst->packet);
	if (status == -ESHUTDOWN) {
		/*
		 * Packet has been refused due to the packet layer shutting
		 * down. Complete it here.
		 */
		set_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state);
		smp_mb__after_atomic();

		ssh_rtl_pending_remove(rqst);
		ssh_rtl_complete_with_status(rqst, -ESHUTDOWN);

		ssh_request_put(rqst);
		return -ESHUTDOWN;

	} else if (status) {
		/*
		 * If submitting the packet failed and the packet layer isn't
		 * shutting down, the packet has either been submmitted/queued
		 * before (-EALREADY, which cannot happen as we have guaranteed
		 * that requests cannot be re-submitted), or the packet was
		 * marked as locked (-EINVAL). To mark the packet locked at this
		 * stage, the request, and thus the packets itself, had to have
		 * been canceled. Simply drop the reference. Cancellation itself
		 * will remove it from the set of pending requests.
		 */

		WARN_ON(status != -EINVAL);

		ssh_request_put(rqst);
		return -EAGAIN;
	}

	ssh_request_put(rqst);
	return 0;
}

static bool ssh_rtl_queue_empty(struct ssh_rtl *rtl)
{
	bool empty;

	spin_lock(&rtl->queue.lock);
	empty = list_empty(&rtl->queue.head);
	spin_unlock(&rtl->queue.lock);

	return empty;
}

static bool ssh_rtl_tx_schedule(struct ssh_rtl *rtl)
{
	if (atomic_read(&rtl->pending.count) >= SSH_RTL_MAX_PENDING)
		return false;

	if (ssh_rtl_queue_empty(rtl))
		return false;

	return schedule_work(&rtl->tx.work);
}

static void ssh_rtl_tx_work_fn(struct work_struct *work)
{
	struct ssh_rtl *rtl = to_ssh_rtl(work, tx.work);
	int i, status;

	/*
	 * Try to be nice and not block the workqueue: Run a maximum of 10
	 * tries, then re-submit if necessary. This should not be neccesary,
	 * for normal execution, but guarantee it anyway.
	 */
	for (i = 0; i < 10; i++) {
		status = ssh_rtl_tx_try_process_one(rtl);
		if (status == -ENOENT || status == -EBUSY)
			return;		// no more requests to process

		if (status == -ESHUTDOWN) {
			/*
			 * Packet system shutting down. No new packets can be
			 * transmitted. Return silently, the party initiating
			 * the shutdown should handle the rest.
			 */
			return;
		}

		WARN_ON(status != 0 && status != -EAGAIN);
	}

	// out of tries, reschedule
	ssh_rtl_tx_schedule(rtl);
}


static int ssh_rtl_submit(struct ssh_rtl *rtl, struct ssh_request *rqst)
{
	trace_ssam_request_submit(rqst);

	/*
	 * Ensure that requests expecting a response are sequenced. If this
	 * invariant ever changes, see the comment in ssh_rtl_complete on what
	 * is required to be changed in the code.
	 */
	if (test_bit(SSH_REQUEST_TY_HAS_RESPONSE_BIT, &rqst->state))
		if (!test_bit(SSH_PACKET_TY_SEQUENCED_BIT, &rqst->packet.state))
			return -EINVAL;

	// try to set ptl and check if this request has already been submitted
	if (cmpxchg(&rqst->packet.ptl, NULL, &rtl->ptl) != NULL)
		return -EALREADY;

	spin_lock(&rtl->queue.lock);

	if (test_bit(SSH_RTL_SF_SHUTDOWN_BIT, &rtl->state)) {
		spin_unlock(&rtl->queue.lock);
		return -ESHUTDOWN;
	}

	if (test_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state)) {
		spin_unlock(&rtl->queue.lock);
		return -EINVAL;
	}

	ssh_request_get(rqst);
	set_bit(SSH_REQUEST_SF_QUEUED_BIT, &rqst->state);
	list_add_tail(&rqst->node, &rtl->queue.head);

	spin_unlock(&rtl->queue.lock);

	ssh_rtl_tx_schedule(rtl);
	return 0;
}


static void ssh_rtl_timeout_reaper_mod(struct ssh_rtl *rtl, ktime_t now,
				       ktime_t expires)
{
	unsigned long delta = msecs_to_jiffies(ktime_ms_delta(expires, now));
	ktime_t aexp = ktime_add(expires, SSH_RTL_REQUEST_TIMEOUT_RESOLUTION);
	ktime_t old;

	// re-adjust / schedule reaper if it is above resolution delta
	old = READ_ONCE(rtl->rtx_timeout.expires);
	while (ktime_before(aexp, old))
		old = cmpxchg64(&rtl->rtx_timeout.expires, old, expires);

	// if we updated the reaper expiration, modify work timeout
	if (old == expires)
		mod_delayed_work(system_wq, &rtl->rtx_timeout.reaper, delta);
}

static void ssh_rtl_timeout_start(struct ssh_request *rqst)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);
	ktime_t timestamp = ktime_get_coarse_boottime();
	ktime_t timeout = rtl->rtx_timeout.timeout;

	if (test_bit(SSH_REQUEST_SF_LOCKED_BIT, &rqst->state))
		return;

	WRITE_ONCE(rqst->timestamp, timestamp);
	smp_mb__after_atomic();

	ssh_rtl_timeout_reaper_mod(rtl, timestamp, timestamp + timeout);
}


static void ssh_rtl_complete(struct ssh_rtl *rtl,
			     const struct ssh_command *command,
			     const struct ssam_span *command_data)
{
	struct ssh_request *r = NULL;
	struct ssh_request *p, *n;
	u16 rqid = get_unaligned_le16(&command->rqid);

	trace_ssam_rx_response_received(command, command_data->len);

	/*
	 * Get request from pending based on request ID and mark it as response
	 * received and locked.
	 */
	spin_lock(&rtl->pending.lock);
	list_for_each_entry_safe(p, n, &rtl->pending.head, node) {
		// we generally expect requests to be processed in order
		if (unlikely(ssh_request_get_rqid(p) != rqid))
			continue;

		// simulate response timeout
		if (ssh_rtl_should_drop_response()) {
			spin_unlock(&rtl->pending.lock);

			trace_ssam_ei_rx_drop_response(p);
			rtl_info(rtl, "request error injection: "
				 "dropping response for request %p\n",
				 &p->packet);
			return;
		}

		/*
		 * Mark as "response received" and "locked" as we're going to
		 * complete it. Ensure that the state doesn't get zero by
		 * employing a memory barrier.
		 */
		set_bit(SSH_REQUEST_SF_LOCKED_BIT, &p->state);
		set_bit(SSH_REQUEST_SF_RSPRCVD_BIT, &p->state);
		smp_mb__before_atomic();
		clear_bit(SSH_REQUEST_SF_PENDING_BIT, &p->state);

		atomic_dec(&rtl->pending.count);
		list_del(&p->node);

		r = p;
		break;
	}
	spin_unlock(&rtl->pending.lock);

	if (!r) {
		rtl_warn(rtl, "rtl: dropping unexpected command message"
			 " (rqid = 0x%04x)\n", rqid);
		return;
	}

	// if the request hasn't been completed yet, we will do this now
	if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state)) {
		ssh_request_put(r);
		ssh_rtl_tx_schedule(rtl);
		return;
	}

	/*
	 * Make sure the request has been transmitted. In case of a sequenced
	 * request, we are guaranteed that the completion callback will run on
	 * the receiver thread directly when the ACK for the packet has been
	 * received. Similarly, this function is guaranteed to run on the
	 * receiver thread. Thus we are guaranteed that if the packet has been
	 * successfully transmitted and received an ACK, the transmitted flag
	 * has been set and is visible here.
	 *
	 * We are currently not handling unsequenced packets here, as those
	 * should never expect a response as ensured in ssh_rtl_submit. If this
	 * ever changes, one would have to test for
	 *
	 * 	(r->state & (transmitting | transmitted))
	 *
	 * on unsequenced packets to determine if they could have been
	 * transmitted. There are no synchronization guarantees as in the
	 * sequenced case, since, in this case, the callback function will not
	 * run on the same thread. Thus an exact determination is impossible.
	 */
	if (!test_bit(SSH_REQUEST_SF_TRANSMITTED_BIT, &r->state)) {
		rtl_err(rtl, "rtl: received response before ACK for request"
			" (rqid = 0x%04x)\n", rqid);

		/*
		 * NB: Timeout has already been canceled, request already been
		 * removed from pending and marked as locked and completed. As
		 * we receive a "false" response, the packet might still be
		 * queued though.
		 */
		ssh_rtl_queue_remove(r);

		ssh_rtl_complete_with_status(r, -EREMOTEIO);
		ssh_request_put(r);

		ssh_rtl_tx_schedule(rtl);
		return;
	}

	/*
	 * NB: Timeout has already been canceled, request already been
	 * removed from pending and marked as locked and completed. The request
	 * can also not be queued any more, as it has been marked as
	 * transmitting and later transmitted. Thus no need to remove it from
	 * anywhere.
	 */

	ssh_rtl_complete_with_rsp(r, command, command_data);
	ssh_request_put(r);

	ssh_rtl_tx_schedule(rtl);
}


static bool ssh_rtl_cancel_nonpending(struct ssh_request *r)
{
	struct ssh_rtl *rtl;
	unsigned long state, fixed;
	bool remove;

	/*
	 * Handle unsubmitted request: Try to mark the packet as locked,
	 * expecting the state to be zero (i.e. unsubmitted). Note that, if
	 * setting the state worked, we might still be adding the packet to the
	 * queue in a currently executing submit call. In that case, however,
	 * ptl reference must have been set previously, as locked is checked
	 * after setting ptl. Thus only if we successfully lock this request and
	 * ptl is NULL, we have successfully removed the request.
	 * Otherwise we need to try and grab it from the queue.
	 *
	 * Note that if the CMPXCHG fails, we are guaranteed that ptl has
	 * been set and is non-NULL, as states can only be nonzero after this
	 * has been set. Also note that we need to fetch the static (type) flags
         * to ensure that they don't cause the cmpxchg to fail.
	 */
        fixed = READ_ONCE(r->state) & SSH_REQUEST_FLAGS_TY_MASK;
	state = cmpxchg(&r->state, fixed, SSH_REQUEST_SF_LOCKED_BIT);
	if (!state && !READ_ONCE(r->packet.ptl)) {
		if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			return true;

		ssh_rtl_complete_with_status(r, -ECANCELED);
		return true;
	}

	rtl = ssh_request_rtl(r);
	spin_lock(&rtl->queue.lock);

	/*
	 * Note: 1) Requests cannot be re-submitted. 2) If a request is queued,
	 * it cannot be "transmitting"/"pending" yet. Thus, if we successfully
	 * remove the the request here, we have removed all its occurences in
	 * the system.
	 */

	remove = test_and_clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &r->state);
	if (!remove) {
		spin_unlock(&rtl->queue.lock);
		return false;
	}

	set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
	list_del(&r->node);

	spin_unlock(&rtl->queue.lock);

	ssh_request_put(r);	// drop reference obtained from queue

	if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
		return true;

	ssh_rtl_complete_with_status(r, -ECANCELED);
	return true;
}

static bool ssh_rtl_cancel_pending(struct ssh_request *r)
{
	// if the packet is already locked, it's going to be removed shortly
	if (test_and_set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state))
		return true;

	/*
	 * Now that we have locked the packet, we have guaranteed that it can't
	 * be added to the system any more. If rtl is zero, the locked
	 * check in ssh_rtl_submit has not been run and any submission,
	 * currently in progress or called later, won't add the packet. Thus we
	 * can directly complete it.
	 */
	if (!ssh_request_rtl(r)) {
		if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			return true;

		ssh_rtl_complete_with_status(r, -ECANCELED);
		return true;
	}

	/*
	 * Try to cancel the packet. If the packet has not been completed yet,
	 * this will subsequently (and synchronously) call the completion
	 * callback of the packet, which will complete the request.
	 */
	ssh_ptl_cancel(&r->packet);

	/*
	 * If the packet has been completed with success, i.e. has not been
	 * canceled by the above call, the request may not have been completed
	 * yet (may be waiting for a response). Check if we need to do this
	 * here.
	 */
	if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
		return true;

	ssh_rtl_queue_remove(r);
	ssh_rtl_pending_remove(r);
	ssh_rtl_complete_with_status(r, -ECANCELED);

	return true;
}

static bool ssh_rtl_cancel(struct ssh_request *rqst, bool pending)
{
	struct ssh_rtl *rtl;
	bool canceled;

	if (test_and_set_bit(SSH_REQUEST_SF_CANCELED_BIT, &rqst->state))
		return true;

	trace_ssam_request_cancel(rqst);

	if (pending)
		canceled = ssh_rtl_cancel_pending(rqst);
	else
		canceled = ssh_rtl_cancel_nonpending(rqst);

	// note: rtl may be NULL if request has not been submitted yet
	rtl = ssh_request_rtl(rqst);
	if (canceled && rtl)
		ssh_rtl_tx_schedule(rtl);

	return canceled;
}


static void ssh_rtl_packet_callback(struct ssh_packet *p, int status)
{
	struct ssh_request *r = to_ssh_request(p, packet);

	if (unlikely(status)) {
		set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);

		if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			return;

		/*
		 * The packet may get cancelled even though it has not been
		 * submitted yet. The request may still be queued. Check the
		 * queue and remove it if necessary. As the timeout would have
		 * been started in this function on success, there's no need to
		 * cancel it here.
		 */
		ssh_rtl_queue_remove(r);
		ssh_rtl_pending_remove(r);
		ssh_rtl_complete_with_status(r, status);

		ssh_rtl_tx_schedule(ssh_request_rtl(r));
		return;
	}

	/*
	 * Mark as transmitted, ensure that state doesn't get zero by inserting
	 * a memory barrier.
	 */
	set_bit(SSH_REQUEST_SF_TRANSMITTED_BIT, &r->state);
	smp_mb__before_atomic();
	clear_bit(SSH_REQUEST_SF_TRANSMITTING_BIT, &r->state);

	// if we expect a response, we just need to start the timeout
	if (test_bit(SSH_REQUEST_TY_HAS_RESPONSE_BIT, &r->state)) {
		ssh_rtl_timeout_start(r);
		return;
	}

	/*
	 * If we don't expect a response, lock, remove, and complete the
	 * request. Note that, at this point, the request is guaranteed to have
	 * left the queue and no timeout has been started. Thus we only need to
	 * remove it from pending. If the request has already been completed (it
	 * may have been canceled) return.
	 */

	set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
	if (test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
		return;

	ssh_rtl_pending_remove(r);
	ssh_rtl_complete_with_status(r, 0);

	ssh_rtl_tx_schedule(ssh_request_rtl(r));
}


static ktime_t ssh_request_get_expiration(struct ssh_request *r, ktime_t timeo)
{
	ktime_t timestamp = READ_ONCE(r->timestamp);

	if (timestamp != KTIME_MAX)
		return ktime_add(timestamp, timeo);
	else
		return KTIME_MAX;
}

static void ssh_rtl_timeout_reap(struct work_struct *work)
{
	struct ssh_rtl *rtl = to_ssh_rtl(work, rtx_timeout.reaper.work);
	struct ssh_request *r, *n;
	LIST_HEAD(claimed);
	ktime_t now = ktime_get_coarse_boottime();
	ktime_t timeout = rtl->rtx_timeout.timeout;
	ktime_t next = KTIME_MAX;

	trace_ssam_rtl_timeout_reap("pending", atomic_read(&rtl->pending.count));

	/*
	 * Mark reaper as "not pending". This is done before checking any
	 * requests to avoid lost-update type problems.
	 */
	WRITE_ONCE(rtl->rtx_timeout.expires, KTIME_MAX);
	smp_mb__after_atomic();

	spin_lock(&rtl->pending.lock);
	list_for_each_entry_safe(r, n, &rtl->pending.head, node) {
		ktime_t expires = ssh_request_get_expiration(r, timeout);

		/*
		 * Check if the timeout hasn't expired yet. Find out next
		 * expiration date to be handled after this run.
		 */
		if (ktime_after(expires, now)) {
			next = ktime_before(expires, next) ? expires : next;
			continue;
		}

		// avoid further transitions if locked
		if (test_and_set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state))
			continue;

		/*
		 * We have now marked the packet as locked. Thus it cannot be
		 * added to the pending or queued lists again after we've
		 * removed it here. We can therefore re-use the node of this
		 * packet temporarily.
		 */

		clear_bit(SSH_REQUEST_SF_PENDING_BIT, &r->state);

		atomic_dec(&rtl->pending.count);
		list_del(&r->node);

		list_add_tail(&r->node, &claimed);
	}
	spin_unlock(&rtl->pending.lock);

	// cancel and complete the request
	list_for_each_entry_safe(r, n, &claimed, node) {
		trace_ssam_request_timeout(r);

		/*
		 * At this point we've removed the packet from pending. This
		 * means that we've obtained the last (only) reference of the
		 * system to it. Thus we can just complete it.
		 */
		if (!test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			ssh_rtl_complete_with_status(r, -ETIMEDOUT);

		// drop the reference we've obtained by removing it from pending
		list_del(&r->node);
		ssh_request_put(r);
	}

	// ensure that reaper doesn't run again immediately
	next = max(next, ktime_add(now, SSH_RTL_REQUEST_TIMEOUT_RESOLUTION));
	if (next != KTIME_MAX)
		ssh_rtl_timeout_reaper_mod(rtl, now, next);

	ssh_rtl_tx_schedule(rtl);
}


static void ssh_rtl_rx_event(struct ssh_rtl *rtl, const struct ssh_command *cmd,
			     const struct ssam_span *data)
{
	trace_ssam_rx_event_received(cmd, data->len);

	rtl_dbg(rtl, "rtl: handling event (rqid: 0x%04x)\n",
		get_unaligned_le16(&cmd->rqid));

	rtl->ops.handle_event(rtl, cmd, data);
}

static void ssh_rtl_rx_command(struct ssh_ptl *p, const struct ssam_span *data)
{
	struct ssh_rtl *rtl = to_ssh_rtl(p, ptl);
	struct device *dev = &p->serdev->dev;
	struct ssh_command *command;
	struct ssam_span command_data;

	if (sshp_parse_command(dev, data, &command, &command_data))
		return;

	if (ssh_rqid_is_event(get_unaligned_le16(&command->rqid)))
		ssh_rtl_rx_event(rtl, command, &command_data);
	else
		ssh_rtl_complete(rtl, command, &command_data);
}

static void ssh_rtl_rx_data(struct ssh_ptl *p, const struct ssam_span *data)
{
	switch (data->ptr[0]) {
	case SSH_PLD_TYPE_CMD:
		ssh_rtl_rx_command(p, data);
		break;

	default:
		ptl_err(p, "rtl: rx: unknown frame payload type"
			" (type: 0x%02x)\n", data->ptr[0]);
		break;
	}
}


static inline struct device *ssh_rtl_get_device(struct ssh_rtl *rtl)
{
	return ssh_ptl_get_device(&rtl->ptl);
}

static inline bool ssh_rtl_tx_flush(struct ssh_rtl *rtl)
{
	return flush_work(&rtl->tx.work);
}

static inline int ssh_rtl_tx_start(struct ssh_rtl *rtl)
{
	int status;
	bool sched;

	status = ssh_ptl_tx_start(&rtl->ptl);
	if (status)
		return status;

	/*
	 * If the packet layer has been shut down and restarted without shutting
	 * down the request layer, there may still be requests queued and not
	 * handled.
	 */
	spin_lock(&rtl->queue.lock);
	sched = !list_empty(&rtl->queue.head);
	spin_unlock(&rtl->queue.lock);

	if (sched)
		ssh_rtl_tx_schedule(rtl);

	return 0;
}

static inline int ssh_rtl_rx_start(struct ssh_rtl *rtl)
{
	return ssh_ptl_rx_start(&rtl->ptl);
}

static int ssh_rtl_init(struct ssh_rtl *rtl, struct serdev_device *serdev,
			const struct ssh_rtl_ops *ops)
{
	struct ssh_ptl_ops ptl_ops;
	int status;

	ptl_ops.data_received = ssh_rtl_rx_data;

	status = ssh_ptl_init(&rtl->ptl, serdev, &ptl_ops);
	if (status)
		return status;

	spin_lock_init(&rtl->queue.lock);
	INIT_LIST_HEAD(&rtl->queue.head);

	spin_lock_init(&rtl->pending.lock);
	INIT_LIST_HEAD(&rtl->pending.head);
	atomic_set_release(&rtl->pending.count, 0);

	INIT_WORK(&rtl->tx.work, ssh_rtl_tx_work_fn);

	rtl->rtx_timeout.timeout = SSH_RTL_REQUEST_TIMEOUT;
	rtl->rtx_timeout.expires = KTIME_MAX;
	INIT_DELAYED_WORK(&rtl->rtx_timeout.reaper, ssh_rtl_timeout_reap);

	rtl->ops = *ops;

	return 0;
}

static void ssh_rtl_destroy(struct ssh_rtl *rtl)
{
	ssh_ptl_destroy(&rtl->ptl);
}


static void ssh_rtl_packet_release(struct ssh_packet *p)
{
	struct ssh_request *rqst = to_ssh_request(p, packet);
	rqst->ops->release(rqst);
}

static const struct ssh_packet_ops ssh_rtl_packet_ops = {
	.complete = ssh_rtl_packet_callback,
	.release = ssh_rtl_packet_release,
};

static void ssh_request_init(struct ssh_request *rqst,
			     enum ssam_request_flags flags,
			     const struct ssh_request_ops *ops)
{
	struct ssh_packet_args packet_args;

	packet_args.type = BIT(SSH_PACKET_TY_BLOCKING_BIT);
	if (!(flags & SSAM_REQUEST_UNSEQUENCED))
		packet_args.type |= BIT(SSH_PACKET_TY_SEQUENCED_BIT);

	packet_args.priority = SSH_PACKET_PRIORITY(DATA, 0);
	packet_args.ops = &ssh_rtl_packet_ops;

	ssh_packet_init(&rqst->packet, &packet_args);
	INIT_LIST_HEAD(&rqst->node);

	rqst->state = 0;
	if (flags & SSAM_REQUEST_HAS_RESPONSE)
		rqst->state |= BIT(SSH_REQUEST_TY_HAS_RESPONSE_BIT);

	rqst->timestamp = KTIME_MAX;
	rqst->ops = ops;
}


struct ssh_flush_request {
	struct ssh_request base;
	struct completion completion;
	int status;
};

static void ssh_rtl_flush_request_complete(struct ssh_request *r,
					   const struct ssh_command *cmd,
					   const struct ssam_span *data,
					   int status)
{
	struct ssh_flush_request *rqst;

	rqst = container_of(r, struct ssh_flush_request, base);
	rqst->status = status;
}

static void ssh_rtl_flush_request_release(struct ssh_request *r)
{
	struct ssh_flush_request *rqst;

	rqst = container_of(r, struct ssh_flush_request, base);
	complete_all(&rqst->completion);
}

static const struct ssh_request_ops ssh_rtl_flush_request_ops = {
	.complete = ssh_rtl_flush_request_complete,
	.release = ssh_rtl_flush_request_release,
};

/**
 * ssh_rtl_flush - flush the request transmission layer
 * @rtl:     request transmission layer
 * @timeout: timeout for the flush operation in jiffies
 *
 * Queue a special flush request and wait for its completion. This request
 * will be completed after all other currently queued and pending requests
 * have been completed. Instead of a normal data packet, this request submits
 * a special flush packet, meaning that upon completion, also the underlying
 * packet transmission layer has been flushed.
 *
 * Flushing the request layer gurarantees that all previously submitted
 * requests have been fully completed before this call returns. Additinally,
 * flushing blocks execution of all later submitted requests until the flush
 * has been completed.
 *
 * If the caller ensures that no new requests are submitted after a call to
 * this function, the request transmission layer is guaranteed to have no
 * remaining requests when this call returns. The same guarantee does not hold
 * for the packet layer, on which control packets may still be queued after
 * this call. See the documentation of ssh_ptl_flush for more details on
 * packet layer flushing.
 *
 * Return: Zero on success, -ETIMEDOUT if the flush timed out and has been
 * canceled as a result of the timeout, or -ESHUTDOWN if the packet and/or
 * request transmission layer has been shut down before this call. May also
 * return -EINTR if the underlying packet transmission has been interrupted.
 */
static int ssh_rtl_flush(struct ssh_rtl *rtl, unsigned long timeout)
{
	const unsigned init_flags = SSAM_REQUEST_UNSEQUENCED;
	struct ssh_flush_request rqst;
	int status;

	ssh_request_init(&rqst.base, init_flags, &ssh_rtl_flush_request_ops);
	rqst.base.packet.state |= BIT(SSH_PACKET_TY_FLUSH_BIT);
	rqst.base.packet.priority = SSH_PACKET_PRIORITY(FLUSH, 0);
	rqst.base.state |= BIT(SSH_REQUEST_TY_FLUSH_BIT);

	init_completion(&rqst.completion);

	status = ssh_rtl_submit(rtl, &rqst.base);
	if (status)
		return status;

	ssh_request_put(&rqst.base);

	if (wait_for_completion_timeout(&rqst.completion, timeout))
		return 0;

	ssh_rtl_cancel(&rqst.base, true);
	wait_for_completion(&rqst.completion);

	WARN_ON(rqst.status != 0 && rqst.status != -ECANCELED
		&& rqst.status != -ESHUTDOWN && rqst.status != -EINTR);

	return rqst.status == -ECANCELED ? -ETIMEDOUT : status;
}


static void ssh_rtl_shutdown(struct ssh_rtl *rtl)
{
	struct ssh_request *r, *n;
	LIST_HEAD(claimed);
	int pending;

	set_bit(SSH_RTL_SF_SHUTDOWN_BIT, &rtl->state);
	smp_mb__after_atomic();

	// remove requests from queue
	spin_lock(&rtl->queue.lock);
	list_for_each_entry_safe(r, n, &rtl->queue.head, node) {
		set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
		smp_mb__before_atomic();
		clear_bit(SSH_REQUEST_SF_QUEUED_BIT, &r->state);

		list_del(&r->node);
		list_add_tail(&r->node, &claimed);
	}
	spin_unlock(&rtl->queue.lock);

	/*
	 * We have now guaranteed that the queue is empty and no more new
	 * requests can be submitted (i.e. it will stay empty). This means that
	 * calling ssh_rtl_tx_schedule will not schedule tx.work any more. So we
	 * can simply call cancel_work_sync on tx.work here and when that
	 * returns, we've locked it down. This also means that after this call,
	 * we don't submit any more packets to the underlying packet layer, so
	 * we can also shut that down.
	 */

	cancel_work_sync(&rtl->tx.work);
	ssh_ptl_shutdown(&rtl->ptl);
	cancel_delayed_work_sync(&rtl->rtx_timeout.reaper);

	/*
	 * Shutting down the packet layer should also have caneled all requests.
	 * Thus the pending set should be empty. Attempt to handle this
	 * gracefully anyways, even though this should be dead code.
	 */

	pending = atomic_read(&rtl->pending.count);
	if (WARN_ON(pending)) {
		spin_lock(&rtl->pending.lock);
		list_for_each_entry_safe(r, n, &rtl->pending.head, node) {
			set_bit(SSH_REQUEST_SF_LOCKED_BIT, &r->state);
			smp_mb__before_atomic();
			clear_bit(SSH_REQUEST_SF_PENDING_BIT, &r->state);

			list_del(&r->node);
			list_add_tail(&r->node, &claimed);
		}
		spin_unlock(&rtl->pending.lock);
	}

	// finally cancel and complete requests
	list_for_each_entry_safe(r, n, &claimed, node) {
		// test_and_set because we still might compete with cancellation
		if (!test_and_set_bit(SSH_REQUEST_SF_COMPLETED_BIT, &r->state))
			ssh_rtl_complete_with_status(r, -ESHUTDOWN);

		// drop the reference we've obtained by removing it from list
		list_del(&r->node);
		ssh_request_put(r);
	}
}


/* -- Event notifier/callbacks. --------------------------------------------- */
/*
 * The notifier system is based on linux/notifier.h, specifically the SRCU
 * implementation. The difference to that is, that some bits of the notifier
 * call return value can be tracked accross multiple calls. This is done so that
 * handling of events can be tracked and a warning can be issued in case an
 * event goes unhandled. The idea of that waring is that it should help discover
 * and identify new/currently unimplemented features.
 */

struct ssam_nf_head {
	struct srcu_struct srcu;
	struct ssam_notifier_block __rcu *head;
};


int ssam_nfblk_call_chain(struct ssam_nf_head *nh, struct ssam_event *event)
{
	struct ssam_notifier_block *nb, *next_nb;
	int ret = 0, idx;

	idx = srcu_read_lock(&nh->srcu);

	nb = rcu_dereference_raw(nh->head);
	while (nb) {
		next_nb = rcu_dereference_raw(nb->next);

		ret = (ret & SSAM_NOTIF_STATE_MASK) | nb->fn(nb, event);
		if (ret & SSAM_NOTIF_STOP)
			break;

		nb = next_nb;
	}

	srcu_read_unlock(&nh->srcu, idx);
	return ret;
}

/*
 * Note: This function must be synchronized by the caller with respect to other
 * insert and/or remove calls.
 */
int __ssam_nfblk_insert(struct ssam_nf_head *nh, struct ssam_notifier_block *nb)
{
	struct ssam_notifier_block **link = &nh->head;

	while ((*link) != NULL) {
		if (unlikely((*link) == nb)) {
			WARN(1, "double register detected");
			return -EINVAL;
		}

		if (nb->priority > (*link)->priority)
			break;

		link = &((*link)->next);
	}

	nb->next = *link;
	rcu_assign_pointer(*link, nb);

	return 0;
}

/*
 * Note: This function must be synchronized by the caller with respect to other
 * insert and/or remove calls. On success, the caller _must_ ensure SRCU
 * synchronization by calling `synchronize_srcu(&nh->srcu)` after leaving the
 * critical section, to ensure that the removed notifier block is not in use any
 * more.
 */
int __ssam_nfblk_remove(struct ssam_nf_head *nh, struct ssam_notifier_block *nb)
{
	struct ssam_notifier_block **link = &nh->head;

	while ((*link) != NULL) {
		if ((*link) == nb) {
			rcu_assign_pointer(*link, nb->next);
			return 0;
		}

		link = &((*link)->next);
	}

	return -ENOENT;
}

static int ssam_nf_head_init(struct ssam_nf_head *nh)
{
	int status;

	status = init_srcu_struct(&nh->srcu);
	if (status)
		return status;

	nh->head = NULL;
	return 0;
}

static void ssam_nf_head_destroy(struct ssam_nf_head *nh)
{
	cleanup_srcu_struct(&nh->srcu);
}


/* -- Event/notification registry. ------------------------------------------ */

struct ssam_nf_refcount_key {
	struct ssam_event_registry reg;
	struct ssam_event_id id;
};

struct ssam_nf_refcount_entry {
	struct rb_node node;
	struct ssam_nf_refcount_key key;
	int refcount;
};

struct ssam_nf {
	struct mutex lock;
	struct rb_root refcount;
	struct ssam_nf_head head[SSH_NUM_EVENTS];
};


static int ssam_nf_refcount_inc(struct ssam_nf *nf,
				struct ssam_event_registry reg,
				struct ssam_event_id id)
{
	struct ssam_nf_refcount_entry *entry;
	struct ssam_nf_refcount_key key;
	struct rb_node **link = &nf->refcount.rb_node;
	struct rb_node *parent = NULL;
	int cmp;

	key.reg = reg;
	key.id = id;

	while (*link) {
		entry = rb_entry(*link, struct ssam_nf_refcount_entry, node);
		parent = *link;

		cmp = memcmp(&key, &entry->key, sizeof(key));
		if (cmp < 0) {
			link = &(*link)->rb_left;
		} else if (cmp > 0) {
			link = &(*link)->rb_right;
		} else if (entry->refcount < INT_MAX) {
			return ++entry->refcount;
		} else {
			return -ENOSPC;
		}
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->key = key;
	entry->refcount = 1;

	rb_link_node(&entry->node, parent, link);
	rb_insert_color(&entry->node, &nf->refcount);

	return entry->refcount;
}

static int ssam_nf_refcount_dec(struct ssam_nf *nf,
				struct ssam_event_registry reg,
				struct ssam_event_id id)
{
	struct ssam_nf_refcount_entry *entry;
	struct ssam_nf_refcount_key key;
	struct rb_node *node = nf->refcount.rb_node;
	int cmp, rc;

	key.reg = reg;
	key.id = id;

	while (node) {
		entry = rb_entry(node, struct ssam_nf_refcount_entry, node);

		cmp = memcmp(&key, &entry->key, sizeof(key));
		if (cmp < 0) {
			node = node->rb_left;
		} else if (cmp > 0) {
			node = node->rb_right;
		} else {
			rc = --entry->refcount;

			if (rc == 0) {
				rb_erase(&entry->node, &nf->refcount);
				kfree(entry);
			}

			return rc;
		}
	}

	return -ENOENT;
}

static bool ssam_nf_refcount_empty(struct ssam_nf *nf)
{
	return RB_EMPTY_ROOT(&nf->refcount);
}

static void ssam_nf_call(struct ssam_nf *nf, struct device *dev, u16 rqid,
			 struct ssam_event *event)
{
	struct ssam_nf_head *nf_head;
	int status, nf_ret;

	if (!ssh_rqid_is_event(rqid)) {
		dev_warn(dev, "event: unsupported rqid: 0x%04x\n", rqid);
		return;
	}

	nf_head = &nf->head[ssh_rqid_to_event(rqid)];
	nf_ret = ssam_nfblk_call_chain(nf_head, event);
	status = ssam_notifier_to_errno(nf_ret);

	if (status < 0) {
		dev_err(dev, "event: error handling event: %d "
			"(tc: 0x%02x, cid: 0x%02x, iid: 0x%02x, chn: 0x%02x)\n",
			status, event->target_category, event->command_id,
			event->instance_id, event->channel);
	}

	if (!(nf_ret & SSAM_NOTIF_HANDLED)) {
		dev_warn(dev, "event: unhandled event (rqid: 0x%02x, "
			 "tc: 0x%02x, cid: 0x%02x, iid: 0x%02x, chn: 0x%02x)\n",
			 rqid, event->target_category, event->command_id,
			 event->instance_id, event->channel);
	}
}

static int ssam_nf_init(struct ssam_nf *nf)
{
	int i, status;

	for (i = 0; i < SSH_NUM_EVENTS; i++) {
		status = ssam_nf_head_init(&nf->head[i]);
		if (status)
			break;
	}

	if (status) {
		for (i = i - 1; i >= 0; i--)
			ssam_nf_head_destroy(&nf->head[i]);

		return status;
	}

	mutex_init(&nf->lock);
	return 0;
}

static void ssam_nf_destroy(struct ssam_nf *nf)
{
	int i;

	for (i = 0; i < SSH_NUM_EVENTS; i++)
		ssam_nf_head_destroy(&nf->head[i]);

	mutex_destroy(&nf->lock);
}


/* -- Event/async request completion system. -------------------------------- */

#define SSAM_CPLT_WQ_NAME	"ssam_cpltq"


struct ssam_cplt;
struct ssam_event_item;

struct ssam_event_item_ops {
	void (*free)(struct ssam_event_item *);
};

struct ssam_event_item {
	struct list_head node;
	u16 rqid;

	struct ssam_event_item_ops ops;
	struct ssam_event event;	// must be last
};

struct ssam_event_queue {
	struct ssam_cplt *cplt;

	spinlock_t lock;
	struct list_head head;
	struct work_struct work;
};

struct ssam_event_channel {
	struct ssam_event_queue queue[SSH_NUM_EVENTS];
};

struct ssam_cplt {
	struct device *dev;
	struct workqueue_struct *wq;

	struct {
		struct ssam_event_channel channel[SSH_NUM_CHANNELS];
		struct ssam_nf notif;
	} event;
};


/**
 * Maximum payload length for cached `ssam_event_item`s.
 *
 * This length has been chosen to be accomodate standard touchpad and keyboard
 * input events. Events with larger payloads will be allocated separately.
 */
#define SSAM_EVENT_ITEM_CACHE_PAYLOAD_LEN	32

static struct kmem_cache *ssam_event_item_cache;

static int ssam_event_item_cache_init(void)
{
	const unsigned int size = sizeof(struct ssam_event_item)
				  + SSAM_EVENT_ITEM_CACHE_PAYLOAD_LEN;
	const unsigned int align = __alignof__(struct ssam_event_item);
	struct kmem_cache *cache;

	cache = kmem_cache_create("ssam_event_item", size, align, 0, NULL);
	if (!cache)
		return -ENOMEM;

	ssam_event_item_cache = cache;
	return 0;
}

static void ssam_event_item_cache_destroy(void)
{
	kmem_cache_destroy(ssam_event_item_cache);
	ssam_event_item_cache = NULL;
}

static void __ssam_event_item_free_cached(struct ssam_event_item *item)
{
	kmem_cache_free(ssam_event_item_cache, item);
}

static void __ssam_event_item_free_generic(struct ssam_event_item *item)
{
	kfree(item);
}

static inline void ssam_event_item_free(struct ssam_event_item *item)
{
	trace_ssam_event_item_free(item);
	item->ops.free(item);
}

static struct ssam_event_item *ssam_event_item_alloc(size_t len, gfp_t flags)
{
	struct ssam_event_item *item;

	if (len <= SSAM_EVENT_ITEM_CACHE_PAYLOAD_LEN) {
		item = kmem_cache_alloc(ssam_event_item_cache, GFP_KERNEL);
		if (!item)
			return NULL;

		item->ops.free = __ssam_event_item_free_cached;
	} else {
		const size_t n = sizeof(struct ssam_event_item) + len;
		item = kzalloc(n, GFP_KERNEL);
		if (!item)
			return NULL;

		item->ops.free = __ssam_event_item_free_generic;
	}

	item->event.length = len;

	trace_ssam_event_item_alloc(item, len);
	return item;
}


static void ssam_event_queue_push(struct ssam_event_queue *q,
				  struct ssam_event_item *item)
{
	spin_lock(&q->lock);
	list_add_tail(&item->node, &q->head);
	spin_unlock(&q->lock);
}

static struct ssam_event_item *ssam_event_queue_pop(struct ssam_event_queue *q)
{
	struct ssam_event_item *item;

	spin_lock(&q->lock);
	item = list_first_entry_or_null(&q->head, struct ssam_event_item, node);
	if (item)
		list_del(&item->node);
	spin_unlock(&q->lock);

	return item;
}

static bool ssam_event_queue_is_empty(struct ssam_event_queue *q)
{
	bool empty;

	spin_lock(&q->lock);
	empty = list_empty(&q->head);
	spin_unlock(&q->lock);

	return empty;
}

static struct ssam_event_queue *ssam_cplt_get_event_queue(
		struct ssam_cplt *cplt, u8 channel, u16 rqid)
{
	u16 event = ssh_rqid_to_event(rqid);
	u16 chidx = ssh_channel_to_index(channel);

	if (!ssh_rqid_is_event(rqid)) {
		dev_err(cplt->dev, "event: unsupported rqid: 0x%04x\n", rqid);
		return NULL;
	}

	if (!ssh_channel_is_valid(channel)) {
		dev_warn(cplt->dev, "event: unsupported channel: %u\n",
			 channel);
		chidx = 0;
	}

	return &cplt->event.channel[chidx].queue[event];
}

static inline bool ssam_cplt_submit(struct ssam_cplt *cplt,
				    struct work_struct *work)
{
	return queue_work(cplt->wq, work);
}

static int ssam_cplt_submit_event(struct ssam_cplt *cplt,
				  struct ssam_event_item *item)
{
	struct ssam_event_queue *evq;

	evq = ssam_cplt_get_event_queue(cplt, item->event.channel, item->rqid);
	if (!evq)
		return -EINVAL;

	ssam_event_queue_push(evq, item);
	ssam_cplt_submit(cplt, &evq->work);
	return 0;
}

static void ssam_cplt_flush(struct ssam_cplt *cplt)
{
	flush_workqueue(cplt->wq);
}

static void ssam_event_queue_work_fn(struct work_struct *work)
{
	struct ssam_event_queue *queue;
	struct ssam_event_item *item;
	struct ssam_nf *nf;
	struct device *dev;
	int i;

	queue = container_of(work, struct ssam_event_queue, work);
	nf = &queue->cplt->event.notif;
	dev = queue->cplt->dev;

	for (i = 0; i < 10; i++) {
		item = ssam_event_queue_pop(queue);
		if (item == NULL)
			return;

		ssam_nf_call(nf, dev, item->rqid, &item->event);
		ssam_event_item_free(item);
	}

	if (!ssam_event_queue_is_empty(queue))
		ssam_cplt_submit(queue->cplt, &queue->work);
}

static void ssam_event_queue_init(struct ssam_cplt *cplt,
				  struct ssam_event_queue *evq)
{
	evq->cplt = cplt;
	spin_lock_init(&evq->lock);
	INIT_LIST_HEAD(&evq->head);
	INIT_WORK(&evq->work, ssam_event_queue_work_fn);
}

static int ssam_cplt_init(struct ssam_cplt *cplt, struct device *dev)
{
	struct ssam_event_channel *channel;
	int status, c, i;

	cplt->dev = dev;

	cplt->wq = create_workqueue(SSAM_CPLT_WQ_NAME);
	if (!cplt->wq)
		return -ENOMEM;

	for (c = 0; c < ARRAY_SIZE(cplt->event.channel); c++) {
		channel = &cplt->event.channel[c];

		for (i = 0; i < ARRAY_SIZE(channel->queue); i++)
			ssam_event_queue_init(cplt, &channel->queue[i]);
	}

	status = ssam_nf_init(&cplt->event.notif);
	if (status)
		destroy_workqueue(cplt->wq);

	return status;
}

static void ssam_cplt_destroy(struct ssam_cplt *cplt)
{
	/*
	 * Note: destroy_workqueue ensures that all currently queued work will
	 * be fully completed and the workqueue drained. This means that this
	 * call will inherently also free any queued ssam_event_items, thus we
	 * don't have to take care of that here explicitly.
	 */
	destroy_workqueue(cplt->wq);
	ssam_nf_destroy(&cplt->event.notif);
}


/* -- Main SSAM device structures. ------------------------------------------ */

enum ssam_controller_state {
	SSAM_CONTROLLER_UNINITIALIZED,
	SSAM_CONTROLLER_INITIALIZED,
	SSAM_CONTROLLER_STARTED,
	SSAM_CONTROLLER_STOPPED,
	SSAM_CONTROLLER_SUSPENDED,
};

struct ssam_device_caps {
	u32 notif_display:1;
	u32 notif_d0exit:1;
};

struct ssam_controller {
	struct kref kref;

	struct rw_semaphore lock;
	enum ssam_controller_state state;

	struct ssh_rtl rtl;
	struct ssam_cplt cplt;

	struct {
		struct ssh_seq_counter seq;
		struct ssh_rqid_counter rqid;
	} counter;

	struct {
		int num;
		bool wakeup_enabled;
	} irq;

	struct ssam_device_caps caps;
};


#define ssam_dbg(ctrl, fmt, ...)  rtl_dbg(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_info(ctrl, fmt, ...) rtl_info(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_warn(ctrl, fmt, ...) rtl_warn(&(ctrl)->rtl, fmt, ##__VA_ARGS__)
#define ssam_err(ctrl, fmt, ...)  rtl_err(&(ctrl)->rtl, fmt, ##__VA_ARGS__)

#define to_ssam_controller(ptr, member) \
	container_of(ptr, struct ssam_controller, member)

struct device *ssam_controller_device(struct ssam_controller *c)
{
	return ssh_rtl_get_device(&c->rtl);
}
EXPORT_SYMBOL_GPL(ssam_controller_device);


static void ssam_controller_destroy(struct ssam_controller *ctrl);

static void __ssam_controller_release(struct kref *kref)
{
	struct ssam_controller *ctrl = to_ssam_controller(kref, kref);

	ssam_controller_destroy(ctrl);
	kfree(ctrl);
}

void ssam_controller_get(struct ssam_controller *c)
{
	kref_get(&c->kref);
}
EXPORT_SYMBOL_GPL(ssam_controller_get);

void ssam_controller_put(struct ssam_controller *c)
{
	kref_put(&c->kref, __ssam_controller_release);
}
EXPORT_SYMBOL_GPL(ssam_controller_put);


void ssam_controller_statelock(struct ssam_controller *c)
{
	down_read(&c->lock);
}
EXPORT_SYMBOL_GPL(ssam_controller_statelock);

void ssam_controller_stateunlock(struct ssam_controller *c)
{
	up_read(&c->lock);
}
EXPORT_SYMBOL_GPL(ssam_controller_stateunlock);

static inline void ssam_controller_lock(struct ssam_controller *c)
{
	down_write(&c->lock);
}

static inline void ssam_controller_unlock(struct ssam_controller *c)
{
	up_write(&c->lock);
}


static void ssam_handle_event(struct ssh_rtl *rtl,
			      const struct ssh_command *cmd,
			      const struct ssam_span *data)
{
	struct ssam_controller *ctrl = to_ssam_controller(rtl, rtl);
	struct ssam_event_item *item;

	item = ssam_event_item_alloc(data->len, GFP_KERNEL);
	if (!item)
		return;

	item->rqid = get_unaligned_le16(&cmd->rqid);
	item->event.target_category = cmd->tc;
	item->event.command_id = cmd->cid;
	item->event.instance_id = cmd->iid;
	item->event.channel = cmd->chn_in;
	memcpy(&item->event.data[0], data->ptr, data->len);

	ssam_cplt_submit_event(&ctrl->cplt, item);
}

static const struct ssh_rtl_ops ssam_rtl_ops = {
	.handle_event = ssam_handle_event,
};


static bool ssam_notifier_empty(struct ssam_controller *ctrl);
static void ssam_notifier_unregister_all(struct ssam_controller *ctrl);


#define SSAM_SSH_DSM_REVISION	0
#define SSAM_SSH_DSM_NOTIF_D0	8
static const guid_t SSAM_SSH_DSM_UUID = GUID_INIT(0xd5e383e1, 0xd892, 0x4a76,
		0x89, 0xfc, 0xf6, 0xaa, 0xae, 0x7e, 0xd5, 0xb5);

static int ssam_device_caps_load_from_acpi(acpi_handle handle,
					   struct ssam_device_caps *caps)
{
	union acpi_object *obj;
	u64 funcs = 0;
	int i;

	// set defaults
	caps->notif_display = true;
	caps->notif_d0exit = false;

	if (!acpi_has_method(handle, "_DSM"))
		return 0;

	// get function availability bitfield
	obj = acpi_evaluate_dsm_typed(handle, &SSAM_SSH_DSM_UUID, 0, 0, NULL,
			ACPI_TYPE_BUFFER);
	if (!obj)
		return -EFAULT;

	for (i = 0; i < obj->buffer.length && i < 8; i++)
		funcs |= (((u64)obj->buffer.pointer[i]) << (i * 8));

	ACPI_FREE(obj);

	// D0 exit/entry notification
	if (funcs & BIT(SSAM_SSH_DSM_NOTIF_D0)) {
		obj = acpi_evaluate_dsm_typed(handle, &SSAM_SSH_DSM_UUID,
				SSAM_SSH_DSM_REVISION, SSAM_SSH_DSM_NOTIF_D0,
				NULL, ACPI_TYPE_INTEGER);
		if (!obj)
			return -EFAULT;

		caps->notif_d0exit = !!obj->integer.value;
		ACPI_FREE(obj);
	}

	return 0;
}

static int ssam_controller_init(struct ssam_controller *ctrl,
				struct serdev_device *serdev)
{
	acpi_handle handle = ACPI_HANDLE(&serdev->dev);
	int status;

	init_rwsem(&ctrl->lock);
	kref_init(&ctrl->kref);

	status = ssam_device_caps_load_from_acpi(handle, &ctrl->caps);
	if (status)
		return status;

	dev_dbg(&serdev->dev, "device capabilities:\n");
	dev_dbg(&serdev->dev, "  notif_display: %u\n", ctrl->caps.notif_display);
	dev_dbg(&serdev->dev, "  notif_d0exit:  %u\n", ctrl->caps.notif_d0exit);

	ssh_seq_reset(&ctrl->counter.seq);
	ssh_rqid_reset(&ctrl->counter.rqid);

	// initialize event/request completion system
	status = ssam_cplt_init(&ctrl->cplt, &serdev->dev);
	if (status)
		return status;

	// initialize request and packet transmission layers
	status = ssh_rtl_init(&ctrl->rtl, serdev, &ssam_rtl_ops);
	if (status) {
		ssam_cplt_destroy(&ctrl->cplt);
		return status;
	}

	// update state
	smp_store_release(&ctrl->state, SSAM_CONTROLLER_INITIALIZED);
	return 0;
}

static int ssam_controller_start(struct ssam_controller *ctrl)
{
	int status;

	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_INITIALIZED)
		return -EINVAL;

	status = ssh_rtl_tx_start(&ctrl->rtl);
	if (status)
		return status;

	status = ssh_rtl_rx_start(&ctrl->rtl);
	if (status) {
		ssh_rtl_tx_flush(&ctrl->rtl);
		return status;
	}

	smp_store_release(&ctrl->state, SSAM_CONTROLLER_STARTED);
	return 0;
}

static void ssam_controller_shutdown(struct ssam_controller *ctrl)
{
	enum ssam_controller_state s = smp_load_acquire(&ctrl->state);
	int status;

	if (s == SSAM_CONTROLLER_UNINITIALIZED || s == SSAM_CONTROLLER_STOPPED)
		return;

	// try to flush pending events and requests while everything still works
	status = ssh_rtl_flush(&ctrl->rtl, msecs_to_jiffies(5000));
	if (status) {
		ssam_err(ctrl, "failed to flush request transmission layer: %d\n",
			 status);
	}

	// try to flush out all currently completing requests and events
	ssam_cplt_flush(&ctrl->cplt);

	/*
	 * We expect all notifiers to have been removed by the respective client
	 * driver that set them up at this point. If this warning occurs, some
	 * client driver has not done that...
	 */
	WARN_ON(!ssam_notifier_empty(ctrl));

	/*
	 * Nevertheless, we should still take care of drivers that don't behave
	 * well. Thus disable all enabled events, unregister all notifiers.
	 */
	ssam_notifier_unregister_all(ctrl);

	// cancel rem. requests, ensure no new ones can be queued, stop threads
	ssh_rtl_tx_flush(&ctrl->rtl);
	ssh_rtl_shutdown(&ctrl->rtl);

	smp_store_release(&ctrl->state, SSAM_CONTROLLER_STOPPED);
	ctrl->rtl.ptl.serdev = NULL;
}

static void ssam_controller_destroy(struct ssam_controller *ctrl)
{
	if (smp_load_acquire(&ctrl->state) == SSAM_CONTROLLER_UNINITIALIZED)
		return;

	/*
	 * Note: New events could still have been received after the previous
	 * flush in ssam_controller_shutdown, before the request transport layer
	 * has been shut down. At this point, after the shutdown, we can be sure
	 * that no new events will be queued. The call to ssam_cplt_destroy will
	 * ensure that those remaining are being completed and freed.
	 */

	// actually free resources
	ssam_cplt_destroy(&ctrl->cplt);
	ssh_rtl_destroy(&ctrl->rtl);

	smp_store_release(&ctrl->state, SSAM_CONTROLLER_UNINITIALIZED);
}

static int ssam_controller_suspend(struct ssam_controller *ctrl)
{
	ssam_controller_lock(ctrl);

	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_STARTED) {
		ssam_controller_unlock(ctrl);
		return -EINVAL;
	}

	ssam_dbg(ctrl, "pm: suspending controller\n");
	smp_store_release(&ctrl->state, SSAM_CONTROLLER_SUSPENDED);

	ssam_controller_unlock(ctrl);
	return 0;
}

static int ssam_controller_resume(struct ssam_controller *ctrl)
{
	ssam_controller_lock(ctrl);

	if (smp_load_acquire(&ctrl->state) != SSAM_CONTROLLER_SUSPENDED) {
		ssam_controller_unlock(ctrl);
		return -EINVAL;
	}

	ssam_dbg(ctrl, "pm: resuming controller\n");
	smp_store_release(&ctrl->state, SSAM_CONTROLLER_STARTED);

	ssam_controller_unlock(ctrl);
	return 0;
}


static inline
int ssam_controller_receive_buf(struct ssam_controller *ctrl,
				const unsigned char *buf, size_t n)
{
	return ssh_ptl_rx_rcvbuf(&ctrl->rtl.ptl, buf, n);
}

static inline void ssam_controller_write_wakeup(struct ssam_controller *ctrl)
{
	ssh_ptl_tx_wakeup(&ctrl->rtl.ptl, true);
}


/* -- Top-level request interface ------------------------------------------- */

ssize_t ssam_request_write_data(struct ssam_span *buf,
				struct ssam_controller *ctrl,
				struct ssam_request *spec)
{
	struct msgbuf msgb;
	u16 rqid;
	u8 seq;

	if (spec->length > SSH_COMMAND_MAX_PAYLOAD_SIZE)
		return -EINVAL;

	msgb_init(&msgb, buf->ptr, buf->len);
	seq = ssh_seq_next(&ctrl->counter.seq);
	rqid = ssh_rqid_next(&ctrl->counter.rqid);
	msgb_push_cmd(&msgb, seq, rqid, spec);

	return msgb_bytes_used(&msgb);
}
EXPORT_SYMBOL_GPL(ssam_request_write_data);


static void ssam_request_sync_complete(struct ssh_request *rqst,
				       const struct ssh_command *cmd,
				       const struct ssam_span *data, int status)
{
	struct ssh_rtl *rtl = ssh_request_rtl(rqst);
	struct ssam_request_sync *r;

	r = container_of(rqst, struct ssam_request_sync, base);
	r->status = status;

        if (r->resp)
	        r->resp->length = 0;

	if (status) {
		rtl_dbg_cond(rtl, "rsp: request failed: %d\n", status);
		return;
	}

	if (!data)	// handle requests without a response
		return;

	if (!r->resp || !r->resp->pointer) {
                if (data->len) {
		        rtl_warn(rtl, "rsp: no response buffer provided, "
                                 "dropping data\n");
                }
                return;
        }

	if (data->len > r->resp->capacity) {
		rtl_err(rtl, "rsp: response buffer too small, "
			"capacity: %zu bytes, got: %zu bytes\n",
			r->resp->capacity, data->len);
		r->status = -ENOSPC;
		return;
	}

	r->resp->length = data->len;
	memcpy(r->resp->pointer, data->ptr, data->len);
}

static void ssam_request_sync_release(struct ssh_request *rqst)
{
	complete_all(&container_of(rqst, struct ssam_request_sync, base)->comp);
}

static const struct ssh_request_ops ssam_request_sync_ops = {
	.release = ssam_request_sync_release,
	.complete = ssam_request_sync_complete,
};


int ssam_request_sync_alloc(size_t payload_len, gfp_t flags,
			    struct ssam_request_sync **rqst,
			    struct ssam_span *buffer)
{
	size_t msglen = SSH_COMMAND_MESSAGE_LENGTH(payload_len);

	*rqst = kzalloc(sizeof(struct ssam_request_sync) + msglen, flags);
	if (!*rqst)
		return -ENOMEM;

	buffer->ptr = (u8 *)(*rqst + 1);
	buffer->len = msglen;

	return 0;
}
EXPORT_SYMBOL_GPL(ssam_request_sync_alloc);

void ssam_request_sync_init(struct ssam_request_sync *rqst,
			    enum ssam_request_flags flags)
{
	ssh_request_init(&rqst->base, flags, &ssam_request_sync_ops);
	init_completion(&rqst->comp);
	rqst->resp = NULL;
	rqst->status = 0;
}
EXPORT_SYMBOL_GPL(ssam_request_sync_init);

int ssam_request_sync_submit(struct ssam_controller *ctrl,
			     struct ssam_request_sync *rqst)
{
	enum ssam_controller_state state = smp_load_acquire(&ctrl->state);
	int status;

	/*
	 * This is only a superficial checks. In general, the caller needs to
	 * ensure that the controller is initialized and is not (and does not
	 * get) suspended during use, i.e. until the request has been completed
	 * (if _absolutely_ necessary, by use of ssam_controller_statelock/
	 * ssam_controller_stateunlock, but something like ssam_client_link
	 * should be preferred as this needs to last until the request has been
	 * completed).
	 *
	 * Note that it is actually safe to use this function while the
	 * controller is in the process of being shut down (as ssh_rtl_submit
	 * is safe with regards to this), but it is generally discouraged to do
	 * so.
	 */
	if (WARN_ON(state != SSAM_CONTROLLER_STARTED)) {
		ssh_request_put(&rqst->base);
		return -ENXIO;
	}

	status = ssh_rtl_submit(&ctrl->rtl, &rqst->base);
	ssh_request_put(&rqst->base);

	return status;
}
EXPORT_SYMBOL_GPL(ssam_request_sync_submit);

int ssam_request_sync(struct ssam_controller *ctrl, struct ssam_request *spec,
		      struct ssam_response *rsp)
{
	struct ssam_request_sync *rqst;
	struct ssam_span buf;
	size_t len;
	int status;

	// prevent overflow, allows us to skip checks later on
	if (spec->length > SSH_COMMAND_MAX_PAYLOAD_SIZE) {
		ssam_err(ctrl, "rqst: request payload too large\n");
		return -EINVAL;
	}

	status = ssam_request_sync_alloc(spec->length, GFP_KERNEL, &rqst, &buf);
	if (status)
		return status;

	ssam_request_sync_init(rqst, spec->flags);
	ssam_request_sync_set_resp(rqst, rsp);

	len = ssam_request_write_data(&buf, ctrl, spec);
	ssam_request_sync_set_data(rqst, buf.ptr, len);

	status = ssam_request_sync_submit(ctrl, rqst);
	if (!status)
		status = ssam_request_sync_wait(rqst);

	kfree(rqst);
	return status;
}
EXPORT_SYMBOL_GPL(ssam_request_sync);

int ssam_request_sync_with_buffer(struct ssam_controller *ctrl,
				  struct ssam_request *spec,
				  struct ssam_response *rsp,
				  struct ssam_span *buf)
{
	struct ssam_request_sync rqst;
	size_t len;
	int status;

	// prevent overflow, allows us to skip checks later on
	if (spec->length > SSH_COMMAND_MAX_PAYLOAD_SIZE) {
		ssam_err(ctrl, "rqst: request payload too large\n");
		return -EINVAL;
	}

	ssam_request_sync_init(&rqst, spec->flags);
	ssam_request_sync_set_resp(&rqst, rsp);

	len = ssam_request_write_data(buf, ctrl, spec);
	ssam_request_sync_set_data(&rqst, buf->ptr, len);

	status = ssam_request_sync_submit(ctrl, &rqst);
	if (!status)
		status = ssam_request_sync_wait(&rqst);

	return status;
}
EXPORT_SYMBOL_GPL(ssam_request_sync_with_buffer);


/* -- Internal SAM requests. ------------------------------------------------ */

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_get_firmware_version, __le32, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x13,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_notif_display_off, u8, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x15,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_notif_display_on, u8, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x16,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_notif_d0_exit, u8, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x33,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static SSAM_DEFINE_SYNC_REQUEST_R(ssam_ssh_notif_d0_entry, u8, {
	.target_category = SSAM_SSH_TC_SAM,
	.command_id      = 0x34,
	.instance_id     = 0x00,
	.channel         = 0x01,
});

static int ssam_ssh_event_enable(struct ssam_controller *ctrl,
				 struct ssam_event_registry reg,
				 struct ssam_event_id id, u8 flags)
{
	struct ssh_notification_params params;
	struct ssam_request rqst;
	struct ssam_response result;
	int status;

	u16 rqid = ssh_tc_to_rqid(id.target_category);
	u8 buf[1] = { 0x00 };

	// only allow RQIDs that lie within event spectrum
	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	params.target_category = id.target_category;
	params.instance_id = id.instance;
	params.flags = flags;
	put_unaligned_le16(rqid, &params.request_id);

	rqst.target_category = reg.target_category;
	rqst.command_id = reg.cid_enable;
	rqst.instance_id = 0x00;
	rqst.channel = reg.channel;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(params);
	rqst.payload = (u8 *)&params;

	result.capacity = ARRAY_SIZE(buf);
	result.length = 0;
	result.pointer = buf;

	status = ssam_request_sync_onstack(ctrl, &rqst, &result, sizeof(params));
	if (status) {
		ssam_err(ctrl, "failed to enable event source "
			 "(tc: 0x%02x, iid: 0x%02x, reg: 0x%02x)\n",
			 id.target_category, id.instance, reg.target_category);
	}

	if (buf[0] != 0x00) {
		ssam_warn(ctrl, "unexpected result while enabling event source: "
			  "0x%02x (tc: 0x%02x, iid: 0x%02x, reg: 0x%02x)\n",
			  buf[0], id.target_category, id.instance,
			  reg.target_category);
	}

	return status;

}

static int ssam_ssh_event_disable(struct ssam_controller *ctrl,
				  struct ssam_event_registry reg,
				  struct ssam_event_id id, u8 flags)
{
	struct ssh_notification_params params;
	struct ssam_request rqst;
	struct ssam_response result;
	int status;

	u16 rqid = ssh_tc_to_rqid(id.target_category);
	u8 buf[1] = { 0x00 };

	// only allow RQIDs that lie within event spectrum
	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	params.target_category = id.target_category;
	params.instance_id = id.instance;
	params.flags = flags;
	put_unaligned_le16(rqid, &params.request_id);

	rqst.target_category = reg.target_category;
	rqst.command_id = reg.cid_disable;
	rqst.instance_id = 0x00;
	rqst.channel = reg.channel;
	rqst.flags = SSAM_REQUEST_HAS_RESPONSE;
	rqst.length = sizeof(params);
	rqst.payload = (u8 *)&params;

	result.capacity = ARRAY_SIZE(buf);
	result.length = 0;
	result.pointer = buf;

	status = ssam_request_sync_onstack(ctrl, &rqst, &result, sizeof(params));
	if (status) {
		ssam_err(ctrl, "failed to disable event source "
			 "(tc: 0x%02x, iid: 0x%02x, reg: 0x%02x)\n",
			 id.target_category, id.instance, reg.target_category);
	}

	if (buf[0] != 0x00) {
		ssam_warn(ctrl, "unexpected result while disabling event source: "
			  "0x%02x (tc: 0x%02x, iid: 0x%02x, reg: 0x%02x)\n",
			  buf[0], id.target_category, id.instance,
			  reg.target_category);
	}

	return status;
}


/* -- Wrappers for internal SAM requests. ----------------------------------- */

static int ssam_log_firmware_version(struct ssam_controller *ctrl)
{
	__le32 __version;
	u32 version, a, b, c;
	int status;

	status = ssam_ssh_get_firmware_version(ctrl, &__version);
	if (status)
		return status;

	version = le32_to_cpu(__version);
	a = (version >> 24) & 0xff;
	b = ((version >> 8) & 0xffff);
	c = version & 0xff;

	ssam_info(ctrl, "SAM controller version: %u.%u.%u\n", a, b, c);
	return 0;
}

static int ssam_ctrl_notif_display_off(struct ssam_controller *ctrl)
{
	int status;
	u8 response;

	if (!ctrl->caps.notif_display)
		return 0;

	ssam_dbg(ctrl, "pm: notifying display off\n");

	status = ssam_ssh_notif_display_off(ctrl, &response);
	if (status)
		return status;

	if (response != 0) {
		ssam_err(ctrl, "unexpected response from display-off notification: "
			 "0x%02x\n", response);
		return -EIO;
	}

	return 0;
}

static int ssam_ctrl_notif_display_on(struct ssam_controller *ctrl)
{
	int status;
	u8 response;

	if (!ctrl->caps.notif_display)
		return 0;

	ssam_dbg(ctrl, "pm: notifying display on\n");

	status = ssam_ssh_notif_display_on(ctrl, &response);
	if (status)
		return status;

	if (response != 0) {
		ssam_err(ctrl, "unexpected response from display-on notification: "
			 "0x%02x\n", response);
		return -EIO;
	}

	return 0;
}

static int ssam_ctrl_notif_d0_exit(struct ssam_controller *ctrl)
{
	int status;
	u8 response;

	if (!ctrl->caps.notif_d0exit)
		return 0;

	ssam_dbg(ctrl, "pm: notifying D0 exit\n");

	status = ssam_ssh_notif_d0_exit(ctrl, &response);
	if (status)
		return status;

	if (response != 0) {
		ssam_err(ctrl, "unexpected response from D0-exit notification: "
			 "0x%02x\n", response);
		return -EIO;
	}

	return 0;
}

static int ssam_ctrl_notif_d0_entry(struct ssam_controller *ctrl)
{
	int status;
	u8 response;

	if (!ctrl->caps.notif_d0exit)
		return 0;

	ssam_dbg(ctrl, "pm: notifying D0 entry\n");

	status = ssam_ssh_notif_d0_entry(ctrl, &response);
	if (status)
		return status;

	if (response != 0) {
		ssam_err(ctrl, "unexpected response from D0-entry notification: "
			 "0x%02x\n", response);
		return -EIO;
	}

	return 0;
}


/* -- Top-level event registry interface. ----------------------------------- */

int ssam_notifier_register(struct ssam_controller *ctrl,
			   struct ssam_event_notifier *n)
{
	u16 rqid = ssh_tc_to_rqid(n->event.id.target_category);
	struct ssam_nf_head *nf_head;
	struct ssam_nf *nf;
	int rc, status;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	nf = &ctrl->cplt.event.notif;
	nf_head = &nf->head[ssh_rqid_to_event(rqid)];

	mutex_lock(&nf->lock);

	rc = ssam_nf_refcount_inc(nf, n->event.reg, n->event.id);
	if (rc < 0) {
		mutex_unlock(&nf->lock);
		return rc;
	}

	ssam_dbg(ctrl, "enabling event (reg: 0x%02x, tc: 0x%02x, iid: 0x%02x, "
		 "rc: %d)\n", n->event.reg.target_category,
		 n->event.id.target_category, n->event.id.instance, rc);

	status = __ssam_nfblk_insert(nf_head, &n->base);
	if (status) {
		ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
		mutex_unlock(&nf->lock);
		return status;
	}

	if (rc == 1) {
		status = ssam_ssh_event_enable(ctrl, n->event.reg, n->event.id,
					       n->event.flags);
		if (status) {
			__ssam_nfblk_remove(nf_head, &n->base);
			ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
			mutex_unlock(&nf->lock);
			synchronize_srcu(&nf_head->srcu);
			return status;
		}
	}

	mutex_unlock(&nf->lock);
	return 0;

}
EXPORT_SYMBOL_GPL(ssam_notifier_register);

int ssam_notifier_unregister(struct ssam_controller *ctrl,
			     struct ssam_event_notifier *n)
{
	u16 rqid = ssh_tc_to_rqid(n->event.id.target_category);
	struct ssam_nf_head *nf_head;
	struct ssam_nf *nf;
	int rc, status = 0;

	if (!ssh_rqid_is_event(rqid))
		return -EINVAL;

	nf = &ctrl->cplt.event.notif;
	nf_head = &nf->head[ssh_rqid_to_event(rqid)];

	mutex_lock(&nf->lock);

	rc = ssam_nf_refcount_dec(nf, n->event.reg, n->event.id);
	if (rc < 0) {
		mutex_unlock(&nf->lock);
		return rc;
	}

	ssam_dbg(ctrl, "disabling event (reg: 0x%02x, tc: 0x%02x, iid: 0x%02x, "
		 "rc: %d)\n", n->event.reg.target_category,
		 n->event.id.target_category, n->event.id.instance, rc);

	if (rc == 0) {
		status = ssam_ssh_event_disable(ctrl, n->event.reg, n->event.id,
						n->event.flags);
	}

	__ssam_nfblk_remove(nf_head, &n->base);
	mutex_unlock(&nf->lock);
	synchronize_srcu(&nf_head->srcu);

	return status;
}
EXPORT_SYMBOL_GPL(ssam_notifier_unregister);

static bool ssam_notifier_empty(struct ssam_controller *ctrl)
{
	struct ssam_nf *nf = &ctrl->cplt.event.notif;
	bool result;

	mutex_lock(&nf->lock);
	result = ssam_nf_refcount_empty(nf);
	mutex_unlock(&nf->lock);

	return result;
}

static void ssam_notifier_unregister_all(struct ssam_controller *ctrl)
{
	struct ssam_nf *nf = &ctrl->cplt.event.notif;
	struct ssam_nf_refcount_entry *pos, *n;

	mutex_lock(&nf->lock);
	rbtree_postorder_for_each_entry_safe(pos, n, &nf->refcount, node) {
		// ignore errors, will get logged in call
		ssam_ssh_event_disable(ctrl, pos->key.reg, pos->key.id, 0);
		kfree(pos);
	}
	nf->refcount = RB_ROOT;
	mutex_unlock(&nf->lock);
}


/* -- Wakeup IRQ. ----------------------------------------------------------- */

static const struct acpi_gpio_params gpio_ssam_wakeup_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_ssam_wakeup     = { 1, 0, false };

static const struct acpi_gpio_mapping ssam_acpi_gpios[] = {
	{ "ssam_wakeup-int-gpio", &gpio_ssam_wakeup_int, 1 },
	{ "ssam_wakeup-gpio",     &gpio_ssam_wakeup,     1 },
	{ },
};

static irqreturn_t ssam_irq_handle(int irq, void *dev_id)
{
	struct ssam_controller *ctrl = dev_id;

	ssam_dbg(ctrl, "pm: wake irq triggered\n");

	// Note: Proper wakeup detection is currently unimplemented.
	//       When the EC is in display-off or any other non-D0 state, it
	//       does not send events/notifications to the host. Instead it
	//       signals that there are events available via the wakeup IRQ.
	//       This driver is responsible for calling back to the EC to
	//       release these events one-by-one.
	//
	//       This IRQ should not cause a full system resume by its own.
	//       Instead, events should be handled by their respective subsystem
	//       drivers, which in turn should signal whether a full system
	//       resume should be performed.
	//
	// TODO: Send GPIO callback command repeatedly to EC until callback
	//       returns 0x00. Return flag of callback is "has more events".
	//       Each time the command is sent, one event is "released". Once
	//       all events have been released (return = 0x00), the GPIO is
	//       re-armed. Detect wakeup events during this process, go back to
	//       sleep if no wakeup event has been received.

	return IRQ_HANDLED;
}

static int ssam_irq_setup(struct ssam_controller *ctrl)
{
	struct device *dev = ssam_controller_device(ctrl);
	struct gpio_desc *gpiod;
	int irq;
	int status;

	/*
	 * The actual GPIO interrupt is declared in ACPI as TRIGGER_HIGH.
	 * However, the GPIO line only gets reset by sending the GPIO callback
	 * command to SAM (or alternatively the display-on notification). As
	 * proper handling for this interrupt is not implemented yet, leaving
	 * the IRQ at TRIGGER_HIGH would cause an IRQ storm (as the callback
	 * never gets sent and thus the line line never gets reset). To avoid
	 * this, mark the IRQ as TRIGGER_RISING for now, only creating a single
	 * interrupt, and let the SAM resume callback during the controller
	 * resume process clear it.
	 */
	const int irqf = IRQF_SHARED | IRQF_ONESHOT | IRQF_TRIGGER_RISING;

	gpiod = gpiod_get(dev, "ssam_wakeup-int", GPIOD_ASIS);
	if (IS_ERR(gpiod))
		return PTR_ERR(gpiod);

	irq = gpiod_to_irq(gpiod);
	gpiod_put(gpiod);

	if (irq < 0)
		return irq;

	status = request_threaded_irq(irq, NULL, ssam_irq_handle, irqf,
				      "surface_sam_wakeup", ctrl);
	if (status)
		return status;

	ctrl->irq.num = irq;
	return 0;
}

static void ssam_irq_free(struct ssam_controller *ctrl)
{
	free_irq(ctrl->irq.num, ctrl);
	ctrl->irq.num = -1;
}


/* -- Glue layer (serdev_device -> ssam_controller). ------------------------ */

static int ssam_receive_buf(struct serdev_device *dev, const unsigned char *buf,
			    size_t n)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(dev);
	return ssam_controller_receive_buf(ctrl, buf, n);
}

static void ssam_write_wakeup(struct serdev_device *dev)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(dev);
	ssam_controller_write_wakeup(ctrl);
}

static const struct serdev_device_ops ssam_serdev_ops = {
	.receive_buf = ssam_receive_buf,
	.write_wakeup = ssam_write_wakeup,
};


/* -- ACPI based device setup. ---------------------------------------------- */

static acpi_status ssam_serdev_setup_via_acpi_crs(struct acpi_resource *rsc,
						  void *ctx)
{
	struct serdev_device *serdev = ctx;
	struct acpi_resource_common_serialbus *serial;
	struct acpi_resource_uart_serialbus *uart;
	bool flow_control;
	int status = 0;

	if (rsc->type != ACPI_RESOURCE_TYPE_SERIAL_BUS)
		return AE_OK;

	serial = &rsc->data.common_serial_bus;
	if (serial->type != ACPI_RESOURCE_SERIAL_TYPE_UART)
		return AE_OK;

	uart = &rsc->data.uart_serial_bus;

	// set up serdev device
	serdev_device_set_baudrate(serdev, uart->default_baud_rate);

	// serdev currently only supports RTSCTS flow control
	if (uart->flow_control & (~((u8) ACPI_UART_FLOW_CONTROL_HW))) {
		dev_warn(&serdev->dev, "setup: unsupported flow control"
			 " (value: 0x%02x)\n", uart->flow_control);
	}

	// set RTSCTS flow control
	flow_control = uart->flow_control & ACPI_UART_FLOW_CONTROL_HW;
	serdev_device_set_flow_control(serdev, flow_control);

	// serdev currently only supports EVEN/ODD parity
	switch (uart->parity) {
	case ACPI_UART_PARITY_NONE:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_NONE);
		break;
	case ACPI_UART_PARITY_EVEN:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_EVEN);
		break;
	case ACPI_UART_PARITY_ODD:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_ODD);
		break;
	default:
		dev_warn(&serdev->dev, "setup: unsupported parity"
			 " (value: 0x%02x)\n", uart->parity);
		break;
	}

	if (status) {
		dev_err(&serdev->dev, "setup: failed to set parity"
			" (value: 0x%02x)\n", uart->parity);
		return status;
	}

	return AE_CTRL_TERMINATE;       // we've found the resource and are done
}

static acpi_status ssam_serdev_setup_via_acpi(acpi_handle handle,
					      struct serdev_device *serdev)
{
	return acpi_walk_resources(handle, METHOD_NAME__CRS,
				   ssam_serdev_setup_via_acpi_crs, serdev);
}


/* -- Power management. ----------------------------------------------------- */

static void surface_sam_ssh_shutdown(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	/*
	 * Try to signal display-off and D0-exit, ignore any errors.
	 *
	 * Note: It has not been established yet if this is actually
	 * necessary/useful for shutdown.
	 */

	status = ssam_ctrl_notif_display_off(c);
	if (status)
		ssam_err(c, "pm: display-off notification failed: %d\n", status);

	status = ssam_ctrl_notif_d0_exit(c);
	if (status)
		ssam_err(c, "pm: D0-exit notification failed: %d\n", status);
}

static int surface_sam_ssh_suspend(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	/*
	 * Try to signal display-off and D0-exit, enable IRQ wakeup if
	 * specified. Abort on error.
	 *
	 * Note: Signalling display-off/display-on should normally be done from
	 * some sort of display state notifier. As that is not available, signal
	 * it here.
	 */

	status = ssam_ctrl_notif_display_off(c);
	if (status) {
		ssam_err(c, "pm: display-off notification failed: %d\n", status);
		return status;
	}

	status = ssam_ctrl_notif_d0_exit(c);
	if (status) {
		ssam_err(c, "pm: D0-exit notification failed: %d\n", status);
		goto err_notif;
	}

	if (device_may_wakeup(dev)) {
		status = enable_irq_wake(c->irq.num);
		if (status) {
			ssam_err(c, "failed to disable wake IRQ: %d\n", status);
			goto err_irq;
		}

		c->irq.wakeup_enabled = true;
	} else {
		c->irq.wakeup_enabled = false;
	}

	WARN_ON(ssam_controller_suspend(c));
	return 0;

err_irq:
	ssam_ctrl_notif_d0_entry(c);
err_notif:
	ssam_ctrl_notif_display_on(c);
	return status;
}

static int surface_sam_ssh_resume(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	WARN_ON(ssam_controller_resume(c));

	/*
	 * Try to disable IRQ wakeup (if specified), signal display-on and
	 * D0-entry. In case of errors, log them and try to restore normal
	 * operation state as far as possible.
	 *
	 * Note: Signalling display-off/display-on should normally be done from
	 * some sort of display state notifier. As that is not available, signal
	 * it here.
	 */

	if (c->irq.wakeup_enabled) {
		status = disable_irq_wake(c->irq.num);
		if (status)
			ssam_err(c, "failed to disable wake IRQ: %d\n", status);

		c->irq.wakeup_enabled = false;
	}

	status = ssam_ctrl_notif_d0_entry(c);
	if (status)
		ssam_err(c, "pm: display-on notification failed: %d\n", status);

	status = ssam_ctrl_notif_display_on(c);
	if (status)
		ssam_err(c, "pm: D0-entry notification failed: %d\n", status);

	return 0;
}

static SIMPLE_DEV_PM_OPS(surface_sam_ssh_pm_ops, surface_sam_ssh_suspend,
			 surface_sam_ssh_resume);


/* -- Static controller reference. ------------------------------------------ */

static struct ssam_controller *__ssam_controller = NULL;
static DEFINE_SPINLOCK(__ssam_controller_lock);

struct ssam_controller *ssam_get_controller(void)
{
	struct ssam_controller *ctrl;

	spin_lock(&__ssam_controller_lock);

	ctrl = __ssam_controller;
	if (!ctrl)
		goto out;

	if (WARN_ON(!kref_get_unless_zero(&ctrl->kref)))
		ctrl = NULL;

out:
	spin_unlock(&__ssam_controller_lock);
	return ctrl;
}
EXPORT_SYMBOL_GPL(ssam_get_controller);

static int ssam_try_set_controller(struct ssam_controller *ctrl)
{
	int status = 0;

	spin_lock(&__ssam_controller_lock);
	if (!__ssam_controller)
		__ssam_controller = ctrl;
	else
		status = -EBUSY;
	spin_unlock(&__ssam_controller_lock);

	return status;
}

static void ssam_clear_controller(void)
{
	spin_lock(&__ssam_controller_lock);
	__ssam_controller = NULL;
	spin_unlock(&__ssam_controller_lock);
}


/* -- Device/driver setup. -------------------------------------------------- */

static int __ssam_client_link(struct ssam_controller *c, struct device *client)
{
	const u32 flags = DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER;
	struct device_link *link;
	struct device *ctrldev;

	if (smp_load_acquire(&c->state) != SSAM_CONTROLLER_STARTED)
		return -ENXIO;

	if ((ctrldev = ssam_controller_device(c)) == NULL)
		return -ENXIO;

	if ((link = device_link_add(client, ctrldev, flags)) == NULL)
		return -ENOMEM;

	/*
	 * Return -ENXIO if supplier driver is on its way to be removed. In this
	 * case, the controller won't be around for much longer and the device
	 * link is not going to save us any more, as unbinding is already in
	 * progress.
	 */
	if (link->status == DL_STATE_SUPPLIER_UNBIND)
		return -ENXIO;

	return 0;
}

int ssam_client_link(struct ssam_controller *ctrl, struct device *client)
{
	int status;

	ssam_controller_statelock(ctrl);
	status = __ssam_client_link(ctrl, client);
	ssam_controller_stateunlock(ctrl);

	return status;
}
EXPORT_SYMBOL_GPL(ssam_client_link);

int ssam_client_bind(struct device *client, struct ssam_controller **ctrl)
{
	struct ssam_controller *c;
	int status;

	c = ssam_get_controller();
	if (!c)
		return -ENXIO;

	status = ssam_client_link(c, client);

	/*
	 * Note that we can drop our controller reference in both success and
	 * failure cases: On success, we have bound the controller lifetime
	 * inherently to the client driver lifetime, i.e. it the controller is
	 * now guaranteed to outlive the client driver. On failure, we're not
	 * going to use the controller any more.
	 */
	ssam_controller_put(c);

	*ctrl = status == 0 ? c : NULL;
	return status;
}
EXPORT_SYMBOL_GPL(ssam_client_bind);


static int surface_sam_ssh_probe(struct serdev_device *serdev)
{
	struct ssam_controller *ctrl;
	acpi_handle *ssh = ACPI_HANDLE(&serdev->dev);
	int status;

	if (gpiod_count(&serdev->dev, NULL) < 0)
		return -ENODEV;

	status = devm_acpi_dev_add_driver_gpios(&serdev->dev, ssam_acpi_gpios);
	if (status)
		return status;

	// allocate controller
	ctrl = kzalloc(sizeof(struct ssam_controller), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	// initialize controller
	status = ssam_controller_init(ctrl, serdev);
	if (status)
		goto err_ctrl_init;

	// set up serdev device
	serdev_device_set_drvdata(serdev, ctrl);
	serdev_device_set_client_ops(serdev, &ssam_serdev_ops);
	status = serdev_device_open(serdev);
	if (status)
		goto err_devopen;

	status = ssam_serdev_setup_via_acpi(ssh, serdev);
	if (ACPI_FAILURE(status))
		goto err_devinit;

	// start controller
	status = ssam_controller_start(ctrl);
	if (status)
		goto err_devinit;

	// initial SAM requests: log version, notify default/init power states
	status = ssam_log_firmware_version(ctrl);
	if (status)
		goto err_initrq;

	status = ssam_ctrl_notif_d0_entry(ctrl);
	if (status)
		goto err_initrq;

	status = ssam_ctrl_notif_display_on(ctrl);
	if (status)
		goto err_initrq;

	// setup IRQ
	status = ssam_irq_setup(ctrl);
	if (status)
		goto err_initrq;

	// finally, set main controller reference
	status = ssam_try_set_controller(ctrl);
	if (status)
		goto err_initrq;

	/*
	 * TODO: The EC can wake up the system via the associated GPIO interrupt
	 *       in multiple situations. One of which is the remaining battery
	 *       capacity falling below a certain threshold. Normally, we should
	 *       use the device_init_wakeup function, however, the EC also seems
	 *       to have other reasons for waking up the system and it seems
	 *       that Windows has additional checks whether the system should be
	 *       resumed. In short, this causes some spurious unwanted wake-ups.
	 *       For now let's thus default power/wakeup to false.
	 */
	device_set_wakeup_capable(&serdev->dev, true);
	acpi_walk_dep_device_list(ssh);

	return 0;

err_initrq:
	ssam_controller_shutdown(ctrl);
err_devinit:
	serdev_device_close(serdev);
err_devopen:
	ssam_controller_destroy(ctrl);
	serdev_device_set_drvdata(serdev, NULL);
err_ctrl_init:
	kfree(ctrl);
	return status;
}

static void surface_sam_ssh_remove(struct serdev_device *serdev)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(serdev);
	int status;

	// clear static reference, so that no one else can get a new one
	ssam_clear_controller();

	ssam_irq_free(ctrl);
	ssam_controller_lock(ctrl);

	// act as if suspending to disable events
	status = ssam_ctrl_notif_display_off(ctrl);
	if (status) {
		dev_err(&serdev->dev, "display-off notification failed: %d\n",
			status);
	}

	status = ssam_ctrl_notif_d0_exit(ctrl);
	if (status) {
		dev_err(&serdev->dev, "D0-exit notification failed: %d\n",
			status);
	}

	// shut down controller and remove serdev device reference from it
	ssam_controller_shutdown(ctrl);

	// shut down actual transport
	serdev_device_wait_until_sent(serdev, 0);
	serdev_device_close(serdev);

	// drop our controller reference
	ssam_controller_unlock(ctrl);
	ssam_controller_put(ctrl);

	device_set_wakeup_capable(&serdev->dev, false);
	serdev_device_set_drvdata(serdev, NULL);
}


static const struct acpi_device_id surface_sam_ssh_match[] = {
	{ "MSHW0084", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_ssh_match);

static struct serdev_device_driver surface_sam_ssh = {
	.probe = surface_sam_ssh_probe,
	.remove = surface_sam_ssh_remove,
	.driver = {
		.name = "surface_sam_ssh",
		.acpi_match_table = surface_sam_ssh_match,
		.pm = &surface_sam_ssh_pm_ops,
		.shutdown = surface_sam_ssh_shutdown,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


/* -- Module setup. --------------------------------------------------------- */

static int __init surface_sam_ssh_init(void)
{
	int status;

	status = ssh_ctrl_packet_cache_init();
	if (status)
		goto err_cpkg;

	status = ssam_event_item_cache_init();
	if (status)
		goto err_evitem;

	status = serdev_device_driver_register(&surface_sam_ssh);
	if (status)
		goto err_register;

	return 0;

err_register:
	ssam_event_item_cache_destroy();
err_evitem:
	ssh_ctrl_packet_cache_destroy();
err_cpkg:
	return status;
}

static void __exit surface_sam_ssh_exit(void)
{
	serdev_device_driver_unregister(&surface_sam_ssh);
	ssam_event_item_cache_destroy();
	ssh_ctrl_packet_cache_destroy();
}

/*
 * Ensure that the driver is loaded late due to some issues with the UART
 * communication. Specifically, we want to ensure that DMA is ready and being
 * used. Not using DMA can result in spurious communication failures,
 * especially during boot, which among other things will result in wrong
 * battery information (via ACPI _BIX) being displayed. Using a late init_call
 * instead of the normal module_init gives the DMA subsystem time to
 * initialize and via that results in a more stable communication, avoiding
 * such failures.
 */
late_initcall(surface_sam_ssh_init);
module_exit(surface_sam_ssh_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface Serial Hub Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");

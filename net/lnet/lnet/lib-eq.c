// SPDX-License-Identifier: GPL-2.0
/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/lnet/lib-eq.c
 *
 * Library level Event queue management routines
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/lnet/lib-lnet.h>

/**
 * Create an event queue that has room for @count number of events.
 *
 * The event queue is circular and older events will be overwritten by new
 * ones if they are not removed in time by the user using the functions
 * LNetEQGet(), LNetEQWait(), or LNetEQPoll(). It is up to the user to
 * determine the appropriate size of the event queue to prevent this loss
 * of events. Note that when EQ handler is specified in @callback, no
 * event loss can happen, since the handler is run for each event deposited
 * into the EQ.
 *
 * @count	The number of events to be stored in the event queue. It
 *		will be rounded up to the next power of two.
 * @callback	A handler function that runs when an event is deposited
 *		into the EQ. The constant value LNET_EQ_HANDLER_NONE can
 *		be used to indicate that no event handler is desired.
 * @handle	On successful return, this location will hold a handle for
 *		the newly created EQ.
 *
 * Return:	0 On success.
 *		-EINVAL If an parameter is not valid.
 *		-ENOMEM If memory for the EQ can't be allocated.
 *
 * \see lnet_eq_handler_t for the discussion on EQ handler semantics.
 */
int
LNetEQAlloc(unsigned int count, lnet_eq_handler_t callback,
	    struct lnet_handle_eq *handle)
{
	struct lnet_eq *eq;

	LASSERT(the_lnet.ln_refcount > 0);

	/*
	 * We need count to be a power of 2 so that when eq_{enq,deq}_seq
	 * overflow, they don't skip entries, so the queue has the same
	 * apparent capacity at all times
	 */
	if (count)
		count = roundup_pow_of_two(count);

	if (callback != LNET_EQ_HANDLER_NONE && count)
		CWARN("EQ callback is guaranteed to get every event, do you still want to set eqcount %d for polling event which will have locking overhead? Please contact with developer to confirm\n", count);

	/*
	 * count can be 0 if only need callback, we can eliminate
	 * overhead of enqueue event
	 */
	if (!count && callback == LNET_EQ_HANDLER_NONE)
		return -EINVAL;

	eq = kzalloc(sizeof(*eq), GFP_NOFS);
	if (!eq)
		return -ENOMEM;

	if (count) {
		eq->eq_events = kvmalloc_array(count, sizeof(*eq->eq_events),
					       GFP_KERNEL | __GFP_ZERO);
		if (!eq->eq_events)
			goto failed;
		/*
		 * NB allocator has set all event sequence numbers to 0,
		 * so all them should be earlier than eq_deq_seq
		 */
	}

	eq->eq_deq_seq = 1;
	eq->eq_enq_seq = 1;
	eq->eq_size = count;
	eq->eq_callback = callback;

	eq->eq_refs = cfs_percpt_alloc(lnet_cpt_table(),
				       sizeof(*eq->eq_refs[0]));
	if (!eq->eq_refs)
		goto failed;

	/* MUST hold both exclusive lnet_res_lock */
	lnet_res_lock(LNET_LOCK_EX);
	/*
	 * NB: hold lnet_eq_wait_lock for EQ link/unlink, so we can do
	 * both EQ lookup and poll event with only lnet_eq_wait_lock
	 */
	lnet_eq_wait_lock();

	lnet_res_lh_initialize(&the_lnet.ln_eq_container, &eq->eq_lh);
	list_add(&eq->eq_list, &the_lnet.ln_eq_container.rec_active);

	lnet_eq_wait_unlock();
	lnet_res_unlock(LNET_LOCK_EX);

	lnet_eq2handle(handle, eq);
	return 0;

failed:
	kvfree(eq->eq_events);

	if (eq->eq_refs)
		cfs_percpt_free(eq->eq_refs);

	kfree(eq);
	return -ENOMEM;
}
EXPORT_SYMBOL(LNetEQAlloc);

/**
 * Release the resources associated with an event queue if it's idle;
 * otherwise do nothing and it's up to the user to try again.
 *
 * @eqh		A handle for the event queue to be released.
 *
 * Return:	0 If the EQ is not in use and freed.
 *		-ENOENT If @eqh does not point to a valid EQ.
 *		-EBUSY If the EQ is still in use by some MDs.
 */
int
LNetEQFree(struct lnet_handle_eq eqh)
{
	struct lnet_eq *eq;
	struct lnet_event *events = NULL;
	int **refs = NULL;
	int *ref;
	int rc = 0;
	int size = 0;
	int i;

	lnet_res_lock(LNET_LOCK_EX);
	/*
	 * NB: hold lnet_eq_wait_lock for EQ link/unlink, so we can do
	 * both EQ lookup and poll event with only lnet_eq_wait_lock
	 */
	lnet_eq_wait_lock();

	eq = lnet_handle2eq(&eqh);
	if (!eq) {
		rc = -ENOENT;
		goto out;
	}

	cfs_percpt_for_each(ref, i, eq->eq_refs) {
		LASSERT(*ref >= 0);
		if (!*ref)
			continue;

		CDEBUG(D_NET, "Event equeue (%d: %d) busy on destroy.\n",
		       i, *ref);
		rc = -EBUSY;
		goto out;
	}

	/* stash for free after lock dropped */
	events = eq->eq_events;
	size = eq->eq_size;
	refs = eq->eq_refs;

	lnet_res_lh_invalidate(&eq->eq_lh);
	list_del(&eq->eq_list);
	kfree(eq);
out:
	lnet_eq_wait_unlock();
	lnet_res_unlock(LNET_LOCK_EX);

	kvfree(events);
	if (refs)
		cfs_percpt_free(refs);

	return rc;
}
EXPORT_SYMBOL(LNetEQFree);

void
lnet_eq_enqueue_event(struct lnet_eq *eq, struct lnet_event *ev)
{
	/* MUST called with resource lock hold but w/o lnet_eq_wait_lock */
	int index;

	if (!eq->eq_size) {
		LASSERT(eq->eq_callback != LNET_EQ_HANDLER_NONE);
		eq->eq_callback(ev);
		return;
	}

	lnet_eq_wait_lock();
	ev->sequence = eq->eq_enq_seq++;

	LASSERT(is_power_of_2(eq->eq_size));
	index = ev->sequence & (eq->eq_size - 1);

	eq->eq_events[index] = *ev;

	if (eq->eq_callback != LNET_EQ_HANDLER_NONE)
		eq->eq_callback(ev);

	/* Wake anyone waiting in LNetEQPoll() */
	if (waitqueue_active(&the_lnet.ln_eq_waitq))
		wake_up_all(&the_lnet.ln_eq_waitq);
	lnet_eq_wait_unlock();
}

static int
lnet_eq_dequeue_event(struct lnet_eq *eq, struct lnet_event *ev)
{
	int new_index = eq->eq_deq_seq & (eq->eq_size - 1);
	struct lnet_event *new_event = &eq->eq_events[new_index];
	int rc;

	/* must called with lnet_eq_wait_lock hold */
	if (LNET_SEQ_GT(eq->eq_deq_seq, new_event->sequence))
		return 0;

	/* We've got a new event... */
	*ev = *new_event;

	CDEBUG(D_INFO, "event: %p, sequence: %lu, eq->size: %u\n",
	       new_event, eq->eq_deq_seq, eq->eq_size);

	/* ...but did it overwrite an event we've not seen yet? */
	if (eq->eq_deq_seq == new_event->sequence) {
		rc = 1;
	} else {
		/*
		 * don't complain with CERROR: some EQs are sized small
		 * anyway; if it's important, the caller should complain
		 */
		CDEBUG(D_NET, "Event Queue Overflow: eq seq %lu ev seq %lu\n",
		       eq->eq_deq_seq, new_event->sequence);
		rc = -EOVERFLOW;
	}

	eq->eq_deq_seq = new_event->sequence + 1;
	return rc;
}

/**
 * A nonblocking function that can be used to get the next event in an EQ.
 * If an event handler is associated with the EQ, the handler will run before
 * this function returns successfully. The event is removed from the queue.
 *
 * @eventq	A handle for the event queue.
 * @event	On successful return (1 or -EOVERFLOW), this location will
 *		hold the next event in the EQ.
 *
 * Return	0 No pending event in the EQ.
 *		1 Indicates success.
 *		-ENOENT If @eventq does not point to a valid EQ.
 *		-EOVERFLOW Indicates success (i.e., an event is returned)
 *		and that at least one event between this event and the last
 *		event obtained from the EQ has been dropped due to limited
 *		space in the EQ.
 */

/**
 * Block the calling process until there is an event in the EQ.
 * If an event handler is associated with the EQ, the handler will run before
 * this function returns successfully. This function returns the next event
 * in the EQ and removes it from the EQ.
 *
 * @eventq	A handle for the event queue.
 * @event	On successful return (1 or -EOVERFLOW), this location will
 *		hold the next event in the EQ.
 *
 * Return:	1 Indicates success.
 *		-ENOENT If @eventq does not point to a valid EQ.
 *		-EOVERFLOW Indicates success (i.e., an event is returned)
 *		and that at least one event between this event and the last
 *		event obtained from the EQ has been dropped due to limited
 *		space in the EQ.
 */
static int
lnet_eq_wait_locked(signed long *timeout, long state)
__must_hold(&the_lnet.ln_eq_wait_lock)
{
	signed long tms = *timeout;
	int wait;
	wait_queue_entry_t wl;

	if (!tms)
		return -ENXIO; /* don't want to wait and no new event */

	init_waitqueue_entry(&wl, current);
	set_current_state(state);
	add_wait_queue(&the_lnet.ln_eq_waitq, &wl);

	lnet_eq_wait_unlock();

	tms = schedule_timeout(tms);
	wait = tms; /* might need to call here again */
	*timeout = tms;

	lnet_eq_wait_lock();
	remove_wait_queue(&the_lnet.ln_eq_waitq, &wl);

	return wait;
}

/**
 * Block the calling process until there's an event from a set of EQs or
 * timeout happens.
 *
 * If an event handler is associated with the EQ, the handler will run before
 * this function returns successfully, in which case the corresponding event
 * is consumed.
 *
 * LNetEQPoll() provides a timeout to allow applications to poll, block for a
 * fixed period, or block indefinitely.
 *
 * @eventqs,neq		An array of EQ handles, and size of the array.
 * @timeout		Time in jiffies to wait for an event to occur on
 *			one of the EQs. The constant MAX_SCHEDULE_TIMEOUT
 *			can be used to indicate an infinite timeout.
 * @interruptible	if true, use TASK_INTERRUPTIBLE, else TASK_IDLE
 * @event,which		On successful return (1 or -EOVERFLOW), @event will
 *			hold the next event in the EQs, and @which will
 *			contain the index of the EQ from which the event
 *			was taken.
 *
 * Return:		0 No pending event in the EQs after timeout.
 *			1 Indicates success.
 *			-EOVERFLOW Indicates success (i.e., an event is
 *			returned) and that at least one event between
 *			this event and the last event obtained from the
 *			EQ indicated by @which has been dropped due to
 *			limited space in the EQ.
 *			-ENOENT If there's an invalid handle in @eventqs.
 */
int
LNetEQPoll(struct lnet_handle_eq *eventqs, int neq, signed long timeout,
	   int interruptible,
	   struct lnet_event *event, int *which)
{
	int wait = 1;
	int rc;
	int i;

	LASSERT(the_lnet.ln_refcount > 0);

	if (neq < 1)
		return -ENOENT;

	lnet_eq_wait_lock();

	for (;;) {
		for (i = 0; i < neq; i++) {
			struct lnet_eq *eq = lnet_handle2eq(&eventqs[i]);

			if (!eq) {
				lnet_eq_wait_unlock();
				return -ENOENT;
			}

			rc = lnet_eq_dequeue_event(eq, event);
			if (rc) {
				lnet_eq_wait_unlock();
				*which = i;
				return rc;
			}
		}

		if (!wait)
			break;

		/*
		 * return value of lnet_eq_wait_locked:
		 * -1 : did nothing and it's sure no new event
		 *  1 : sleep inside and wait until new event
		 *  0 : don't want to wait anymore, but might have new event
		 *      so need to call dequeue again
		 */
		wait = lnet_eq_wait_locked(&timeout,
					   interruptible ? TASK_INTERRUPTIBLE
					   : TASK_IDLE);
		if (wait < 0) /* no new event */
			break;
	}

	lnet_eq_wait_unlock();
	return 0;
}

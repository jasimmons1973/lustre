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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/selftest/timer.c
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include "selftest.h"

/*
 * Timers are implemented as a sorted queue of expiry times. The queue
 * is slotted, with each slot holding timers which expire in a
 * 2**STTIMER_MINPOLL (8) second period. The timers in each slot are
 * sorted by increasing expiry time. The number of slots is 2**7 (128),
 * to cover a time period of 1024 seconds into the future before wrapping.
 */
#define STTIMER_MINPOLL		3	/* log2 min poll interval (8 s) */
#define STTIMER_SLOTTIME	BIT(STTIMER_MINPOLL)
#define STTIMER_SLOTTIMEMASK	(~(STTIMER_SLOTTIME - 1))
#define STTIMER_NSLOTS		BIT(7)
#define STTIMER_SLOT(t)		(&stt_data.stt_hash[(((t) >> STTIMER_MINPOLL) & \
						     (STTIMER_NSLOTS - 1))])

static struct st_timer_data {
	spinlock_t	  stt_lock;
	time64_t	  stt_prev_slot; /* start time of the slot processed
					  * previously
					  */
	struct list_head  stt_hash[STTIMER_NSLOTS];
	int		  stt_shuttingdown;
	wait_queue_head_t stt_waitq;
	int		  stt_nthreads;
} stt_data;

void
stt_add_timer(struct stt_timer *timer)
{
	struct list_head *pos;

	spin_lock(&stt_data.stt_lock);

	LASSERT(stt_data.stt_nthreads > 0);
	LASSERT(!stt_data.stt_shuttingdown);
	LASSERT(timer->stt_func);
	LASSERT(list_empty(&timer->stt_list));
	LASSERT(timer->stt_expires > ktime_get_real_seconds());

	/* a simple insertion sort */
	list_for_each_prev(pos, STTIMER_SLOT(timer->stt_expires)) {
		struct stt_timer *old = list_entry(pos, struct stt_timer,
						   stt_list);

		if (timer->stt_expires >= old->stt_expires)
			break;
	}
	list_add(&timer->stt_list, pos);

	spin_unlock(&stt_data.stt_lock);
}

/*
 * The function returns whether it has deactivated a pending timer or not.
 * (ie. del_timer() of an inactive timer returns 0, del_timer() of an
 * active timer returns 1.)
 *
 * CAVEAT EMPTOR:
 * When 0 is returned, it is possible that timer->stt_func _is_ running on
 * another CPU.
 */
int
stt_del_timer(struct stt_timer *timer)
{
	int ret = 0;

	spin_lock(&stt_data.stt_lock);

	LASSERT(stt_data.stt_nthreads > 0);
	LASSERT(!stt_data.stt_shuttingdown);

	if (!list_empty(&timer->stt_list)) {
		ret = 1;
		list_del_init(&timer->stt_list);
	}

	spin_unlock(&stt_data.stt_lock);
	return ret;
}

/* called with stt_data.stt_lock held */
static int
stt_expire_list(struct list_head *slot, time64_t now)
{
	int expired = 0;
	struct stt_timer *timer;

	while ((timer = list_first_entry_or_null(slot, struct stt_timer,
						 stt_list)) != NULL) {

		if (timer->stt_expires > now)
			break;

		list_del_init(&timer->stt_list);
		spin_unlock(&stt_data.stt_lock);

		expired++;
		(*timer->stt_func) (timer->stt_data);

		spin_lock(&stt_data.stt_lock);
	}

	return expired;
}

static int
stt_check_timers(time64_t *last)
{
	int expired = 0;
	time64_t now;
	time64_t this_slot;

	now = ktime_get_real_seconds();
	this_slot = now & STTIMER_SLOTTIMEMASK;

	spin_lock(&stt_data.stt_lock);

	while (this_slot >= *last) {
		expired += stt_expire_list(STTIMER_SLOT(this_slot), now);
		this_slot = this_slot - STTIMER_SLOTTIME;
	}

	*last = now & STTIMER_SLOTTIMEMASK;
	spin_unlock(&stt_data.stt_lock);
	return expired;
}

static int
stt_timer_main(void *arg)
{
	int rc = 0;

	while (!stt_data.stt_shuttingdown) {
		stt_check_timers(&stt_data.stt_prev_slot);

		rc = wait_event_timeout(stt_data.stt_waitq,
					stt_data.stt_shuttingdown,
					STTIMER_SLOTTIME * HZ);
	}

	spin_lock(&stt_data.stt_lock);
	stt_data.stt_nthreads--;
	spin_unlock(&stt_data.stt_lock);
	return rc;
}

static int
stt_start_timer_thread(void)
{
	struct task_struct *task;

	LASSERT(!stt_data.stt_shuttingdown);

	task = kthread_run(stt_timer_main, NULL, "st_timer");
	if (IS_ERR(task))
		return PTR_ERR(task);

	spin_lock(&stt_data.stt_lock);
	stt_data.stt_nthreads++;
	spin_unlock(&stt_data.stt_lock);
	return 0;
}

int
stt_startup(void)
{
	int rc = 0;
	int i;

	stt_data.stt_shuttingdown = 0;
	stt_data.stt_prev_slot = ktime_get_real_seconds() & STTIMER_SLOTTIMEMASK;

	spin_lock_init(&stt_data.stt_lock);
	for (i = 0; i < STTIMER_NSLOTS; i++)
		INIT_LIST_HEAD(&stt_data.stt_hash[i]);

	stt_data.stt_nthreads = 0;
	init_waitqueue_head(&stt_data.stt_waitq);
	rc = stt_start_timer_thread();
	if (rc)
		CERROR("Can't spawn timer thread: %d\n", rc);

	return rc;
}

void
stt_shutdown(void)
{
	int i;

	spin_lock(&stt_data.stt_lock);

	for (i = 0; i < STTIMER_NSLOTS; i++)
		LASSERT(list_empty(&stt_data.stt_hash[i]));

	stt_data.stt_shuttingdown = 1;

	wake_up(&stt_data.stt_waitq);
	lst_wait_until(!stt_data.stt_nthreads, stt_data.stt_lock,
		       "waiting for %d threads to terminate\n",
		       stt_data.stt_nthreads);

	spin_unlock(&stt_data.stt_lock);
}

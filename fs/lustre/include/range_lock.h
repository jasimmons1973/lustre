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
 * Range lock is used to allow multiple threads writing a single shared
 * file given each thread is writing to a non-overlapping portion of the
 * file.
 *
 * Refer to the possible upstream kernel version of range lock by
 * Jan Kara <jack@suse.cz>: https://lkml.org/lkml/2013/1/31/480
 *
 * This file could later replaced by the upstream kernel version.
 */
/*
 * Author: Prakash Surya <surya1@llnl.gov>
 * Author: Bobi Jam <bobijam.xu@intel.com>
 */
#ifndef _RANGE_LOCK_H
#define _RANGE_LOCK_H

#include <linux/spinlock.h>
#include <linux/rbtree.h>

struct range_lock {
	struct rb_node		rl_rb;
	u64			rl_start, rl_last;
	u64			__subtree_last;
	/**
	 * Process to enqueue this lock.
	 */
	struct task_struct	*rl_task;
	/**
	 * Number of ranges which are blocking acquisition of the lock
	 */
	unsigned int		rl_blocking_ranges;
	/**
	 * Sequence number of range lock. This number is used to get to know
	 * the order the locks are queued; this is required for range_cancel().
	 */
	u64			rl_sequence;
};

struct range_lock_tree {
	struct rb_root_cached	rlt_root;
	spinlock_t		rlt_lock;	/* protect range lock tree */
	u64			rlt_sequence;
};

void range_lock_tree_init(struct range_lock_tree *tree);
int range_lock_init(struct range_lock *lock, u64 start, u64 end);
int  range_lock(struct range_lock_tree *tree, struct range_lock *lock);
void range_unlock(struct range_lock_tree *tree, struct range_lock *lock);
#endif

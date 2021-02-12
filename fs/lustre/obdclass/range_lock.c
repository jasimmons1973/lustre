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
#include <linux/sched/signal.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <range_lock.h>
#include <linux/libcfs/libcfs.h>
#include <linux/interval_tree_generic.h>

#define START(node) ((node)->rl_start)
#define LAST(node)  ((node)->rl_last)

INTERVAL_TREE_DEFINE(struct range_lock, rl_rb, u64, __subtree_last,
		     START, LAST, static, range);
/**
 * Initialize a range lock tree
 *
 * @tree	an empty range lock tree
 *
 * Pre:  Caller should have allocated the range lock tree.
 * Post: The range lock tree is ready to function.
 */
void range_lock_tree_init(struct range_lock_tree *tree)
{
	tree->rlt_root = RB_ROOT_CACHED;
	tree->rlt_sequence = 0;
	spin_lock_init(&tree->rlt_lock);
}
EXPORT_SYMBOL(range_lock_tree_init);

/**
 * Initialize a range lock node
 *
 * @lock	an empty range lock node
 * @start	start of the covering region
 * @end		end of the covering region
 *
 * Pre:  Caller should have allocated the range lock node.
 * Post: The range lock node is meant to cover [start, end] region
 */
int range_lock_init(struct range_lock *lock, u64 start, u64 end)
{
	RB_CLEAR_NODE(&lock->rl_rb);

	if (end != LUSTRE_EOF)
		end >>= PAGE_SHIFT;
	lock->rl_start = start >> PAGE_SHIFT;
	lock->rl_last = end;
	if (lock->rl_start > lock->rl_last)
		return -ERANGE;

	lock->rl_task = NULL;
	lock->rl_blocking_ranges = 0;
	lock->rl_sequence = 0;
	return 0;
}
EXPORT_SYMBOL(range_lock_init);

/**
 * Unlock a range lock, wake up locks blocked by this lock.
 *
 * @tree	range lock tree
 * @lock	range lock to be deleted
 *
 * If this lock has been granted, relase it; if not, just delete it from
 * the tree or the same region lock list. Wake up those locks only blocked
 * by this lock.
 */
void range_unlock(struct range_lock_tree *tree, struct range_lock *lock)
{
	struct range_lock *overlap;

	spin_lock(&tree->rlt_lock);
	LASSERT(!RB_EMPTY_NODE(&lock->rl_rb));
	range_remove(lock, &tree->rlt_root);

	for (overlap = range_iter_first(&tree->rlt_root,
					lock->rl_start, lock->rl_last);
	     overlap;
	     overlap = range_iter_next(overlap, lock->rl_start, lock->rl_last))
		if (overlap->rl_sequence > lock->rl_sequence) {
			--overlap->rl_blocking_ranges;
			if (overlap->rl_blocking_ranges == 0)
				wake_up_process(overlap->rl_task);
		}

	spin_unlock(&tree->rlt_lock);
}
EXPORT_SYMBOL(range_unlock);

/**
 * Lock a region
 *
 * @tree	range lock tree
 * @lock	range lock node containing the region span
 *
 * Return:	0 get the range lock
 *		<0 error code while not getting the range lock
 *
 * If there exists overlapping range lock, the new lock will wait and
 * retry, if later it find that it is not the chosen one to wake up,
 * it wait again.
 */
int range_lock(struct range_lock_tree *tree, struct range_lock *lock)
{
	int rc = 0;
	struct range_lock *it;

	spin_lock(&tree->rlt_lock);
	/*
	 * We need to check for all conflicting intervals
	 * already in the tree.
	 */
	for (it = range_iter_first(&tree->rlt_root,
				   lock->rl_start, lock->rl_last);
	     it;
	     it = range_iter_next(it, lock->rl_start, lock->rl_last))
		lock->rl_blocking_ranges++;

	range_insert(lock, &tree->rlt_root);
	lock->rl_sequence = ++tree->rlt_sequence;

	while (lock->rl_blocking_ranges > 0) {
		lock->rl_task = current;
		__set_current_state(TASK_INTERRUPTIBLE);
		spin_unlock(&tree->rlt_lock);
		schedule();

		if (signal_pending(current)) {
			range_unlock(tree, lock);
			rc = -ERESTARTSYS;
			goto out;
		}
		spin_lock(&tree->rlt_lock);
	}
	spin_unlock(&tree->rlt_lock);
out:
	return rc;
}
EXPORT_SYMBOL(range_lock);

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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_extent.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

/**
 * This file contains implementation of EXTENT lock type
 *
 * EXTENT lock type is for locking a contiguous range of values, represented
 * by 64-bit starting and ending offsets (inclusive). There are several extent
 * lock modes, some of which may be mutually incompatible. Extent locks are
 * considered incompatible if their modes are incompatible and their extents
 * intersect.  See the lock mode compatibility matrix in lustre_dlm.h.
 */

#define DEBUG_SUBSYSTEM S_LDLM
#include <lustre_dlm.h>
#include <obd_support.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include "ldlm_internal.h"

/* When a lock is cancelled by a client, the KMS may undergo change if this
 * is the "highest lock".  This function returns the new KMS value.
 * Caller must hold lr_lock already.
 *
 * NB: A lock on [x,y] protects a KMS of up to y + 1 bytes!
 */
__u64 ldlm_extent_shift_kms(struct ldlm_lock *lock, __u64 old_kms)
{
	struct ldlm_resource *res = lock->l_resource;
	struct ldlm_lock *lck;
	__u64 kms = 0;

	/* don't let another thread in ldlm_extent_shift_kms race in
	 * just after we finish and take our lock into account in its
	 * calculation of the kms
	 */
	ldlm_set_kms_ignore(lock);

	list_for_each_entry(lck, &res->lr_granted, l_res_link) {

		if (ldlm_is_kms_ignore(lck))
			continue;

		if (lck->l_policy_data.l_extent.end >= old_kms)
			return old_kms;

		/* This extent _has_ to be smaller than old_kms (checked above)
		 * so kms can only ever be smaller or the same as old_kms.
		 */
		if (lck->l_policy_data.l_extent.end + 1 > kms)
			kms = lck->l_policy_data.l_extent.end + 1;
	}
	LASSERTF(kms <= old_kms, "kms %llu old_kms %llu\n", kms, old_kms);

	return kms;
}
EXPORT_SYMBOL(ldlm_extent_shift_kms);

static inline int lock_mode_to_index(enum ldlm_mode mode)
{
	int index;

	LASSERT(mode != 0);
	LASSERT(is_power_of_2(mode));
	for (index = -1; mode; index++)
		mode >>= 1;
	LASSERT(index < LCK_MODE_NUM);
	return index;
}

/** Add newly granted lock into interval tree for the resource. */
void ldlm_extent_add_lock(struct ldlm_resource *res,
			  struct ldlm_lock *lock)
{
	struct interval_node **root;
	struct ldlm_extent *extent;
	int idx, rc;

	LASSERT(lock->l_granted_mode == lock->l_req_mode);

	LASSERT(!interval_is_intree(&lock->l_tree_node));

	idx = lock_mode_to_index(lock->l_granted_mode);
	LASSERT(lock->l_granted_mode == 1 << idx);
	LASSERT(lock->l_granted_mode == res->lr_itree[idx].lit_mode);

	/* node extent initialize */
	extent = &lock->l_policy_data.l_extent;
	rc = interval_set(&lock->l_tree_node, extent->start, extent->end);
	LASSERT(!rc);

	root = &res->lr_itree[idx].lit_root;
	interval_insert(&lock->l_tree_node, root);
	res->lr_itree[idx].lit_size++;

	/* even though we use interval tree to manage the extent lock, we also
	 * add the locks into grant list, for debug purpose, ..
	 */
	ldlm_resource_add_lock(res, &res->lr_granted, lock);

	if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_GRANT_CHECK)) {
		struct ldlm_lock *lck;

		list_for_each_entry_reverse(lck, &res->lr_granted,
					    l_res_link) {
			if (lck == lock)
				continue;
			if (lockmode_compat(lck->l_granted_mode,
					    lock->l_granted_mode))
				continue;
			if (ldlm_extent_overlap(&lck->l_req_extent,
						&lock->l_req_extent)) {
				CDEBUG(D_ERROR,
				       "granting conflicting lock %p %p\n",
				       lck, lock);
				ldlm_resource_dump(D_ERROR, res);
				LBUG();
			}
		}
	}
}

/** Remove cancelled lock from resource interval tree. */
void ldlm_extent_unlink_lock(struct ldlm_lock *lock)
{
	struct ldlm_resource *res = lock->l_resource;
	struct ldlm_interval_tree *tree;
	int idx;

	if (!interval_is_intree(&lock->l_tree_node)) /* duplicate unlink */
		return;

	idx = lock_mode_to_index(lock->l_granted_mode);
	LASSERT(lock->l_granted_mode == 1 << idx);
	tree = &res->lr_itree[idx];

	LASSERT(tree->lit_root); /* assure the tree is not null */

	tree->lit_size--;
	interval_erase(&lock->l_tree_node, &tree->lit_root);
}

void ldlm_extent_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				      union ldlm_policy_data *lpolicy)
{
	lpolicy->l_extent.start = wpolicy->l_extent.start;
	lpolicy->l_extent.end = wpolicy->l_extent.end;
	lpolicy->l_extent.gid = wpolicy->l_extent.gid;
}

void ldlm_extent_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				      union ldlm_wire_policy_data *wpolicy)
{
	memset(wpolicy, 0, sizeof(*wpolicy));
	wpolicy->l_extent.start = lpolicy->l_extent.start;
	wpolicy->l_extent.end = lpolicy->l_extent.end;
	wpolicy->l_extent.gid = lpolicy->l_extent.gid;
}

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
 *
 * lnet/lnet/lib-me.c
 *
 * Match Entry management routines
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/lnet/lib-lnet.h>

/**
 * Create and attach a match entry to the match list of @portal. The new
 * ME is empty, i.e. not associated with a memory descriptor. LNetMDAttach()
 * can be used to attach a MD to an empty ME.
 *
 * @portal	The portal table index where the ME should be attached.
 * @match_id	Specifies the match criteria for the process ID of
 *		the requester. The constants LNET_PID_ANY and LNET_NID_ANY
 *		can be used to wildcard either of the identifiers in the
 *		lnet_process_id structure.
 * @match_bits
 * @ignore_bits Specify the match criteria to apply to the match bits in the
 *		incoming request. The ignore bits are used to mask out
 *		insignificant bits in the incoming match bits. The resulting
 *		bits are then compared to the ME's match bits to determine if
 *		the incoming request meets the match criteria.
 * @unlink	Indicates whether the ME should be unlinked when the memory
 *		descriptor associated with it is unlinked (Note that the check
 *		for unlinking a ME only occurs when the memory descriptor is
 *		unlinked.). Valid values are LNET_RETAIN and LNET_UNLINK.
 * @pos		Indicates whether the new ME should be prepended or
 *		appended to the match list. Allowed constants: LNET_INS_BEFORE,
 *		LNET_INS_AFTER.
 *
 * Return:	0 On success. handle to the newly created ME is returned on success
 *		ERR_PTR(-EINVAL) If \a portal is invalid.
 *		ERR_PTR(-ENOMEM) If new ME object cannot be allocated.
 */
struct lnet_me *
LNetMEAttach(unsigned int portal,
	     struct lnet_processid *match_id,
	     u64 match_bits, u64 ignore_bits,
	     enum lnet_unlink unlink, enum lnet_ins_pos pos)
{
	struct lnet_match_table *mtable;
	struct lnet_me *me;
	struct list_head *head;

	LASSERT(the_lnet.ln_refcount > 0);

	if ((int)portal >= the_lnet.ln_nportals)
		return ERR_PTR(-EINVAL);

	mtable = lnet_mt_of_attach(portal, match_id,
				   match_bits, ignore_bits, pos);
	if (!mtable) /* can't match portal type */
		return ERR_PTR(-EPERM);

	me = kmem_cache_zalloc(lnet_mes_cachep, GFP_NOFS);
	if (!me)
		return ERR_PTR(-ENOMEM);

	lnet_res_lock(mtable->mt_cpt);

	me->me_portal = portal;
	me->me_match_id = *match_id;
	me->me_match_bits = match_bits;
	me->me_ignore_bits = ignore_bits;
	me->me_unlink = unlink;
	me->me_md = NULL;

	me->me_cpt = mtable->mt_cpt;

	if (ignore_bits)
		head = &mtable->mt_mhash[LNET_MT_HASH_IGNORE];
	else
		head = lnet_mt_match_head(mtable, match_id, match_bits);

	me->me_pos = head - &mtable->mt_mhash[0];
	if (pos == LNET_INS_AFTER || pos == LNET_INS_LOCAL)
		list_add_tail(&me->me_list, head);
	else
		list_add(&me->me_list, head);

	lnet_res_unlock(mtable->mt_cpt);
	return me;
}
EXPORT_SYMBOL(LNetMEAttach);

/* call with lnet_res_lock please */
void
lnet_me_unlink(struct lnet_me *me)
{
	list_del(&me->me_list);

	if (me->me_md) {
		struct lnet_libmd *md = me->me_md;

		/* detach MD from portal of this ME */
		lnet_ptl_detach_md(me, md);
		lnet_md_unlink(md);
	}

	kfree(me);
}

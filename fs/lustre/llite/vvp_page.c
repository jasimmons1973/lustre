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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_page for VVP layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>

#include "llite_internal.h"
#include "vvp_internal.h"

/*****************************************************************************
 *
 * Page operations.
 *
 */
static void vvp_page_discard(const struct lu_env *env,
			     const struct cl_page_slice *slice,
			     struct cl_io *unused)
{
	struct cl_page *cp = slice->cpl_page;
	struct page *vmpage = cp->cp_vmpage;

	if (cp->cp_defer_uptodate && !cp->cp_ra_used && vmpage->mapping)
		ll_ra_stats_inc(vmpage->mapping->host, RA_STAT_DISCARDED);
}

/**
 * Handles page transfer errors at VM level.
 *
 * This takes inode as a separate argument, because inode on which error is to
 * be set can be different from @vmpage inode in case of direct-io.
 */
static void vvp_vmpage_error(struct inode *inode, struct page *vmpage,
			     int ioret)
{
	struct vvp_object *obj = cl_inode2vvp(inode);

	if (ioret == 0) {
		ClearPageError(vmpage);
		obj->vob_discard_page_warned = 0;
	} else {
		SetPageError(vmpage);
		mapping_set_error(inode->i_mapping, ioret);

		if ((ioret == -ESHUTDOWN || ioret == -EINTR ||
		     ioret == -EIO) && obj->vob_discard_page_warned == 0) {
			obj->vob_discard_page_warned = 1;
			ll_dirty_page_discard_warn(inode, ioret);
		}
	}
}

static void vvp_page_completion_read(const struct lu_env *env,
				     const struct cl_page_slice *slice,
				     int ioret)
{
	struct cl_page *cp = slice->cpl_page;
	struct page *vmpage = cp->cp_vmpage;
	struct inode *inode = vvp_object_inode(cp->cp_obj);

	LASSERT(PageLocked(vmpage));
	CL_PAGE_HEADER(D_PAGE, env, cp, "completing READ with %d\n", ioret);

	if (cp->cp_defer_uptodate)
		ll_ra_count_put(ll_i2sbi(inode), 1);

	if (ioret == 0)  {
		if (!cp->cp_defer_uptodate)
			SetPageUptodate(vmpage);
	} else if (cp->cp_defer_uptodate) {
		cp->cp_defer_uptodate = 0;
		if (ioret == -EAGAIN) {
			/* mirror read failed, it needs to destroy the page
			 * because subpage would be from wrong osc when trying
			 * to read from a new mirror
			 */
			generic_error_remove_page(vmpage->mapping, vmpage);
		}
	}

	if (!cp->cp_sync_io)
		unlock_page(vmpage);
}

static void vvp_page_completion_write(const struct lu_env *env,
				      const struct cl_page_slice *slice,
				      int ioret)
{
	struct cl_page *cp = slice->cpl_page;
	struct page *vmpage = cp->cp_vmpage;

	CL_PAGE_HEADER(D_PAGE, env, cp, "completing WRITE with %d\n", ioret);

	if (cp->cp_sync_io) {
		LASSERT(PageLocked(vmpage));
		LASSERT(!PageWriteback(vmpage));
	} else {
		LASSERT(PageWriteback(vmpage));
		/*
		 * Only mark the page error only when it's an async write
		 * because applications won't wait for IO to finish.
		 */
		vvp_vmpage_error(vvp_object_inode(cp->cp_obj), vmpage, ioret);

		end_page_writeback(vmpage);
	}
}

static const struct cl_page_operations vvp_page_ops = {
	.cpo_discard		= vvp_page_discard,
	.io = {
		[CRT_READ] = {
			.cpo_completion	= vvp_page_completion_read,
		},
		[CRT_WRITE] = {
			.cpo_completion = vvp_page_completion_write,
		},
	},
};

static const struct cl_page_operations vvp_transient_page_ops = {
};

int vvp_page_init(const struct lu_env *env, struct cl_object *obj,
		  struct cl_page *page, pgoff_t index)
{
	struct cl_page_slice *cpl = cl_object_page_slice(obj, page);
	struct page *vmpage = page->cp_vmpage;

	CLOBINVRNT(env, obj, vvp_object_invariant(obj));

	if (page->cp_type == CPT_TRANSIENT) {
		/* DIO pages are referenced by userspace, we don't need to take
		 * a reference on them. (contrast with get_page() call above)
		 */
		cl_page_slice_add(page, cpl, obj,
				  &vvp_transient_page_ops);
	} else {
		get_page(vmpage);
		/* in cache, decref in cl_page_delete */
		refcount_inc(&page->cp_ref);
		SetPagePrivate(vmpage);
		vmpage->private = (unsigned long)page;
		cl_page_slice_add(page, cpl, obj, &vvp_page_ops);
	}
	return 0;
}

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

static int vvp_page_prep_read(const struct lu_env *env,
			      const struct cl_page_slice *slice,
			      struct cl_io *unused)
{
	/* Skip the page already marked as PG_uptodate. */
	return PageUptodate(cl2vm_page(slice)) ? -EALREADY : 0;
}

static int vvp_page_prep_write(const struct lu_env *env,
			       const struct cl_page_slice *slice,
			       struct cl_io *unused)
{
	struct page *vmpage = cl2vm_page(slice);
	struct cl_page *pg = slice->cpl_page;

	LASSERT(PageLocked(vmpage));
	LASSERT(!PageDirty(vmpage));

	/* ll_writepage path is not a sync write, so need to set page writeback
	 * flag
	 */
	if (!pg->cp_sync_io)
		set_page_writeback(vmpage);

	return 0;
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
	struct vvp_page *vpg = cl2vvp_page(slice);
	struct cl_page *pg = slice->cpl_page;
	struct page *vmpage = vpg->vpg_page;

	CL_PAGE_HEADER(D_PAGE, env, pg, "completing WRITE with %d\n", ioret);

	if (pg->cp_sync_io) {
		LASSERT(PageLocked(vmpage));
		LASSERT(!PageWriteback(vmpage));
	} else {
		LASSERT(PageWriteback(vmpage));
		/*
		 * Only mark the page error only when it's an async write
		 * because applications won't wait for IO to finish.
		 */
		vvp_vmpage_error(vvp_object_inode(pg->cp_obj), vmpage, ioret);

		end_page_writeback(vmpage);
	}
}

/**
 * Implements cl_page_operations::cpo_make_ready() method.
 *
 * This is called to yank a page from the transfer cache and to send it out as
 * a part of transfer. This function try-locks the page. If try-lock failed,
 * page is owned by some concurrent IO, and should be skipped (this is bad,
 * but hopefully rare situation, as it usually results in transfer being
 * shorter than possible).
 *
 * Return:	0 success, page can be placed into transfer
 *
 *		-EAGAIN page is either used by concurrent IO has been
 *		truncated. Skip it.
 */
static int vvp_page_make_ready(const struct lu_env *env,
			       const struct cl_page_slice *slice)
{
	struct page *vmpage = cl2vm_page(slice);
	struct cl_page *pg = slice->cpl_page;
	int result = 0;

	lock_page(vmpage);
	if (clear_page_dirty_for_io(vmpage)) {
		LASSERT(pg->cp_state == CPS_CACHED);
		/* This actually clears the dirty bit in the radix tree. */
		set_page_writeback(vmpage);
		CL_PAGE_HEADER(D_PAGE, env, pg, "readied\n");
	} else if (pg->cp_state == CPS_PAGEOUT) {
		/* is it possible for osc_flush_async_page() to already
		 * make it ready?
		 */
		result = -EALREADY;
	} else {
		CL_PAGE_DEBUG(D_ERROR, env, pg, "Unexpecting page state %d.\n",
			      pg->cp_state);
		LBUG();
	}
	unlock_page(vmpage);
	return result;
}

static int vvp_page_print(const struct lu_env *env,
			  const struct cl_page_slice *slice,
			  void *cookie, lu_printer_t printer)
{
	struct vvp_page *vpg = cl2vvp_page(slice);
	struct page *vmpage = vpg->vpg_page;

	(*printer)(env, cookie,
		   LUSTRE_VVP_NAME"-page@%p vm@%p ", vpg, vmpage);
	if (vmpage) {
		(*printer)(env, cookie, "%lx %d:%d %lx %lu %slru",
			   (long)vmpage->flags, page_count(vmpage),
			   page_mapcount(vmpage), vmpage->private,
			   vmpage->index,
			   list_empty(&vmpage->lru) ? "not-" : "");
	}

	(*printer)(env, cookie, "\n");

	return 0;
}

static int vvp_page_fail(const struct lu_env *env,
			 const struct cl_page_slice *slice)
{
	/*
	 * Cached read?
	 */
	LBUG();

	return 0;
}

static const struct cl_page_operations vvp_page_ops = {
	.cpo_discard		= vvp_page_discard,
	.cpo_print		= vvp_page_print,
	.io = {
		[CRT_READ] = {
			.cpo_prep	= vvp_page_prep_read,
			.cpo_completion	= vvp_page_completion_read,
			.cpo_make_ready = vvp_page_fail,
		},
		[CRT_WRITE] = {
			.cpo_prep	= vvp_page_prep_write,
			.cpo_completion = vvp_page_completion_write,
			.cpo_make_ready = vvp_page_make_ready,
		},
	},
};

static const struct cl_page_operations vvp_transient_page_ops = {
	.cpo_print		= vvp_page_print,
};

int vvp_page_init(const struct lu_env *env, struct cl_object *obj,
		  struct cl_page *page, pgoff_t index)
{
	struct vvp_page *vpg = cl_object_page_slice(obj, page);
	struct page *vmpage = page->cp_vmpage;

	CLOBINVRNT(env, obj, vvp_object_invariant(obj));

	vpg->vpg_page = vmpage;

	if (page->cp_type == CPT_TRANSIENT) {
		/* DIO pages are referenced by userspace, we don't need to take
		 * a reference on them. (contrast with get_page() call above)
		 */
		cl_page_slice_add(page, &vpg->vpg_cl, obj,
				  &vvp_transient_page_ops);
	} else {
		get_page(vmpage);
		/* in cache, decref in cl_page_delete */
		refcount_inc(&page->cp_ref);
		SetPagePrivate(vmpage);
		vmpage->private = (unsigned long)page;
		cl_page_slice_add(page, &vpg->vpg_cl, obj,
				  &vvp_page_ops);
	}
	return 0;
}

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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lustre/llite/rw26.c
 *
 * Lustre Lite I/O page cache routines for the 2.5/2.6 kernel version
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>

#include <linux/migrate.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include "llite_internal.h"

/**
 * Implements Linux VM address_space::invalidatepage() method. This method is
 * called when the page is truncate from a file, either as a result of
 * explicit truncate, or when inode is removed from memory (as a result of
 * final iput(), umount, or memory pressure induced icache shrinking).
 *
 * [0, offset] bytes of the page remain valid (this is for a case of not-page
 * aligned truncate). Lustre leaves partially truncated page in the cache,
 * relying on struct inode::i_size to limit further accesses.
 */
static void ll_invalidatepage(struct page *vmpage, unsigned int offset,
			      unsigned int length)
{
	struct inode *inode;
	struct lu_env *env;
	struct cl_page *page;
	struct cl_object *obj;

	LASSERT(PageLocked(vmpage));
	LASSERT(!PageWriteback(vmpage));

	/*
	 * It is safe to not check anything in invalidatepage/releasepage
	 * below because they are run with page locked and all our io is
	 * happening with locked page too
	 */
	if (offset == 0 && length == PAGE_SIZE) {
		/* See the comment in ll_releasepage() */
		env = cl_env_percpu_get();
		LASSERT(!IS_ERR(env));
		inode = vmpage->mapping->host;
		obj = ll_i2info(inode)->lli_clob;
		if (obj) {
			page = cl_vmpage_page(vmpage, obj);
			if (page) {
				cl_page_delete(env, page);
				cl_page_put(env, page);
			}
		} else {
			LASSERT(vmpage->private == 0);
		}
		cl_env_percpu_put(env);
	}
}

static int ll_releasepage(struct page *vmpage, gfp_t gfp_mask)
{
	struct lu_env *env;
	struct cl_object *obj;
	struct cl_page *page;
	struct address_space *mapping;
	int result = 0;

	LASSERT(PageLocked(vmpage));
	if (PageWriteback(vmpage) || PageDirty(vmpage))
		return 0;

	mapping = vmpage->mapping;
	if (!mapping)
		return 1;

	obj = ll_i2info(mapping->host)->lli_clob;
	if (!obj)
		return 1;

	page = cl_vmpage_page(vmpage, obj);
	if (!page)
		return 1;

	env = cl_env_percpu_get();
	LASSERT(!IS_ERR(env));

	if (!cl_page_in_use(page)) {
		result = 1;
		cl_page_delete(env, page);
	}

	/* To use percpu env array, the call path can not be rescheduled;
	 * otherwise percpu array will be messed if ll_releaspage() called
	 * again on the same CPU.
	 *
	 * If this page holds the last refc of cl_object, the following
	 * call path may cause reschedule:
	 *   cl_page_put -> cl_page_free -> cl_object_put ->
	 *     lu_object_put -> lu_object_free -> lov_delete_raid0.
	 *
	 * However, the kernel can't get rid of this inode until all pages have
	 * been cleaned up. Now that we hold page lock here, it's pretty safe
	 * that we won't get into object delete path.
	 */
	LASSERT(cl_object_refc(obj) > 1);
	cl_page_put(env, page);

	cl_env_percpu_put(env);
	return result;
}

/*
 * ll_free_user_pages - tear down page struct array
 * @pages: array of page struct pointers underlying target buffer
 */
static void ll_free_user_pages(struct page **pages, int npages)
{
	int i;

	for (i = 0; i < npages; i++) {
		if (!pages[i])
			break;
		put_page(pages[i]);
	}
	kvfree(pages);
}

static ssize_t ll_get_user_pages(int rw, struct iov_iter *iter,
				struct page ***pages, ssize_t *npages,
				size_t maxsize)
{
	size_t start;
	size_t result;

	result = iov_iter_get_pages_alloc(iter, pages, maxsize, &start);
	if (result > 0)
		*npages = DIV_ROUND_UP(result + start, PAGE_SIZE);

	return result;
}

/* direct IO pages */
struct ll_dio_pages {
	struct cl_dio_aio	*ldp_aio;
	/*
	 * page array to be written. we don't support
	 * partial pages except the last one.
	 */
	struct page		**ldp_pages;
	/* # of pages in the array. */
	size_t			ldp_count;
	/* the file offset of the first page. */
	loff_t			ldp_file_offset;
};

static int
ll_direct_rw_pages(const struct lu_env *env, struct cl_io *io, size_t size,
		   int rw, struct inode *inode, struct ll_dio_pages *pv)
{
	struct cl_page *page;
	struct cl_2queue *queue = &io->ci_queue;
	struct cl_object *obj = io->ci_obj;
	struct cl_sync_io *anchor = &pv->ldp_aio->cda_sync;
	loff_t offset = pv->ldp_file_offset;
	int io_pages = 0;
	size_t page_size = cl_page_size(obj);
	int i;
	pgoff_t index = offset >> PAGE_SHIFT;
	ssize_t rc = 0;

	cl_2queue_init(queue);
	for (i = 0; i < pv->ldp_count; i++) {
		LASSERT(!(offset & (PAGE_SIZE - 1)));
		page = cl_page_find(env, obj, cl_index(obj, offset),
				    pv->ldp_pages[i], CPT_TRANSIENT);
		if (IS_ERR(page)) {
			rc = PTR_ERR(page);
			break;
		}
		LASSERT(page->cp_type == CPT_TRANSIENT);
		rc = cl_page_own(env, io, page);
		if (rc) {
			cl_page_put(env, page);
			break;
		}

		page->cp_sync_io = anchor;
		if (inode && IS_ENCRYPTED(inode)) {
			struct page *vmpage = cl_page_vmpage(page);

			/* In case of Direct IO on encrypted file, we need to
			 * set the correct page index, and add a reference to
			 * the mapping. This is required by llcrypt to proceed
			 * to encryption/decryption, because each block is
			 * encrypted independently, and each block's IV is set
			 * to the logical block number within the file.
			 * This is safe because we know these pages are private
			 * to the thread doing the Direct IO, and despite
			 * setting a mapping on the pages, cached lookups will
			 * not find them.
			 * Set PageChecked to detect special case of Direct IO
			 * in osc_brw_fini_request().
			 * Reference to the mapping and PageChecked flag are
			 * removed in cl_aio_end().
			 */
			vmpage->index = index++;
			vmpage->mapping = inode->i_mapping;
			SetPageChecked(vmpage);
		}
		cl_page_list_add(&queue->c2_qin, page);
		/*
		 * Set page clip to tell transfer formation engine
		 * that page has to be sent even if it is beyond KMS.
		 */
		cl_page_clip(env, page, 0, min(size, page_size));
		++io_pages;

		/* drop the reference count for cl_page_find */
		cl_page_put(env, page);
		offset += page_size;
		size -= page_size;
	}
	if (rc == 0 && io_pages > 0) {
		int iot = rw == READ ? CRT_READ : CRT_WRITE;

		atomic_add(io_pages, &anchor->csi_sync_nr);
		/*
		 * Avoid out-of-order execution of adding inflight
		 * modifications count and io submit.
		 */
		smp_mb();
		rc = cl_io_submit_rw(env, io, iot, queue);
		if (rc == 0) {
			cl_page_list_splice(&queue->c2_qout,
					&pv->ldp_aio->cda_pages);
		} else {
			atomic_add(-queue->c2_qin.pl_nr,
				   &anchor->csi_sync_nr);
			cl_page_list_for_each(page, &queue->c2_qin)
				page->cp_sync_io = NULL;
		}
		/* handle partially submitted reqs */
		if (queue->c2_qin.pl_nr > 0) {
			CERROR(DFID " failed to submit %d dio pages: %zd\n",
			       PFID(lu_object_fid(&obj->co_lu)),
			       queue->c2_qin.pl_nr, rc);
			if (rc == 0)
				rc = -EIO;
		}
	}

	cl_2queue_discard(env, io, queue);
	cl_2queue_disown(env, io, queue);
	cl_2queue_fini(env, queue);
	return rc;
}

/* This is the maximum size of a single O_DIRECT request, based on the
 * kmalloc limit.  We need to fit all of the brw_page structs, each one
 * representing PAGE_SIZE worth of user data, into a single buffer, and
 * then truncate this to be a full-sized RPC.  For 4kB PAGE_SIZE this is
 * up to 22MB for 128kB kmalloc and up to 682MB for 4MB kmalloc.
 */
#define MAX_DIO_SIZE ((KMALLOC_MAX_SIZE / sizeof(struct brw_page) * PAGE_SIZE) & \
		      ~((size_t)DT_MAX_BRW_SIZE - 1))

static ssize_t ll_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct ll_cl_context *lcc;
	const struct lu_env *env;
	struct cl_io *io;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct cl_dio_aio *aio;
	size_t count = iov_iter_count(iter);
	ssize_t tot_bytes = 0, result = 0;
	loff_t file_offset = iocb->ki_pos;
	int rw = iov_iter_rw(iter);
	struct vvp_io *vio;

	/* Check EOF by ourselves */
	if (rw == READ && file_offset >= i_size_read(inode))
		return 0;

	/* FIXME: io smaller than PAGE_SIZE is broken on ia64 ??? */
	if ((file_offset & ~PAGE_MASK) || (count & ~PAGE_MASK))
		return -EINVAL;

	CDEBUG(D_VFSTRACE,
	       "VFS Op:inode=" DFID "(%p), size=%zd (max %lu), offset=%lld=%llx, pages %zd (max %lu)\n",
	       PFID(ll_inode2fid(inode)), inode, count, MAX_DIO_SIZE,
	       file_offset, file_offset, count >> PAGE_SHIFT,
	       MAX_DIO_SIZE >> PAGE_SHIFT);

	/* Check that all user buffers are aligned as well */
	if (iov_iter_alignment(iter) & ~PAGE_MASK)
		return -EINVAL;

	lcc = ll_cl_find(file);
	if (!lcc)
		return -EIO;

	env = lcc->lcc_env;
	LASSERT(!IS_ERR(env));
	vio = vvp_env_io(env);
	io = lcc->lcc_io;
	LASSERT(io);

	aio = io->ci_aio;
	LASSERT(aio);
	LASSERT(aio->cda_iocb == iocb);

	while (iov_iter_count(iter)) {
		struct ll_dio_pages pvec = { .ldp_aio = aio };
		struct page **pages;

		count = min_t(size_t, iov_iter_count(iter), MAX_DIO_SIZE);
		if (rw == READ) {
			if (file_offset >= i_size_read(inode))
				break;

			if (file_offset + count > i_size_read(inode))
				count = i_size_read(inode) - file_offset;
		}

		result = ll_get_user_pages(rw, iter, &pages,
					   &pvec.ldp_count, count);
		if (unlikely(result <= 0))
			goto out;

		count = result;
		pvec.ldp_file_offset = file_offset;
		pvec.ldp_pages = pages;

		result = ll_direct_rw_pages(env, io, count,
					    rw, inode, &pvec);
		ll_free_user_pages(pages, pvec.ldp_count);

		if (unlikely(result < 0))
			goto out;

		iov_iter_advance(iter, count);
		tot_bytes += count;
		file_offset += count;
	}

out:
	aio->cda_bytes += tot_bytes;

	if (is_sync_kiocb(iocb)) {
		struct cl_sync_io *anchor = &aio->cda_sync;
		ssize_t rc2;

		/**
		 * @anchor was inited as 1 to prevent end_io to be
		 * called before we add all pages for IO, so drop
		 * one extra reference to make sure we could wait
		 * count to be zero.
		 */
		cl_sync_io_note(env, anchor, result);

		rc2 = cl_sync_io_wait(env, anchor, 0);
		if (result == 0 && rc2)
			result = rc2;

		/**
		 * One extra reference again, as if @anchor is
		 * reused we assume it as 1 before using.
		 */
		atomic_add(1, &anchor->csi_sync_nr);
		if (result == 0) {
			/* no commit async for direct IO */
			vio->u.readwrite.vui_written += tot_bytes;
			result = tot_bytes;
		}
	} else {
		if (rw == WRITE)
			vio->u.readwrite.vui_written += tot_bytes;
		else
			vio->u.readwrite.vui_read += tot_bytes;
		result = -EIOCBQUEUED;
	}

	return result;
}

/**
 * Prepare partially written-to page for a write.
 * @pg is owned when passed in and disowned when it returns non-zero result to
 * the caller.
 */
static int ll_prepare_partial_page(const struct lu_env *env, struct cl_io *io,
				   struct cl_page *pg, struct file *file)
{
	struct cl_attr *attr = vvp_env_thread_attr(env);
	struct cl_object *obj = io->ci_obj;
	struct vvp_page *vpg = cl_object_page_slice(obj, pg);
	loff_t offset = cl_offset(obj, vvp_index(vpg));
	int result;

	cl_object_attr_lock(obj);
	result = cl_object_attr_get(env, obj, attr);
	cl_object_attr_unlock(obj);
	if (result) {
		cl_page_disown(env, io, pg);
		goto out;
	}

	/*
	 * If are writing to a new page, no need to read old data.
	 * The extent locking will have updated the KMS, and for our
	 * purposes here we can treat it like i_size.
	 */
	if (attr->cat_kms <= offset) {
		char *kaddr = kmap_atomic(vpg->vpg_page);

		memset(kaddr, 0, cl_page_size(obj));
		kunmap_atomic(kaddr);
		result = 0;
		goto out;
	}

	if (vpg->vpg_defer_uptodate) {
		vpg->vpg_ra_used = 1;
		result = 0;
		goto out;
	}

	result = ll_io_read_page(env, io, pg, file);
	if (result)
		goto out;

	/* ll_io_read_page() disowns the page */
	result = cl_page_own(env, io, pg);
	if (!result) {
		if (!PageUptodate(cl_page_vmpage(pg))) {
			cl_page_disown(env, io, pg);
			result = -EIO;
		}
	} else if (result == -ENOENT) {
		/* page was truncated */
		result = -EAGAIN;
	}

out:
	return result;
}

static int ll_tiny_write_begin(struct page *vmpage,
			       struct address_space *mapping)
{
	/* Page must be present, up to date, dirty, and not in writeback. */
	if (!vmpage || !PageUptodate(vmpage) || !PageDirty(vmpage) ||
	    PageWriteback(vmpage) || vmpage->mapping != mapping)
		return -ENODATA;

	return 0;
}

static int ll_write_begin(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned int len, unsigned int flags,
			  struct page **pagep, void **fsdata)
{
	struct ll_cl_context *lcc = NULL;
	const struct lu_env *env = NULL;
	struct cl_io *io = NULL;
	struct cl_page *page = NULL;
	struct cl_object *clob = ll_i2info(mapping->host)->lli_clob;
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *vmpage = NULL;
	unsigned int from = pos & (PAGE_SIZE - 1);
	unsigned int to = from + len;
	int result = 0;

	CDEBUG(D_VFSTRACE, "Writing %lu of %d to %d bytes\n", index, from, len);

	lcc = ll_cl_find(file);
	if (!lcc) {
		vmpage = grab_cache_page_nowait(mapping, index);
		result = ll_tiny_write_begin(vmpage, mapping);
		goto out;
	}

	env = lcc->lcc_env;
	io  = lcc->lcc_io;

	if (file->f_flags & O_DIRECT) {
		/* direct IO failed because it couldn't clean up cached pages,
		 * this causes a problem for mirror write because the cached
		 * page may belong to another mirror, which will result in
		 * problem submitting the I/O.
		 */
		if (io->ci_designated_mirror > 0) {
			result = -EBUSY;
			goto out;
		}

		/*
		 * Direct write can fall back to buffered read, but DIO is done
		 * with lockless i/o, and buffered requires LDLM locking, so
		 * in this case we must restart without lockless.
		 */
		if (!io->ci_dio_lock) {
			io->ci_dio_lock = 1;
			io->ci_need_restart = 1;
			result = -ENOLCK;
			goto out;
		}
	}
again:
	/* To avoid deadlock, try to lock page first. */
	vmpage = grab_cache_page_nowait(mapping, index);
	if (unlikely(!vmpage || PageDirty(vmpage) || PageWriteback(vmpage))) {
		struct vvp_io *vio = vvp_env_io(env);
		struct cl_page_list *plist = &vio->u.readwrite.vui_queue;

		/* if the page is already in dirty cache, we have to commit
		 * the pages right now; otherwise, it may cause deadlock
		 * because it holds page lock of a dirty page and request for
		 * more grants. It's okay for the dirty page to be the first
		 * one in commit page list, though.
		 */
		if (vmpage && plist->pl_nr > 0) {
			unlock_page(vmpage);
			put_page(vmpage);
			vmpage = NULL;
		}

		/* commit pages and then wait for page lock */
		result = vvp_io_write_commit(env, io);
		if (result < 0)
			goto out;

		if (!vmpage) {
			vmpage = grab_cache_page_write_begin(mapping, index,
							     flags);
			if (!vmpage) {
				result = -ENOMEM;
				goto out;
			}
		}
	}

	/* page was truncated */
	if (mapping != vmpage->mapping) {
		CDEBUG(D_VFSTRACE, "page: %lu was truncated\n", index);
		unlock_page(vmpage);
		put_page(vmpage);
		vmpage = NULL;
		goto again;
	}

	page = cl_page_find(env, clob, vmpage->index, vmpage, CPT_CACHEABLE);
	if (IS_ERR(page)) {
		result = PTR_ERR(page);
		goto out;
	}

	lcc->lcc_page = page;
	lu_ref_add(&page->cp_reference, "cl_io", io);

	cl_page_assume(env, io, page);
	if (!PageUptodate(vmpage)) {
		/*
		 * We're completely overwriting an existing page,
		 * so _don't_ set it up to date until commit_write
		 */
		if (from == 0 && to == PAGE_SIZE) {
			CL_PAGE_HEADER(D_PAGE, env, page, "full page write\n");
			POISON_PAGE(vmpage, 0x11);
		} else {
			/* TODO: can be optimized at OSC layer to check if it
			 * is a lockless IO. In that case, it's not necessary
			 * to read the data.
			 */
			result = ll_prepare_partial_page(env, io, page, file);
			if (result) {
				/* vmpage should have been unlocked */
				put_page(vmpage);
				vmpage = NULL;

				if (result == -EAGAIN)
					goto again;
				goto out;
			}
		}
	}
out:
	if (result < 0) {
		if (vmpage) {
			unlock_page(vmpage);
			put_page(vmpage);
		}
		/* On tiny_write failure, page and io are always null. */
		if (!IS_ERR_OR_NULL(page)) {
			lu_ref_del(&page->cp_reference, "cl_io", io);
			cl_page_put(env, page);
		}
		if (io)
			io->ci_result = result;
	} else {
		*pagep = vmpage;
		*fsdata = lcc;
	}
	return result;
}

static int ll_tiny_write_end(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned int len, unsigned int copied,
			     struct page *vmpage)
{
	struct cl_page *clpage = (struct cl_page *) vmpage->private;
	loff_t kms = pos+copied;
	loff_t to = kms & (PAGE_SIZE-1) ? kms & (PAGE_SIZE-1) : PAGE_SIZE;
	u16 refcheck;
	struct lu_env *env = cl_env_get(&refcheck);
	int rc = 0;

	if (IS_ERR(env)) {
		rc = PTR_ERR(env);
		goto out;
	}

	/* This page is dirty in cache, so it should have a cl_page pointer
	 * set in vmpage->private.
	 */
	LASSERT(clpage);

	if (copied == 0)
		goto out_env;

	/* Update the underlying size information in the OSC/LOV objects this
	 * page is part of.
	 */
	cl_page_touch(env, clpage, to);

out_env:
	cl_env_put(env, &refcheck);

out:
	/* Must return page unlocked. */
	unlock_page(vmpage);

	return rc;
}

static int ll_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned int len, unsigned int copied,
			struct page *vmpage, void *fsdata)
{
	struct ll_cl_context *lcc = fsdata;
	const struct lu_env *env;
	struct cl_io *io;
	struct vvp_io *vio;
	struct cl_page *page;
	unsigned int from = pos & (PAGE_SIZE - 1);
	bool unplug = false;
	int result = 0;

	put_page(vmpage);

	CDEBUG(D_VFSTRACE, "pos %llu, len %u, copied %u\n", pos, len, copied);

	if (!lcc) {
		result = ll_tiny_write_end(file, mapping, pos, len, copied,
					   vmpage);
		goto out;
	}

	env  = lcc->lcc_env;
	page = lcc->lcc_page;
	io   = lcc->lcc_io;
	vio  = vvp_env_io(env);

	LASSERT(cl_page_is_owned(page, io));
	if (copied > 0) {
		struct cl_page_list *plist = &vio->u.readwrite.vui_queue;

		lcc->lcc_page = NULL; /* page will be queued */

		/* Add it into write queue */
		cl_page_list_add(plist, page);
		if (plist->pl_nr == 1) /* first page */
			vio->u.readwrite.vui_from = from;
		else
			LASSERT(from == 0);
		vio->u.readwrite.vui_to = from + copied;

		/*
		 * To address the deadlock in balance_dirty_pages() where
		 * this dirty page may be written back in the same thread.
		 */
		if (PageDirty(vmpage))
			unplug = true;

		/* We may have one full RPC, commit it soon */
		if (plist->pl_nr >= PTLRPC_MAX_BRW_PAGES)
			unplug = true;

		CL_PAGE_DEBUG(D_VFSTRACE, env, page,
			      "queued page: %d.\n", plist->pl_nr);
	} else {
		cl_page_disown(env, io, page);

		lcc->lcc_page = NULL;
		lu_ref_del(&page->cp_reference, "cl_io", io);
		cl_page_put(env, page);

		/* page list is not contiguous now, commit it now */
		unplug = true;
	}

	if (unplug || io->u.ci_wr.wr_sync)
		result = vvp_io_write_commit(env, io);

	if (result < 0)
		io->ci_result = result;


out:
	return result >= 0 ? copied : result;
}

#ifdef CONFIG_MIGRATION
static int ll_migratepage(struct address_space *mapping,
			  struct page *newpage, struct page *page,
			  enum migrate_mode mode)
{
	/* Always fail page migration until we have a proper implementation */
	return -EIO;
}
#endif

const struct address_space_operations ll_aops = {
	.readpage		= ll_readpage,
	.direct_IO		= ll_direct_IO,
	.writepage		= ll_writepage,
	.writepages		= ll_writepages,
	.set_page_dirty		= __set_page_dirty_nobuffers,
	.write_begin		= ll_write_begin,
	.write_end		= ll_write_end,
	.invalidatepage		= ll_invalidatepage,
	.releasepage		= (void *)ll_releasepage,
#ifdef CONFIG_MIGRATION
	.migratepage		= ll_migratepage,
#endif
};

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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/quotaops.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_dlm.h>

#include "llite_internal.h"

static void free_dentry_data(struct rcu_head *head)
{
	struct ll_dentry_data *lld;

	lld = container_of(head, struct ll_dentry_data, lld_rcu_head);
	kfree(lld);
}

/* should NOT be called with the dcache lock, see fs/dcache.c */
static void ll_release(struct dentry *de)
{
	struct ll_dentry_data *lld;

	LASSERT(de);
	lld = ll_d2d(de);
	call_rcu(&lld->lld_rcu_head, free_dentry_data);
}

/* Compare if two dentries are the same.  Don't match if the existing dentry
 * is marked invalid.  Returns 1 if different, 0 if the same.
 *
 * This avoids a race where ll_lookup_it() instantiates a dentry, but we get
 * an AST before calling d_revalidate_it().  The dentry still exists (marked
 * INVALID) so d_lookup() matches it, but we have no lock on it (so
 * lock_match() fails) and we spin around real_lookup().
 *
 * This race doesn't apply to lookups in d_alloc_parallel(), and for
 * those we want to ensure that only one dentry with a given name is
 * in ll_lookup_nd() at a time.  So allow invalid dentries to match
 * while d_in_lookup().  We will be called again when the lookup
 * completes, and can give a different answer then.
 */
static int ll_dcompare(const struct dentry *dentry,
		       unsigned int len, const char *str,
		       const struct qstr *name)
{
	if (len != name->len)
		return 1;

	if (memcmp(str, name->name, len))
		return 1;

	CDEBUG(D_DENTRY, "found name %.*s(%p) flags %#x refc %d\n",
	       name->len, name->name, dentry, dentry->d_flags,
	       d_count(dentry));

	/* mountpoint is always valid */
	if (d_mountpoint(dentry))
		return 0;

	/* ensure exclusion against parallel lookup of the same name */
	if (d_in_lookup((struct dentry *)dentry))
		return 0;

	if (d_lustre_invalid(dentry))
		return 1;

	return 0;
}

/**
 * Called when last reference to a dentry is dropped and dcache wants to know
 * whether or not it should cache it:
 * - return 1 to delete the dentry immediately
 * - return 0 to cache the dentry
 * Should NOT be called with the dcache lock, see fs/dcache.c
 */
static int ll_ddelete(const struct dentry *de)
{
	LASSERT(de);

	CDEBUG(D_DENTRY, "%s dentry %pd (%p, parent %p, inode %p) %s%s\n",
	       d_lustre_invalid(de) ? "deleting" : "keeping",
	       de, de, de->d_parent, d_inode(de),
	       d_unhashed(de) ? "" : "hashed,",
	       list_empty(&de->d_subdirs) ? "" : "subdirs");

	/* kernel >= 2.6.38 last refcount is decreased after this function. */
	LASSERT(d_count(de) == 1);

	if (d_lustre_invalid(de))
		return 1;
	return 0;
}

static int ll_d_init(struct dentry *de)
{
	struct ll_dentry_data *lld = kzalloc(sizeof(*lld), GFP_KERNEL);

	if (unlikely(!lld))
		return -ENOMEM;
	lld->lld_invalid = 1;
	de->d_fsdata = lld;
	return 0;
}

void ll_intent_drop_lock(struct lookup_intent *it)
{
	if (it->it_op && it->it_lock_mode) {
		struct lustre_handle handle;

		handle.cookie = it->it_lock_handle;

		CDEBUG(D_DLMTRACE,
		       "releasing lock with cookie %#llx from it %p\n",
		       handle.cookie, it);
		ldlm_lock_decref(&handle, it->it_lock_mode);

		/* bug 494: intent_release may be called multiple times, from
		 * this thread and we don't want to double-decref this lock
		 */
		it->it_lock_mode = 0;
		if (it->it_remote_lock_mode != 0) {
			handle.cookie = it->it_remote_lock_handle;

			CDEBUG(D_DLMTRACE,
			       "releasing remote lock with cookie %#llx from it %p\n",
			       handle.cookie, it);
			ldlm_lock_decref(&handle,
					 it->it_remote_lock_mode);
			it->it_remote_lock_mode = 0;
		}
	}
}

void ll_intent_release(struct lookup_intent *it)
{
	CDEBUG(D_INFO, "intent %p released\n", it);
	ll_intent_drop_lock(it);
	/* We are still holding extra reference on a request, need to free it */
	if (it_disposition(it, DISP_ENQ_OPEN_REF))
		ptlrpc_req_finished(it->it_request); /* ll_file_open */

	if (it_disposition(it, DISP_ENQ_CREATE_REF)) /* create rec */
		ptlrpc_req_finished(it->it_request);

	it->it_disposition = 0;
	it->it_request = NULL;
}

/* mark aliases invalid and prune unused aliases */
void ll_prune_aliases(struct inode *inode)
{
	struct dentry *dentry;

	CDEBUG(D_INODE, "marking dentries for ino " DFID "(%p) invalid\n",
	       PFID(ll_inode2fid(inode)), inode);

	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_u.d_alias)
		d_lustre_invalidate(dentry);
	spin_unlock(&inode->i_lock);

	d_prune_aliases(inode);
}

int ll_revalidate_it_finish(struct ptlrpc_request *request,
			    struct lookup_intent *it,
			    struct dentry *de)
{
	struct inode *inode = d_inode(de);
	u64 bits = 0;
	int rc;

	if (!request)
		return 0;

	if (it_disposition(it, DISP_LOOKUP_NEG))
		return -ENOENT;

	rc = ll_prep_inode(&inode, &request->rq_pill, NULL, it);
	if (rc)
		return rc;

	ll_set_lock_data(ll_i2sbi(inode)->ll_md_exp, inode, it,
			 &bits);
	if (bits & MDS_INODELOCK_LOOKUP) {
		d_lustre_revalidate(de);
		if (S_ISDIR(inode->i_mode))
			ll_update_dir_depth_dmv(de->d_parent->d_inode, de);
	}

	return rc;
}

void ll_lookup_finish_locks(struct lookup_intent *it, struct inode *inode)
{
	if (it->it_lock_mode && inode) {
		struct ll_sb_info *sbi = ll_i2sbi(inode);

		CDEBUG(D_DLMTRACE, "setting l_data to inode " DFID "(%p)\n",
		       PFID(ll_inode2fid(inode)), inode);
		ll_set_lock_data(sbi->ll_md_exp, inode, it, NULL);
	}

	/* drop lookup or getattr locks immediately */
	if (it->it_op == IT_LOOKUP || it->it_op == IT_GETATTR) {
		/* on 2.6 there are situation when several lookups and
		 * revalidations may be requested during single operation.
		 * therefore, we don't release intent here -bzzz
		 */
		ll_intent_drop_lock(it);
	}
}

static int ll_revalidate_dentry(struct dentry *dentry,
				unsigned int lookup_flags)
{
	struct inode *dir = d_inode(dentry->d_parent);
	int rc;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%s, flags=%u\n",
	       dentry->d_name.name, lookup_flags);

	rc = ll_revalidate_d_crypto(dentry, lookup_flags);
	if (rc != 1)
		return rc;

	/* If this is intermediate component path lookup and we were able to get
	 * to this dentry, then its lock has not been revoked and the
	 * path component is valid.
	 */
	if (lookup_flags & LOOKUP_PARENT) {
		if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
			ll_update_dir_depth_dmv(dir, dentry);
		return 1;
	}

	/* Symlink - always valid as long as the dentry was found */
	/* only special case is to prevent ELOOP error from VFS during open
	 * of a foreign symlink file/dir with O_NOFOLLOW, like it happens for
	 * real symlinks. This will allow to open foreign symlink file/dir
	 * for get[dir]stripe/unlock ioctl()s.
	 */
	if (d_is_symlink(dentry)) {
		if (!S_ISLNK(dentry->d_inode->i_mode) &&
		    !(lookup_flags & LOOKUP_FOLLOW))
			return 0;
		else
			return 1;
	}

	/*
	 * VFS warns us that this is the second go around and previous
	 * operation failed (most likely open|creat), so this time
	 * we better talk to the server via the lookup path by name,
	 * not by fid.
	 */
	if (lookup_flags & LOOKUP_REVAL)
		return 0;

	if (!dentry_may_statahead(dir, dentry))
		return 1;

	if (lookup_flags & LOOKUP_RCU)
		return -ECHILD;

	if (dentry_may_statahead(dir, dentry))
		ll_revalidate_statahead(dir, &dentry, !d_inode(dentry));

	if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode))
		ll_update_dir_depth_dmv(dir, dentry);

	return 1;
}

/*
 * Always trust cached dentries. Update statahead window if necessary.
 */
static int ll_revalidate_nd(struct dentry *dentry, unsigned int flags)
{
	CDEBUG(D_VFSTRACE, "VFS Op:name=%pd, flags=%u\n",
	       dentry, flags);

	return ll_revalidate_dentry(dentry, flags);
}

const struct dentry_operations ll_d_ops = {
	.d_init = ll_d_init,
	.d_revalidate = ll_revalidate_nd,
	.d_release = ll_release,
	.d_delete  = ll_ddelete,
	.d_compare = ll_dcompare,
};

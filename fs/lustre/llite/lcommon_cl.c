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
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/rbtree.h>

#include <obd.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <lustre_dlm.h>
#include <lustre_mdc.h>
#include <cl_object.h>

#include "llite_internal.h"

/*
 * ccc_ prefix stands for "Common Client Code".
 */

/*****************************************************************************
 *
 * Vvp device and device type functions.
 *
 */
#include "vvp_internal.h"

/**
 * An `emergency' environment used by cl_inode_fini() when cl_env_get()
 * fails. Access to this environment is serialized by cl_inode_fini_guard
 * mutex.
 */
struct lu_env *cl_inode_fini_env;
u16 cl_inode_fini_refcheck;

/**
 * A mutex serializing calls to slp_inode_fini() under extreme memory
 * pressure, when environments cannot be allocated.
 */
static DEFINE_MUTEX(cl_inode_fini_guard);

int cl_setattr_ost(struct cl_object *obj, const struct iattr *attr,
		   enum op_xvalid xvalid, unsigned int attr_flags)
{
	struct lu_env *env;
	struct cl_io *io;
	int result;
	u16 refcheck;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	io = vvp_env_thread_io(env);
	io->ci_obj = obj;
	io->ci_verify_layout = 1;

	io->u.ci_setattr.sa_attr.lvb_atime = attr->ia_atime.tv_sec;
	io->u.ci_setattr.sa_attr.lvb_mtime = attr->ia_mtime.tv_sec;
	io->u.ci_setattr.sa_attr.lvb_ctime = attr->ia_ctime.tv_sec;
	io->u.ci_setattr.sa_attr.lvb_size = attr->ia_size;
	io->u.ci_setattr.sa_attr_flags = attr_flags;
	io->u.ci_setattr.sa_avalid = attr->ia_valid;
	io->u.ci_setattr.sa_xvalid = xvalid;
	io->u.ci_setattr.sa_parent_fid = lu_object_fid(&obj->co_lu);

	if (attr->ia_valid & ATTR_SIZE)
		io->u.ci_setattr.sa_subtype = CL_SETATTR_TRUNC;
again:
	if (attr->ia_valid & ATTR_FILE)
		ll_io_set_mirror(io, attr->ia_file);

	if (cl_io_init(env, io, CIT_SETATTR, io->ci_obj) == 0) {
		struct vvp_io *vio = vvp_env_io(env);

		if (attr->ia_valid & ATTR_FILE)
			/* populate the file descriptor for ftruncate to honor
			 * group lock - see LU-787
			 */
			vio->vui_fd = attr->ia_file->private_data;

		result = cl_io_loop(env, io);
	} else {
		result = io->ci_result;
	}
	cl_io_fini(env, io);
	if (unlikely(io->ci_need_restart))
		goto again;

	cl_env_put(env, &refcheck);
	return result;
}

/**
 * Initialize or update CLIO structures for regular files when new
 * meta-data arrives from the server.
 *
 * @inode	regular file inode
 * @md		new file metadata from MDS
 *
 * - allocates cl_object if necessary,
 * - updated layout, if object was already here.
 */
int cl_file_inode_init(struct inode *inode, struct lustre_md *md)
{
	struct lu_env *env;
	struct ll_inode_info *lli;
	struct cl_object *clob;
	struct lu_site *site;
	struct lu_fid *fid;
	struct cl_object_conf conf = {
		.coc_inode = inode,
		.u = {
			.coc_layout = md->layout,
		}
	};
	int result = 0;
	u16 refcheck;

	LASSERT(md->body->mbo_valid & OBD_MD_FLID);
	LASSERT(S_ISREG(inode->i_mode));

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	site = ll_i2sbi(inode)->ll_site;
	lli = ll_i2info(inode);
	fid = &lli->lli_fid;
	LASSERT(fid_is_sane(fid));

	if (!lli->lli_clob) {
		/* clob is slave of inode, empty lli_clob means for new inode,
		 * there is no clob in cache with the given fid, so it is
		 * unnecessary to perform lookup-alloc-lookup-insert, just
		 * alloc and insert directly.
		 */
		if (!(inode->i_state & I_NEW)) {
			result = -EIO;
			CERROR("%s: unexpected not-NEW inode "DFID": rc = %d\n",
			       ll_i2sbi(inode)->ll_fsname, PFID(fid), result);
			goto out;
		}

		conf.coc_lu.loc_flags = LOC_F_NEW;
		clob = cl_object_find(env, lu2cl_dev(site->ls_top_dev),
				      fid, &conf);
		if (!IS_ERR(clob)) {
			/*
			 * No locking is necessary, as new inode is
			 * locked by I_NEW bit.
			 */
			lli->lli_clob = clob;
			lu_object_ref_add(&clob->co_lu, "inode", inode);
		} else {
			result = PTR_ERR(clob);
		}
	} else {
		result = cl_conf_set(env, lli->lli_clob, &conf);
		if (result == -EBUSY) {
			/* ignore the error since I/O will handle it later */
			result = 0;
		}
	}

	if (result)
		CERROR("%s: failed to initialize cl_object "DFID": rc = %d\n",
		       ll_i2sbi(inode)->ll_fsname, PFID(fid), result);

out:
	cl_env_put(env, &refcheck);

	return result;
}

/**
 * Wait for others drop their references of the object at first, then we drop
 * the last one, which will lead to the object be destroyed immediately.
 * Must be called after cl_object_kill() against this object.
 *
 * The reason we want to do this is: destroying top object will wait for sub
 * objects being destroyed first, so we can't let bottom layer (e.g. from ASTs)
 * to initiate top object destroying which may deadlock. See bz22520.
 */
static void cl_object_put_last(struct lu_env *env, struct cl_object *obj)
{
	struct lu_object_header *header = obj->co_lu.lo_header;

	if (unlikely(atomic_read(&header->loh_ref) != 1)) {
		struct lu_site *site = obj->co_lu.lo_dev->ld_site;
		wait_queue_head_t *wq;

		wq = lu_site_wq_from_fid(site, &header->loh_fid);

		/* LU_OBJECT_HEARD_BANSHEE is set in cl_object_kill(), in case
		 * someone is waiting on this, wake up and then wait for object
		 * refcount becomes one.
		 */
		wake_up(wq);
		wait_event(*wq, atomic_read(&header->loh_ref) == 1);
	}

	cl_object_put(env, obj);
}

void cl_inode_fini(struct inode *inode)
{
	struct lu_env *env;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *clob = lli->lli_clob;
	u16 refcheck;
	int emergency;

	if (clob) {
		env = cl_env_get(&refcheck);
		emergency = IS_ERR(env);
		if (emergency) {
			mutex_lock(&cl_inode_fini_guard);
			LASSERT(cl_inode_fini_env);
			env = cl_inode_fini_env;
		}
		/*
		 * cl_object cache is a slave to inode cache (which, in turn
		 * is a slave to dentry cache), don't keep cl_object in memory
		 * when its master is evicted.
		 */
		cl_object_kill(env, clob);
		lu_object_ref_del(&clob->co_lu, "inode", inode);
		cl_object_put_last(env, clob);
		lli->lli_clob = NULL;
		if (emergency)
			mutex_unlock(&cl_inode_fini_guard);
		else
			cl_env_put(env, &refcheck);
	}
}

/**
 * build inode number from passed @fid
 */
u64 cl_fid_build_ino(const struct lu_fid *fid, bool api32)
{
	if (BITS_PER_LONG == 32 || api32)
		return fid_flatten32(fid);
	else
		return fid_flatten(fid);
}

/*
 * build inode generation from passed @fid.  If our FID overflows the 32-bit
 * inode number then return a non-zero generation to distinguish them.
 */
u32 cl_fid_build_gen(const struct lu_fid *fid)
{
	if (fid_is_igif(fid))
		return lu_igif_gen(fid);

	return fid_flatten(fid) >> 32;
}

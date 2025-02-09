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
 *
 * lustre/llite/dir.c
 *
 * Directory code for lustre client.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/buffer_head.h>   /* for wait_on_buffer */
#include <linux/pagevec.h>
#include <linux/prefetch.h>
#include <linux/security.h>
#include <linux/fscrypt.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <obd_class.h>
#include <uapi/linux/fscrypt.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_lib.h>
#include <lustre_dlm.h>
#include <lustre_fid.h>
#include <lustre_kernelcomm.h>
#include <lustre_swab.h>

#include "llite_internal.h"

/*
 * (new) readdir implementation overview.
 *
 * Original lustre readdir implementation cached exact copy of raw directory
 * pages on the client. These pages were indexed in client page cache by
 * logical offset in the directory file. This design, while very simple and
 * intuitive had some inherent problems:
 *
 *     . it implies that byte offset to the directory entry serves as a
 *     telldir(3)/seekdir(3) cookie, but that offset is not stable: in
 *     ext3/htree directory entries may move due to splits, and more
 *     importantly,
 *
 *     . it is incompatible with the design of split directories for cmd3,
 *     that assumes that names are distributed across nodes based on their
 *     hash, and so readdir should be done in hash order.
 *
 * New readdir implementation does readdir in hash order, and uses hash of a
 * file name as a telldir/seekdir cookie. This led to number of complications:
 *
 *     . hash is not unique, so it cannot be used to index cached directory
 *     pages on the client (note, that it requires a whole pageful of hash
 *     collided entries to cause two pages to have identical hashes);
 *
 *     . hash is not unique, so it cannot, strictly speaking, be used as an
 *     entry cookie. ext3/htree has the same problem and lustre implementation
 *     mimics their solution: seekdir(hash) positions directory at the first
 *     entry with the given hash.
 *
 * Client side.
 *
 * 0. caching
 *
 * Client caches directory pages using hash of the first entry as an index. As
 * noted above hash is not unique, so this solution doesn't work as is:
 * special processing is needed for "page hash chains" (i.e., sequences of
 * pages filled with entries all having the same hash value).
 *
 * First, such chains have to be detected. To this end, server returns to the
 * client the hash of the first entry on the page next to one returned. When
 * client detects that this hash is the same as hash of the first entry on the
 * returned page, page hash collision has to be handled. Pages in the
 * hash chain, except first one, are termed "overflow pages".
 *
 * Proposed (unimplimented) solution to index uniqueness problem is to
 * not cache overflow pages.  Instead, when page hash collision is
 * detected, all overflow pages from emerging chain should be
 * immediately requested from the server and placed in a special data
 * structure.  This data structure can be used by ll_readdir() to
 * process entries from overflow pages.  When readdir invocation
 * finishes, overflow pages are discarded.  If page hash collision chain
 * weren't completely processed, next call to readdir will again detect
 * page hash collision, again read overflow pages in, process next
 * portion of entries and again discard the pages.  This is not as
 * wasteful as it looks, because, given reasonable hash, page hash
 * collisions are extremely rare.
 *
 * 1. directory positioning
 *
 * When seekdir(hash) is called.
 *
 * seekdir() sets the location in the directory stream from which the next
 * readdir() call will start. mdc_page_locate() is used to find page with
 * starting hash and will issue RPC to fetch that page. If there is a hash
 * collision the concerned page is removed.
 *
 *
 * Server.
 *
 * identification of and access to overflow pages
 *
 * page format
 *
 * Page in MDS_READPAGE RPC is packed in LU_PAGE_SIZE, and each page contains
 * a header lu_dirpage which describes the start/end hash, and whether this
 * page is empty (contains no dir entry) or hash collide with next page.
 * After client receives reply, several pages will be integrated into dir page
 * in PAGE_SIZE (if PAGE_SIZE greater than LU_PAGE_SIZE), and the
 * lu_dirpage for this integrated page will be adjusted. See
 * mdc_adjust_dirpages().
 *
 */
struct page *ll_get_dir_page(struct inode *dir, struct md_op_data *op_data,
			     u64 offset, int *partial_readdir_rc)
{
	struct md_readdir_info mrinfo = {
		.mr_blocking_ast = ll_md_blocking_ast
	};
	struct page *page;
	int rc;

	rc = md_read_page(ll_i2mdexp(dir), op_data, &mrinfo, offset, &page);
	if (rc != 0)
		return ERR_PTR(rc);

	if (partial_readdir_rc && mrinfo.mr_partial_readdir_rc)
		*partial_readdir_rc = mrinfo.mr_partial_readdir_rc;

	return page;
}

void ll_release_page(struct inode *inode, struct page *page, bool remove)
{
	kunmap(page);

	/* Always remove the page for striped dir, because the page is
	 * built from temporarily in LMV layer
	 */
	if (inode && S_ISDIR(inode->i_mode) &&
	    lmv_dir_striped(ll_i2info(inode)->lli_lsm_md)) {
		__free_page(page);
		return;
	}

	if (remove) {
		lock_page(page);
		if (likely(page->mapping))
			delete_from_page_cache(page);
		unlock_page(page);
	}
	put_page(page);
}

int ll_dir_read(struct inode *inode, u64 *ppos, struct md_op_data *op_data,
		struct dir_context *ctx, int *partial_readdir_rc)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	u64 pos = *ppos;
	bool is_api32 = ll_need_32bit_api(sbi);
	bool is_hash64 = test_bit(LL_SBI_64BIT_HASH, sbi->ll_flags);
	struct fscrypt_str lltr = FSTR_INIT(NULL, 0);
	struct page *page;
	bool done = false;
	int rc = 0;

	if (IS_ENCRYPTED(inode)) {
		rc = fscrypt_fname_alloc_buffer(inode, NAME_MAX, &lltr);
		if (rc < 0)
			return rc;
	}

	page = ll_get_dir_page(inode, op_data, pos, partial_readdir_rc);

	while (rc == 0 && !done) {
		struct lu_dirpage *dp;
		struct lu_dirent  *ent;
		u64 hash;
		u64 next;

		if (IS_ERR(page)) {
			rc = PTR_ERR(page);
			break;
		}

		hash = MDS_DIR_END_OFF;
		dp = page_address(page);
		for (ent = lu_dirent_start(dp); ent && !done;
		     ent = lu_dirent_next(ent)) {
			u16 type;
			int namelen;
			struct lu_fid fid;
			u64 lhash;
			u64 ino;

			hash = le64_to_cpu(ent->lde_hash);
			if (hash < pos) /* Skip until we find target hash */
				continue;

			namelen = le16_to_cpu(ent->lde_namelen);
			if (namelen == 0) /* Skip dummy record */
				continue;

			if (is_api32 && is_hash64)
				lhash = hash >> 32;
			else
				lhash = hash;
			fid_le_to_cpu(&fid, &ent->lde_fid);
			ino = cl_fid_build_ino(&fid, is_api32);
			type = S_DT(lu_dirent_type_get(ent));
			/* For ll_nfs_get_name_filldir(), it will try to access
			 * 'ent' through 'lde_name', so the parameter 'name'
			 * for 'dir_emit()' must be part of the 'ent'.
			 */
			ctx->pos = lhash;
			if (!IS_ENCRYPTED(inode)) {
				done = !dir_emit(ctx, ent->lde_name, namelen,
						 ino, type);
			} else {
				/* Directory is encrypted */
				int save_len = lltr.len;
				struct fscrypt_str de_name
					= FSTR_INIT(ent->lde_name, namelen);

				rc = ll_fname_disk_to_usr(inode, 0, 0, &de_name,
							  &lltr, &fid);
				de_name = lltr;
				lltr.len = save_len;
				if (rc) {
					done = 1;
					break;
				}
				done = !dir_emit(ctx, de_name.name, de_name.len,
						 ino, type);
			}
		}

		if (done) {
			pos = hash;
			ll_release_page(inode, page, false);
			break;
		}

		next = le64_to_cpu(dp->ldp_hash_end);
		pos = next;
		if (pos == MDS_DIR_END_OFF) {
			/* End of directory reached. */
			done = 1;
			ll_release_page(inode, page, false);
		} else {
			/* Normal case: continue to the next page.*/
			ll_release_page(inode, page,
					le32_to_cpu(dp->ldp_flags) &
					LDF_COLLIDE);
			next = pos;
			page = ll_get_dir_page(inode, op_data, pos,
					       partial_readdir_rc);
		}
	}

	ctx->pos = pos;
	fscrypt_fname_free_buffer(&lltr);
	return rc;
}

static int ll_readdir(struct file *filp, struct dir_context *ctx)
{
	struct inode *inode = file_inode(filp);
	struct ll_file_data *lfd = filp->private_data;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	bool hash64 = test_bit(LL_SBI_64BIT_HASH, sbi->ll_flags);
	bool api32 = ll_need_32bit_api(sbi);
	struct md_op_data *op_data;
	struct lu_fid pfid = { 0 };
	ktime_t kstart = ktime_get();
	/* result of possible partial readdir */
	int partial_readdir_rc = 0;
	u64 pos;
	int rc;

	LASSERT(lfd);
	pos = lfd->lfd_pos;

	CDEBUG(D_VFSTRACE,
	       "VFS Op:inode="DFID"(%p) pos/size %lu/%llu 32bit_api %d\n",
	       PFID(ll_inode2fid(inode)), inode, (unsigned long)pos,
	       i_size_read(inode), api32);

	if (IS_ENCRYPTED(inode)) {
		rc = fscrypt_get_encryption_info(inode);
		if (rc && rc != -ENOKEY)
			goto out;
	}

	if (pos == MDS_DIR_END_OFF) {
		/* end-of-file. */
		rc = 0;
		goto out;
	}

	if (unlikely(ll_dir_striped(inode))) {
		/*
		 * This is only needed for striped dir to fill ..,
		 * see lmv_read_page
		 */
		if (file_dentry(filp)->d_parent &&
		    file_dentry(filp)->d_parent->d_inode) {
			u64 ibits = MDS_INODELOCK_LOOKUP;
			struct inode *parent;

			parent = file_dentry(filp)->d_parent->d_inode;
			if (ll_have_md_lock(ll_i2mdexp(parent), parent, &ibits,
					    LCK_MINMODE))
				pfid = *ll_inode2fid(parent);
		}

		/* If it can not find in cache, do lookup .. on the master
		 * object
		 */
		if (fid_is_zero(&pfid)) {
			rc = ll_dir_get_parent_fid(inode, &pfid);
			if (rc != 0)
				return rc;
		}
	}

	op_data = ll_prep_md_op_data(NULL, inode, inode, NULL, 0, 0,
				     LUSTRE_OPC_ANY, inode);
	if (IS_ERR(op_data)) {
		rc = PTR_ERR(op_data);
		goto out;
	}

	/* foreign dirs are browsed out of Lustre */
	if (unlikely(op_data->op_mea1 &&
		     op_data->op_mea1->lsm_md_magic == LMV_MAGIC_FOREIGN)) {
		ll_finish_md_op_data(op_data);
		return -ENODATA;
	}

	op_data->op_fid3 = pfid;

	ctx->pos = pos;
	rc = ll_dir_read(inode, &pos, op_data, ctx, &partial_readdir_rc);
	pos = ctx->pos;
	lfd->lfd_pos = pos;
	if (!lfd->fd_partial_readdir_rc)
		lfd->fd_partial_readdir_rc = partial_readdir_rc;

	if (pos == MDS_DIR_END_OFF) {
		if (api32)
			pos = LL_DIR_END_OFF_32BIT;
		else
			pos = LL_DIR_END_OFF;
	} else {
		if (api32 && hash64)
			pos >>= 32;
	}
	ctx->pos = pos;
	ll_finish_md_op_data(op_data);
out:
	if (!rc)
		ll_stats_ops_tally(sbi, LPROC_LL_READDIR,
				   ktime_us_delta(ktime_get(), kstart));

	return rc;
}

/**
 * Create striped directory with specified stripe(@lump)
 *
 * @dparent:	the parent of the directory.
 * @lump:	the specified stripes.
 * @dirname:	the name of the directory.
 * @mode:	the specified mode of the directory.
 *
 * Returns:	=0 if striped directory is being created successfully.
 *		<0 if the creation is failed.
 */
static int ll_dir_setdirstripe(struct dentry *dparent, struct lmv_user_md *lump,
			       size_t len, const char *dirname, umode_t mode,
			       bool createonly)
{
	struct inode *parent = dparent->d_inode;
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data;
	struct ll_sb_info *sbi = ll_i2sbi(parent);
	struct inode *inode = NULL;
	struct dentry dentry = {
		.d_parent = dparent,
		.d_name = {
			.name = dirname,
			.len = strlen(dirname),
			.hash = full_name_hash(dparent, dirname,
					       strlen(dirname)),
		},
		.d_sb = dparent->d_sb,
	};
	bool encrypt = false;
	int hash_flags;
	int err;

	if (unlikely(!lmv_user_magic_supported(lump->lum_magic)))
		return -EINVAL;

	if (lump->lum_magic != LMV_MAGIC_FOREIGN) {
		CDEBUG(D_VFSTRACE,
		       "VFS Op:inode="DFID"(%p) name %s stripe_offset %d stripe_count: %u, hash_type=%x\n",
		       PFID(ll_inode2fid(parent)), parent, dirname,
		       (int)lump->lum_stripe_offset, lump->lum_stripe_count,
		       lump->lum_hash_type);
	} else {
		struct lmv_foreign_md *lfm = (struct lmv_foreign_md *)lump;

		CDEBUG(D_VFSTRACE,
		       "VFS Op:inode="DFID"(%p) name %s foreign, length %u, value '%.*s'\n",
		       PFID(ll_inode2fid(parent)), parent, dirname,
		       lfm->lfm_length, lfm->lfm_length, lfm->lfm_value);
	}

	if (lump->lum_stripe_count > 1 &&
	    !(exp_connect_flags(sbi->ll_md_exp) & OBD_CONNECT_DIR_STRIPE))
		return -EINVAL;

	if (IS_DEADDIR(parent) &&
	    !CFS_FAIL_CHECK(OBD_FAIL_LLITE_NO_CHECK_DEAD))
		return -ENOENT;

	/* MDS < 2.14 doesn't support 'crush' hash type, and cannot handle
	 * unknown hash if client doesn't set a valid one. switch to fnv_1a_64.
	 */
	if (CFS_FAIL_CHECK(OBD_FAIL_LMV_UNKNOWN_STRIPE)) {
		lump->lum_hash_type = cfs_fail_val;
	} else if (!(exp_connect_flags2(sbi->ll_md_exp) & OBD_CONNECT2_CRUSH)) {
		enum lmv_hash_type type = lump->lum_hash_type &
					  LMV_HASH_TYPE_MASK;

		if (type >= LMV_HASH_TYPE_CRUSH ||
		    type == LMV_HASH_TYPE_UNKNOWN)
			lump->lum_hash_type = (lump->lum_hash_type ^ type) |
					      LMV_HASH_TYPE_FNV_1A_64;
	}

	hash_flags = lump->lum_hash_type & ~LMV_HASH_TYPE_MASK;
	if (hash_flags & ~LMV_HASH_FLAG_KNOWN)
		return -EINVAL;

	if (unlikely(!lmv_user_magic_supported(cpu_to_le32(lump->lum_magic))))
		lustre_swab_lmv_user_md(lump);

	if (!IS_POSIXACL(parent) || !exp_connect_umask(ll_i2mdexp(parent)))
		mode &= ~current_umask();
	mode = (mode & (0777 | S_ISVTX)) | S_IFDIR;
	op_data = ll_prep_md_op_data(NULL, parent, NULL, dirname,
				     strlen(dirname), mode, LUSTRE_OPC_MKDIR,
				     lump);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	op_data->op_dir_depth = ll_i2info(parent)->lli_inherit_depth ?:
				ll_i2info(parent)->lli_dir_depth;

	if (ll_sbi_has_encrypt(sbi) &&
	    (IS_ENCRYPTED(parent) ||
	     unlikely(ll_sb_has_test_dummy_encryption(parent->i_sb)))) {
		err = fscrypt_get_encryption_info(parent);
		if (err)
			goto out_op_data;
		if (!fscrypt_has_encryption_key(parent)) {
			err = -ENOKEY;
			goto out_op_data;
		}
		encrypt = true;
	}

	if (test_bit(LL_SBI_FILE_SECCTX, sbi->ll_flags)) {
		/* selinux_dentry_init_security() uses dentry->d_parent and name
		 * to determine the security context for the file. So our fake
		 * dentry should be real enough for this purpose.
		 */
		err = ll_dentry_init_security(&dentry, mode, &dentry.d_name,
					      &op_data->op_file_secctx_name,
					      &op_data->op_file_secctx_name_size,
					      &op_data->op_file_secctx,
					      &op_data->op_file_secctx_size);
		if (err < 0)
			goto out_op_data;
	}

	if (encrypt) {
		err = fscrypt_inherit_context(parent, NULL, op_data, false);
		if (err)
			goto out_op_data;
	}

	op_data->op_cli_flags |= CLI_SET_MEA;
	if (createonly)
		op_data->op_bias |= MDS_SETSTRIPE_CREATE;

	err = md_create(sbi->ll_md_exp, op_data, lump, len, mode,
			from_kuid(&init_user_ns, current_fsuid()),
			from_kgid(&init_user_ns, current_fsgid()),
			current_cap(), 0, &request);
	if (err)
		goto out_request;

	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_SETDIRSTRIPE_PAUSE, cfs_fail_val);

	err = ll_prep_inode(&inode, &request->rq_pill, parent->i_sb, NULL);
	if (err)
		goto out_inode;

	dentry.d_inode = inode;

	if (test_bit(LL_SBI_FILE_SECCTX, sbi->ll_flags))
		err = ll_inode_notifysecctx(inode, op_data->op_file_secctx,
					    op_data->op_file_secctx_size);
	else
		err = ll_inode_init_security(&dentry, inode, parent);
	if (err)
		goto out_inode;

	if (encrypt)
		err = ll_set_encflags(inode, op_data->op_file_encctx,
				      op_data->op_file_encctx_size, false);
out_inode:
	iput(inode);
out_request:
	ptlrpc_req_finished(request);
out_op_data:
	ll_finish_md_op_data(op_data);

	return err;
}

int ll_dir_setstripe(struct inode *inode, struct lov_user_md *lump,
		     int set_default)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int rc = 0;
	int lum_size;

	if (lump) {
		switch (lump->lmm_magic) {
		case LOV_USER_MAGIC_V1:
			lum_size = sizeof(struct lov_user_md_v1);
			break;
		case LOV_USER_MAGIC_V3:
			lum_size = sizeof(struct lov_user_md_v3);
			break;
		case LOV_USER_MAGIC_COMP_V1:
			lum_size = ((struct lov_comp_md_v1 *)lump)->lcm_size;
			break;
		case LMV_USER_MAGIC: {
			struct lmv_user_md *lmv = (struct lmv_user_md *)lump;

			/* MDS < 2.14 doesn't support 'crush' hash type, and
			 * cannot handle unknown hash if client doesn't set a
			 * valid one. switch to fnv_1a_64.
			 */
			if (!(exp_connect_flags2(sbi->ll_md_exp) &
			      OBD_CONNECT2_CRUSH)) {
				enum lmv_hash_type type = lmv->lum_hash_type &
							  LMV_HASH_TYPE_MASK;

				if (type >= LMV_HASH_TYPE_CRUSH ||
				    type == LMV_HASH_TYPE_UNKNOWN)
					lmv->lum_hash_type =
						(lmv->lum_hash_type ^ type) |
						LMV_HASH_TYPE_FNV_1A_64;
			}
			if (lmv->lum_magic != cpu_to_le32(LMV_USER_MAGIC))
				lustre_swab_lmv_user_md(lmv);
			lum_size = sizeof(*lmv);
			break;
		}
		case LOV_USER_MAGIC_SPECIFIC: {
			struct lov_user_md_v3 *v3 =
				(struct lov_user_md_v3 *)lump;
			if (v3->lmm_stripe_count > LOV_MAX_STRIPE_COUNT)
				return -EINVAL;
			lum_size = lov_user_md_size(v3->lmm_stripe_count,
						    LOV_USER_MAGIC_SPECIFIC);
			break;
		}
		default:
			CDEBUG(D_IOCTL,
			       "bad userland LOV MAGIC: %#08x != %#08x nor %#08x\n",
			       lump->lmm_magic, LOV_USER_MAGIC_V1,
			       LOV_USER_MAGIC_V3);
			return -EINVAL;
		}

		/* This is coming from userspace, so should be in
		 * local endian.  But the MDS would like it in little
		 * endian, so we swab it before we send it.
		 */
		if ((__swab32(lump->lmm_magic) & le32_to_cpu(LOV_MAGIC_MASK)) ==
		    le32_to_cpu(LOV_MAGIC_MAGIC))
			lustre_swab_lov_user_md(lump, 0);
	} else {
		lum_size = sizeof(struct lov_user_md_v1);
	}

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	/* swabbing is done in lov_setstripe() on server side */
	rc = md_setattr(sbi->ll_md_exp, op_data, lump, lum_size, &req);
	ll_finish_md_op_data(op_data);
	ptlrpc_req_finished(req);

	return rc;
}

/* get default LMV from client cache */
static int ll_dir_get_default_lmv(struct inode *inode, struct lmv_user_md *lum)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	const struct lmv_stripe_md *lsm;
	bool fs_dmv_got = false;
	int rc = -ENODATA;

retry:
	if (lli->lli_default_lsm_md) {
		down_read(&lli->lli_lsm_sem);
		lsm = lli->lli_default_lsm_md;
		if (lsm) {
			lum->lum_magic = lsm->lsm_md_magic;
			lum->lum_stripe_count = lsm->lsm_md_stripe_count;
			lum->lum_stripe_offset = lsm->lsm_md_master_mdt_index;
			lum->lum_hash_type = lsm->lsm_md_hash_type;
			lum->lum_max_inherit = lsm->lsm_md_max_inherit;
			lum->lum_max_inherit_rr = lsm->lsm_md_max_inherit_rr;
			rc = 0;
		}
		up_read(&lli->lli_lsm_sem);
	}

	if (rc == -ENODATA && !is_root_inode(inode) && !fs_dmv_got) {
		lli = ll_i2info(inode->i_sb->s_root->d_inode);
		fs_dmv_got = true;
		goto retry;
	}

	if (!rc && fs_dmv_got) {
		lli = ll_i2info(inode);
		if (lum->lum_max_inherit != LMV_INHERIT_UNLIMITED) {
			if (lum->lum_max_inherit == LMV_INHERIT_NONE ||
			    lum->lum_max_inherit < LMV_INHERIT_END ||
			    lum->lum_max_inherit > LMV_INHERIT_MAX ||
			    lum->lum_max_inherit <= lli->lli_dir_depth) {
				rc = -ENODATA;
				goto out;
			}
			lum->lum_max_inherit -= lli->lli_dir_depth;
		}

		if (lum->lum_max_inherit_rr != LMV_INHERIT_RR_UNLIMITED) {
			if (lum->lum_max_inherit_rr == LMV_INHERIT_NONE ||
			    lum->lum_max_inherit_rr < LMV_INHERIT_RR_END ||
			    lum->lum_max_inherit_rr > LMV_INHERIT_RR_MAX ||
			    lum->lum_max_inherit_rr <= lli->lli_dir_depth)
				lum->lum_max_inherit_rr = LMV_INHERIT_RR_NONE;

			if (lum->lum_max_inherit_rr > lli->lli_dir_depth)
				lum->lum_max_inherit_rr -= lli->lli_dir_depth;
		}
	}
out:
	return rc;
}

int ll_dir_get_default_layout(struct inode *inode, void **plmm, int *plmm_size,
			      struct ptlrpc_request **request, u64 valid,
			      enum get_default_layout_type type)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct mdt_body *body;
	struct lov_mds_md *lmm = NULL;
	struct ptlrpc_request *req = NULL;
	int lmm_size = OBD_MAX_DEFAULT_EA_SIZE;
	struct md_op_data *op_data;
	struct lu_fid fid;
	int rc;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, lmm_size,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	op_data->op_valid = valid | OBD_MD_FLEASIZE | OBD_MD_FLDIREA;

	if (type == GET_DEFAULT_LAYOUT_ROOT) {
		lu_root_fid(&op_data->op_fid1);
		fid = op_data->op_fid1;
	} else {
		fid = *ll_inode2fid(inode);
	}

	rc = md_getattr(sbi->ll_md_exp, op_data, &req);
	ll_finish_md_op_data(op_data);
	if (rc < 0) {
		CDEBUG(D_INFO, "md_getattr failed on inode "DFID": rc %d\n",
		       PFID(&fid), rc);
		goto out;
	}

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	LASSERT(body);

	lmm_size = body->mbo_eadatasize;

	if (!(body->mbo_valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
	    lmm_size == 0) {
		rc = -ENODATA;
		goto out;
	}

	lmm = req_capsule_server_sized_get(&req->rq_pill,
					   &RMF_MDT_MD, lmm_size);
	LASSERT(lmm);

	/* This is coming from the MDS, so is probably in
	 * little endian.  We convert it to host endian before
	 * passing it to userspace.
	 */
	/* We don't swab objects for directories */
	switch (le32_to_cpu(lmm->lmm_magic)) {
	case LOV_MAGIC_V1:
	case LOV_MAGIC_V3:
	case LOV_MAGIC_COMP_V1:
	case LOV_USER_MAGIC_SPECIFIC:
		if (cpu_to_le32(LOV_MAGIC) != LOV_MAGIC)
			lustre_swab_lov_user_md((struct lov_user_md *)lmm, 0);
		break;
	case LMV_MAGIC_V1:
		if (cpu_to_le32(LMV_MAGIC) != LMV_MAGIC)
			lustre_swab_lmv_mds_md((union lmv_mds_md *)lmm);
		break;
	case LMV_USER_MAGIC:
		if (cpu_to_le32(LMV_USER_MAGIC) != LMV_USER_MAGIC)
			lustre_swab_lmv_user_md((struct lmv_user_md *)lmm);
		break;
	case LMV_MAGIC_FOREIGN: {
		struct lmv_foreign_md *lfm = (struct lmv_foreign_md *)lmm;

		if (cpu_to_le32(LMV_MAGIC_FOREIGN) != LMV_MAGIC_FOREIGN) {
			__swab32s(&lfm->lfm_magic);
			__swab32s(&lfm->lfm_length);
			__swab32s(&lfm->lfm_type);
			__swab32s(&lfm->lfm_flags);
		}
		break;
	}
	default:
		rc = -EPROTO;
		CERROR("%s: unknown magic: %lX: rc = %d\n", sbi->ll_fsname,
		       (unsigned long)lmm->lmm_magic, rc);
	}
out:
	*plmm = lmm;
	*plmm_size = lmm_size;
	*request = req;
	return rc;
}

/**
 * This function will be used to get default LOV/LMV/Default LMV
 * @valid will be used to indicate which stripe it will retrieve.
 * If the directory does not have its own default layout, then the
 * function will request the default layout from root FID.
 *	OBD_MD_MEA		LMV stripe EA
 *	OBD_MD_DEFAULT_MEA	Default LMV stripe EA
 *	otherwise		Default LOV EA.
 * Each time, it can only retrieve 1 stripe EA
 */
int ll_dir_getstripe_default(struct inode *inode, void **plmm, int *plmm_size,
			     struct ptlrpc_request **request,
			     struct ptlrpc_request **root_request,
			     u64 valid)
{
	struct ptlrpc_request *req = NULL;
	struct ptlrpc_request *root_req = NULL;
	struct lov_mds_md *lmm = NULL;
	int lmm_size = 0;
	int rc = 0;

	rc = ll_dir_get_default_layout(inode, (void **)&lmm, &lmm_size,
				       &req, valid, 0);
	if (rc == -ENODATA && !fid_is_root(ll_inode2fid(inode)) &&
	    !(valid & OBD_MD_MEA) && root_request) {
		int rc2 = ll_dir_get_default_layout(inode, (void **)&lmm,
						    &lmm_size, &root_req, valid,
						    GET_DEFAULT_LAYOUT_ROOT);
		if (rc2 == 0)
			rc = 0;
	}

	*plmm = lmm;
	*plmm_size = lmm_size;
	*request = req;
	if (root_request)
		*root_request = root_req;

	return rc;
}

/**
 * This function will be used to get default LOV/LMV/Default LMV
 * @valid will be used to indicate which stripe it will retrieve
 *	OBD_MD_MEA		LMV stripe EA
 *	OBD_MD_DEFAULT_MEA	Default LMV stripe EA
 *	otherwise		Default LOV EA.
 * Each time, it can only retrieve 1 stripe EA
 */
int ll_dir_getstripe(struct inode *inode, void **plmm, int *plmm_size,
		     struct ptlrpc_request **request, u64 valid)
{
	struct ptlrpc_request *req = NULL;
	struct lov_mds_md *lmm = NULL;
	int lmm_size = 0;
	int rc = 0;

	rc = ll_dir_get_default_layout(inode, (void **)&lmm, &lmm_size,
				       &req, valid, 0);

	*plmm = lmm;
	*plmm_size = lmm_size;
	*request = req;

	return rc;
}

int ll_get_mdt_idx_by_fid(struct ll_sb_info *sbi, const struct lu_fid *fid)
{
	struct md_op_data *op_data;
	int mdt_index, rc;

	op_data = kzalloc(sizeof(*op_data), GFP_NOFS);
	if (!op_data)
		return -ENOMEM;

	op_data->op_flags |= MF_GET_MDT_IDX;
	op_data->op_fid1 = *fid;
	rc = md_getattr(sbi->ll_md_exp, op_data, NULL);
	mdt_index = op_data->op_mds;
	kvfree(op_data);
	if (rc < 0)
		return rc;

	return mdt_index;
}

/*
 *  Get MDT index for the inode.
 */
int ll_get_mdt_idx(struct inode *inode)
{
	return ll_get_mdt_idx_by_fid(ll_i2sbi(inode), ll_inode2fid(inode));
}

/**
 * Generic handler to do any pre-copy work.
 *
 * It sends a first hsm_progress (with extent length == 0) to coordinator as a
 * first information for it that real work has started.
 *
 * Moreover, for a ARCHIVE request, it will sample the file data version and
 * store it in @copy.
 *
 * \return 0 on success.
 */
static int ll_ioc_copy_start(struct super_block *sb, struct hsm_copy *copy)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct hsm_progress_kernel hpk;
	int rc2, rc = 0;

	/* Forge a hsm_progress based on data from copy. */
	hpk.hpk_fid = copy->hc_hai.hai_fid;
	hpk.hpk_cookie = copy->hc_hai.hai_cookie;
	hpk.hpk_extent.offset = copy->hc_hai.hai_extent.offset;
	hpk.hpk_extent.length = 0;
	hpk.hpk_flags = 0;
	hpk.hpk_errval = 0;
	hpk.hpk_data_version = 0;

	/* For archive request, we need to read the current file version. */
	if (copy->hc_hai.hai_action == HSMA_ARCHIVE) {
		struct inode *inode;
		u64 data_version = 0;

		/* Get inode for this fid */
		inode = search_inode_for_lustre(sb, &copy->hc_hai.hai_fid);
		if (IS_ERR(inode)) {
			hpk.hpk_flags |= HP_FLAG_RETRY;
			/* hpk_errval is >= 0 */
			hpk.hpk_errval = -PTR_ERR(inode);
			rc = PTR_ERR(inode);
			goto progress;
		}

		/* Read current file data version */
		rc = ll_data_version(inode, &data_version, LL_DV_RD_FLUSH);
		iput(inode);
		if (rc != 0) {
			CDEBUG(D_HSM,
			       "Could not read file data version of "DFID" (rc = %d). Archive request (%#llx) could not be done.\n",
			       PFID(&copy->hc_hai.hai_fid), rc,
			       copy->hc_hai.hai_cookie);
			hpk.hpk_flags |= HP_FLAG_RETRY;
			/* hpk_errval must be >= 0 */
			hpk.hpk_errval = -rc;
			goto progress;
		}

		/* Store in the hsm_copy for later copytool use.
		 * Always modified even if no lsm.
		 */
		copy->hc_data_version = data_version;
	}

progress:
	/* On error, the request should be considered as completed */
	if (hpk.hpk_errval > 0)
		hpk.hpk_flags |= HP_FLAG_COMPLETED;

	rc2 = obd_iocontrol(LL_IOC_HSM_PROGRESS, sbi->ll_md_exp, sizeof(hpk),
			    &hpk, NULL);

	/* Return first error */
	return rc ? rc : rc2;
}

/**
 * Generic handler to do any post-copy work.
 *
 * It will send the last hsm_progress update to coordinator to inform it
 * that copy is finished and whether it was successful or not.
 *
 * Moreover,
 * - for ARCHIVE request, it will sample the file data version and compare it
 *   with the version saved in ll_ioc_copy_start(). If they do not match, copy
 *   will be considered as failed.
 * - for RESTORE request, it will sample the file data version and send it to
 *   coordinator which is useful if the file was imported as 'released'.
 *
 * \return 0 on success.
 */
static int ll_ioc_copy_end(struct super_block *sb, struct hsm_copy *copy)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct hsm_progress_kernel hpk;
	int rc2, rc = 0;

	/* If you modify the logic here, also check llapi_hsm_copy_end(). */
	/* Take care: copy->hc_hai.hai_action, len, gid and data are not
	 * initialized if copy_end was called with copy == NULL.
	 */

	/* Forge a hsm_progress based on data from copy. */
	hpk.hpk_fid = copy->hc_hai.hai_fid;
	hpk.hpk_cookie = copy->hc_hai.hai_cookie;
	hpk.hpk_extent = copy->hc_hai.hai_extent;
	hpk.hpk_flags = copy->hc_flags | HP_FLAG_COMPLETED;
	hpk.hpk_errval = copy->hc_errval;
	hpk.hpk_data_version = 0;

	/* For archive request, we need to check the file data was not changed.
	 *
	 * For restore request, we need to send the file data version, this is
	 * useful when the file was created using hsm_import.
	 */
	if (((copy->hc_hai.hai_action == HSMA_ARCHIVE) ||
	     (copy->hc_hai.hai_action == HSMA_RESTORE)) &&
	    (copy->hc_errval == 0)) {
		struct inode *inode;
		u64 data_version = 0;

		/* Get lsm for this fid */
		inode = search_inode_for_lustre(sb, &copy->hc_hai.hai_fid);
		if (IS_ERR(inode)) {
			hpk.hpk_flags |= HP_FLAG_RETRY;
			/* hpk_errval must be >= 0 */
			hpk.hpk_errval = -PTR_ERR(inode);
			rc = PTR_ERR(inode);
			goto progress;
		}

		rc = ll_data_version(inode, &data_version, LL_DV_RD_FLUSH);
		iput(inode);
		if (rc) {
			CDEBUG(D_HSM,
			       "Could not read file data version. Request could not be confirmed.\n");
			if (hpk.hpk_errval == 0)
				hpk.hpk_errval = -rc;
			goto progress;
		}

		/* Store in the hsm_copy for later copytool use.
		 * Always modified even if no lsm.
		 */
		hpk.hpk_data_version = data_version;

		/* File could have been stripped during archiving, so we need
		 * to check anyway.
		 */
		if ((copy->hc_hai.hai_action == HSMA_ARCHIVE) &&
		    (copy->hc_data_version != data_version)) {
			CDEBUG(D_HSM,
			       "File data version mismatched. File content was changed during archiving. " DFID ", start:%#llx current:%#llx\n",
			       PFID(&copy->hc_hai.hai_fid),
			       copy->hc_data_version, data_version);
			/* File was changed, send error to cdt. Do not ask for
			 * retry because if a file is modified frequently,
			 * the cdt will loop on retried archive requests.
			 * The policy engine will ask for a new archive later
			 * when the file will not be modified for some tunable
			 * time
			 */
			hpk.hpk_flags &= ~HP_FLAG_RETRY;
			rc = -EBUSY;
			/* hpk_errval must be >= 0 */
			hpk.hpk_errval = -rc;
		}
	}

progress:
	rc2 = obd_iocontrol(LL_IOC_HSM_PROGRESS, sbi->ll_md_exp, sizeof(hpk),
			    &hpk, NULL);

	return rc ? rc : rc2;
}

static int copy_and_ct_start(int cmd, struct obd_export *exp,
			     const struct lustre_kernelcomm __user *data)
{
	struct lustre_kernelcomm *lk;
	struct lustre_kernelcomm *tmp;
	size_t size = sizeof(*lk);
	size_t new_size;
	int rc;
	int i;

	lk = memdup_user(data, size);
	if (IS_ERR(lk)) {
		rc = PTR_ERR(lk);
		goto out_lk;
	}

	if (lk->lk_flags & LK_FLG_STOP)
		goto do_ioctl;

	if (!(lk->lk_flags & LK_FLG_DATANR)) {
		u32 archive_mask = lk->lk_data_count;
		int count;

		/* old hsm agent to old MDS */
		if (!exp_connect_archive_id_array(exp))
			goto do_ioctl;

		/* old hsm agent to new MDS */
		lk->lk_flags |= LK_FLG_DATANR;

		if (archive_mask == 0)
			goto do_ioctl;

		count = hweight32(archive_mask);
		new_size = offsetof(struct lustre_kernelcomm, lk_data[count]);
		tmp = kmalloc(new_size, GFP_KERNEL);
		if (!tmp) {
			rc = -ENOMEM;
			goto out_lk;
		}
		memcpy(tmp, lk, size);
		tmp->lk_data_count = count;
		kfree(lk);
		lk = tmp;
		size = new_size;

		count = 0;
		for (i = 0; i < sizeof(archive_mask) * 8; i++) {
			if (BIT(i) & archive_mask) {
				lk->lk_data[count] = i + 1;
				count++;
			}
		}
		goto do_ioctl;
	}

	/* new hsm agent to new mds */
	if (lk->lk_data_count > 0) {
		new_size = offsetof(struct lustre_kernelcomm,
				    lk_data[lk->lk_data_count]);
		tmp = kmalloc(new_size, GFP_KERNEL);
		if (!tmp) {
			rc = -ENOMEM;
			goto out_lk;
		}

		kfree(lk);
		lk = tmp;
		size = new_size;

		if (copy_from_user(lk, data, size)) {
			rc = -EFAULT;
			goto out_lk;
		}
	}

	/* new hsm agent to old MDS */
	if (!exp_connect_archive_id_array(exp)) {
		u32 archives = 0;

		if (lk->lk_data_count > LL_HSM_ORIGIN_MAX_ARCHIVE) {
			rc = -EINVAL;
			goto out_lk;
		}

		for (i = 0; i < lk->lk_data_count; i++) {
			if (lk->lk_data[i] > LL_HSM_ORIGIN_MAX_ARCHIVE) {
				rc = -EINVAL;
				CERROR("%s: archive id %d requested but only [0 - %zu] supported: rc = %d\n",
				       exp->exp_obd->obd_name, lk->lk_data[i],
				LL_HSM_ORIGIN_MAX_ARCHIVE, rc);
				goto out_lk;
			}

			if (lk->lk_data[i] == 0) {
				archives = 0;
				break;
			}

			archives |= BIT(lk->lk_data[i] - 1);
		}
		lk->lk_flags &= ~LK_FLG_DATANR;
		lk->lk_data_count = archives;
	}
do_ioctl:
	rc = obd_iocontrol(cmd, exp, size, lk, NULL);
out_lk:
	kfree(lk);
	return rc;
}

static int check_owner(int type, int id)
{
	switch (type) {
	case USRQUOTA:
		if (!uid_eq(current_euid(), make_kuid(&init_user_ns, id)))
			return -EPERM;
		break;
	case GRPQUOTA:
		if (!in_egroup_p(make_kgid(&init_user_ns, id)))
			return -EPERM;
		break;
	case PRJQUOTA:
		break;
	}
	return 0;
}

int quotactl_ioctl(struct super_block *sb, struct if_quotactl *qctl)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int cmd = qctl->qc_cmd;
	int type = qctl->qc_type;
	int id = qctl->qc_id;
	int valid = qctl->qc_valid;
	int rc = 0;

	switch (cmd) {
	case Q_SETQUOTA:
	case Q_SETINFO:
	case LUSTRE_Q_SETDEFAULT:
	case LUSTRE_Q_SETQUOTAPOOL:
	case LUSTRE_Q_SETINFOPOOL:
	case LUSTRE_Q_SETDEFAULT_POOL:
	case LUSTRE_Q_DELETEQID:
	case LUSTRE_Q_RESETQID:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (sb->s_flags & SB_RDONLY)
			return -EROFS;
		break;
	case Q_GETQUOTA:
	case LUSTRE_Q_GETDEFAULT:
	case LUSTRE_Q_GETQUOTAPOOL:
	case LUSTRE_Q_GETDEFAULT_POOL:
		if (check_owner(type, id) && !capable(CAP_SYS_ADMIN))
			return -EPERM;
		break;
	case Q_GETINFO:
	case LUSTRE_Q_GETINFOPOOL:
		break;
	default:
		CERROR("%s: unsupported quotactl op: %#x: rc = %d\n",
		       sbi->ll_fsname, cmd, -EOPNOTSUPP);
		return -ENOTSUPP;
	}

	if (valid != QC_GENERAL) {
		if (cmd == Q_GETINFO)
			qctl->qc_cmd = Q_GETOINFO;
		else if (cmd == Q_GETQUOTA ||
			 cmd == LUSTRE_Q_GETQUOTAPOOL)
			qctl->qc_cmd = Q_GETOQUOTA;
		else
			return -EINVAL;

		switch (valid) {
		case QC_MDTIDX:
			rc = obd_iocontrol(OBD_IOC_QUOTACTL, sbi->ll_md_exp,
					   sizeof(*qctl), qctl, NULL);
			break;
		case QC_OSTIDX:
			rc = obd_iocontrol(OBD_IOC_QUOTACTL, sbi->ll_dt_exp,
					   sizeof(*qctl), qctl, NULL);
			break;
		case QC_UUID:
			rc = obd_iocontrol(OBD_IOC_QUOTACTL, sbi->ll_md_exp,
					   sizeof(*qctl), qctl, NULL);
			if (rc == -EAGAIN)
				rc = obd_iocontrol(OBD_IOC_QUOTACTL,
						   sbi->ll_dt_exp,
						   sizeof(*qctl), qctl, NULL);
			break;
		default:
			rc = -EINVAL;
			break;
		}

		qctl->qc_cmd = cmd;
		if (rc)
			return rc;
	} else {
		struct obd_quotactl *oqctl;
		int oqctl_len = sizeof(*oqctl);

		if (LUSTRE_Q_CMD_IS_POOL(cmd))
			oqctl_len += LOV_MAXPOOLNAME + 1;

		oqctl = kzalloc(oqctl_len, GFP_NOFS);
		if (!oqctl)
			return -ENOMEM;

		QCTL_COPY(oqctl, qctl);
		rc = obd_quotactl(sbi->ll_md_exp, oqctl);
		if (rc) {
			kfree(oqctl);
			return rc;
		}
		/* If QIF_SPACE is not set, client should collect the
		 * space usage from OSSs by itself
		 */
		if ((cmd == Q_GETQUOTA || cmd == LUSTRE_Q_GETQUOTAPOOL) &&
		    !(oqctl->qc_dqblk.dqb_valid & QIF_SPACE) &&
		    !oqctl->qc_dqblk.dqb_curspace) {
			struct obd_quotactl *oqctl_tmp;
			int qctl_len = sizeof(*oqctl_tmp) + LOV_MAXPOOLNAME + 1;

			oqctl_tmp = kzalloc(qctl_len, GFP_NOFS);
			if (!oqctl_tmp) {
				rc = -ENOMEM;
				goto out;
			}

			if (cmd == LUSTRE_Q_GETQUOTAPOOL) {
				oqctl_tmp->qc_cmd = LUSTRE_Q_GETQUOTAPOOL;
				memcpy(oqctl_tmp->qc_poolname,
				       qctl->qc_poolname,
				       LOV_MAXPOOLNAME + 1);
			} else {
				oqctl_tmp->qc_cmd = Q_GETOQUOTA;
			}
			oqctl_tmp->qc_id = oqctl->qc_id;
			oqctl_tmp->qc_type = oqctl->qc_type;

			/* collect space usage from OSTs */
			oqctl_tmp->qc_dqblk.dqb_curspace = 0;
			rc = obd_quotactl(sbi->ll_dt_exp, oqctl_tmp);
			if (!rc || rc == -EREMOTEIO) {
				oqctl->qc_dqblk.dqb_curspace =
					oqctl_tmp->qc_dqblk.dqb_curspace;
				oqctl->qc_dqblk.dqb_valid |= QIF_SPACE;
			}

			/* collect space & inode usage from MDTs */
			oqctl_tmp->qc_cmd = Q_GETOQUOTA;
			oqctl_tmp->qc_dqblk.dqb_curspace = 0;
			oqctl_tmp->qc_dqblk.dqb_curinodes = 0;
			rc = obd_quotactl(sbi->ll_md_exp, oqctl_tmp);
			if (!rc || rc == -EREMOTEIO) {
				oqctl->qc_dqblk.dqb_curspace +=
					oqctl_tmp->qc_dqblk.dqb_curspace;
				oqctl->qc_dqblk.dqb_curinodes =
					oqctl_tmp->qc_dqblk.dqb_curinodes;
				oqctl->qc_dqblk.dqb_valid |= QIF_INODES;
			} else {
				oqctl->qc_dqblk.dqb_valid &= ~QIF_SPACE;
			}

			kfree(oqctl_tmp);
		}
out:
		QCTL_COPY(qctl, oqctl);
		kfree(oqctl);
	}

	return rc;
}

int ll_rmfid(struct file *file, void __user *arg)
{
	const struct fid_array __user *ufa = arg;
	struct inode *inode = file_inode(file);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct fid_array *lfa = NULL;
	size_t size;
	unsigned int nr;
	int i, rc, *rcs = NULL;

	if (!capable(CAP_DAC_READ_SEARCH) &&
	    !test_bit(LL_SBI_USER_FID2PATH, ll_i2sbi(inode)->ll_flags))
		return -EPERM;
	/* Only need to get the buflen */
	if (get_user(nr, &ufa->fa_nr))
		return -EFAULT;
	/* DoS protection */
	if (nr > OBD_MAX_FIDS_IN_ARRAY)
		return -E2BIG;

	size = offsetof(struct fid_array, fa_fids[nr]);
	lfa = kzalloc(size, GFP_NOFS);
	if (!lfa)
		return -ENOMEM;

	rcs = kcalloc(nr, sizeof(int), GFP_NOFS);
	if (!rcs) {
		rc = -ENOMEM;
		goto free_lfa;
	}

	if (copy_from_user(lfa, arg, size)) {
		rc = -EFAULT;
		goto free_rcs;
	}

	/* In case of subdirectory mount, we need to make sure all the files
	 * for which we want to remove FID are visible in the namespace.
	 */
	if (!fid_is_root(&sbi->ll_root_fid)) {
		struct fid_array *lfa_new = NULL;
		int path_len = PATH_MAX, linkno;
		struct getinfo_fid2path *gf;
		int idx, last_idx = nr - 1;

		lfa_new = kzalloc(size, GFP_NOFS);
		if (!lfa_new) {
			rc = -ENOMEM;
			goto free_rcs;
		}
		lfa_new->fa_nr = 0;

		gf = kmalloc(sizeof(*gf) + path_len + 1, GFP_NOFS);
		if (!gf) {
			rc = -ENOMEM;
			goto free_rcs;
		}

		for (idx = 0; idx < nr; idx++) {
			linkno = 0;
			while (1) {
				memset(gf, 0, sizeof(*gf) + path_len + 1);
				gf->gf_fid = lfa->fa_fids[idx];
				gf->gf_pathlen = path_len;
				gf->gf_linkno = linkno;
				rc = __ll_fid2path(inode, gf,
						   sizeof(*gf) + gf->gf_pathlen,
						   gf->gf_pathlen);
				if (rc == -ENAMETOOLONG) {
					struct getinfo_fid2path *tmpgf;

					path_len += PATH_MAX;
					tmpgf = krealloc(gf,
						     sizeof(*gf) + path_len + 1,
						     GFP_NOFS);
					if (!tmpgf) {
						kfree(gf);
						kfree(lfa_new);
						rc = -ENOMEM;
						goto free_rcs;
					}
					gf = tmpgf;
					continue;
				}
				if (rc)
					break;
				if (gf->gf_linkno == linkno)
					break;
				linkno = gf->gf_linkno;
			}

			if (!rc) {
				/* All the links for this fid are visible in the
				 * mounted subdir. So add it to the list of fids
				 * to remove.
				 */
				lfa_new->fa_fids[lfa_new->fa_nr++] =
					lfa->fa_fids[idx];
			} else {
				/* At least one link for this fid is not visible
				 * in the mounted subdir. So add it at the end
				 * of the list that will be hidden to lower
				 * layers, and set -ENOENT as ret code.
				 */
				lfa_new->fa_fids[last_idx] = lfa->fa_fids[idx];
				rcs[last_idx--] = rc;
			}
		}
		kfree(gf);
		kfree(lfa);
		lfa = lfa_new;
	}

	if (lfa->fa_nr == 0) {
		rc = rcs[nr - 1];
		goto free_rcs;
	}

	/* Call mdc_iocontrol */
	rc = md_rmfid(ll_i2mdexp(file_inode(file)), lfa, rcs, NULL);
	lfa->fa_nr = nr;
	if (!rc) {
		for (i = 0; i < nr; i++)
			if (rcs[i])
				lfa->fa_fids[i].f_ver = rcs[i];
		if (copy_to_user(arg, lfa, size))
			rc = -EFAULT;
	}

free_rcs:
	kfree(rcs);
free_lfa:
	kfree(lfa);

	return rc;
}

/* This function tries to get a single name component,
 * to send to the server. No actual path traversal involved,
 * so we limit to NAME_MAX
 */
static char *ll_getname(const char __user *filename)
{
	char *tmp;

	tmp = strndup_user(filename, NAME_MAX + 1);
	if (IS_ERR(tmp)) {
		int ret = PTR_ERR(tmp);

		switch (ret) {
		case -EFAULT: /* zero length */
			tmp = ERR_PTR(-ENOENT);
			break;
		case -EINVAL:
			tmp = ERR_PTR(-ENAMETOOLONG);
		fallthrough;
		default:
			break;
		}
	}

	return tmp;
}

static long ll_dir_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct obd_ioctl_data *data = NULL;
	void __user *uarg = (void __user *)arg;
	int rc = 0;

	CDEBUG(D_VFSTRACE|D_IOCTL, "VFS Op:inode="DFID"(%pK) cmd=%x arg=%lx\n",
	       PFID(ll_inode2fid(inode)), inode, cmd, arg);

	/* asm-ppc{,64} declares TCGETS, et. al. as type 't' not 'T' */
	if (_IOC_TYPE(cmd) == 'T' || _IOC_TYPE(cmd) == 't') /* tty ioctls */
		return -ENOTTY;

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_IOCTL, 1);
	switch (cmd) {
	case IOC_MDC_LOOKUP: {
		int namelen, len = 0;
		char *filename;

		rc = obd_ioctl_getdata(&data, &len, uarg);
		if (rc != 0)
			return rc;

		filename = data->ioc_inlbuf1;
		namelen = strlen(filename);
		if (namelen < 1) {
			CDEBUG(D_INFO, "IOC_MDC_LOOKUP missing filename\n");
			rc = -EINVAL;
			goto out_free;
		}

		rc = ll_get_fid_by_name(inode, filename, namelen, NULL, NULL);
		if (rc < 0) {
			CERROR("%s: lookup %.*s failed: rc = %d\n",
			       sbi->ll_fsname, namelen, filename, rc);
			goto out_free;
		}
out_free:
		kvfree(data);
		return rc;
	}
	case LL_IOC_LMV_SETSTRIPE: {
		struct lmv_user_md  *lum;
		char *filename;
		int namelen = 0;
		int lumlen = 0;
		umode_t mode;
		bool createonly = false;
		int len;
		int rc;

		rc = obd_ioctl_getdata(&data, &len, uarg);
		if (rc)
			return rc;

		if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2 ||
		    data->ioc_inllen1 == 0 || data->ioc_inllen2 == 0) {
			rc = -EINVAL;
			goto lmv_out_free;
		}

		filename = data->ioc_inlbuf1;
		namelen = data->ioc_inllen1;

		if (namelen < 1) {
			CDEBUG(D_INFO, "IOC_MDC_LOOKUP missing filename\n");
			rc = -EINVAL;
			goto lmv_out_free;
		}
		lum = (struct lmv_user_md *)data->ioc_inlbuf2;
		lumlen = data->ioc_inllen2;

		if (!lmv_user_magic_supported(lum->lum_magic)) {
			CERROR("%s: wrong lum magic %x : rc = %d\n", filename,
			       lum->lum_magic, -EINVAL);
			rc = -EINVAL;
			goto lmv_out_free;
		}

		if ((lum->lum_magic == LMV_USER_MAGIC ||
		     lum->lum_magic == LMV_USER_MAGIC_SPECIFIC) &&
		    lumlen < sizeof(*lum)) {
			CERROR("%s: wrong lum size %d for magic %x : rc = %d\n",
			       filename, lumlen, lum->lum_magic, -EINVAL);
			rc = -EINVAL;
			goto lmv_out_free;
		}

		if (lum->lum_magic == LMV_MAGIC_FOREIGN &&
		    lumlen < sizeof(struct lmv_foreign_md)) {
			CERROR("%s: wrong lum magic %x or size %d: rc = %d\n",
			       filename, lum->lum_magic, lumlen, -EFAULT);
			rc = -EINVAL;
			goto lmv_out_free;
		}

		mode = data->ioc_type;
		createonly = data->ioc_obdo1.o_flags & OBD_FL_OBDMDEXISTS;
		rc = ll_dir_setdirstripe(dentry, lum, lumlen, filename, mode,
					 createonly);
lmv_out_free:
		kvfree(data);
		return rc;
	}
	case LL_IOC_LMV_SET_DEFAULT_STRIPE: {
		struct lmv_user_md __user *ulump = uarg;
		struct lmv_user_md lum;
		int rc;

		if (copy_from_user(&lum, ulump, sizeof(lum)))
			return -EFAULT;

		if (lum.lum_magic != LMV_USER_MAGIC)
			return -EINVAL;

		rc = ll_dir_setstripe(inode, (struct lov_user_md *)&lum, 0);

		return rc;
	}
	case LL_IOC_LOV_SETSTRIPE_NEW:
	case LL_IOC_LOV_SETSTRIPE: {
		struct lov_user_md_v3 *lumv3 = NULL;
		struct lov_user_md_v1 lumv1;
		struct lov_user_md_v1 *lumv1_ptr = &lumv1;
		struct lov_user_md_v1 __user *lumv1p = uarg;
		struct lov_user_md_v3 __user *lumv3p = uarg;
		int lum_size = 0;
		int set_default = 0;

		BUILD_BUG_ON(sizeof(struct lov_user_md_v3) <=
			     sizeof(struct lov_comp_md_v1));
		BUILD_BUG_ON(sizeof(*lumv3) != sizeof(*lumv3p));
		/* first try with v1 which is smaller than v3 */
		if (copy_from_user(&lumv1, lumv1p, sizeof(lumv1)))
			return -EFAULT;

		if (is_root_inode(inode))
			set_default = 1;

		switch (lumv1.lmm_magic) {
		case LOV_USER_MAGIC_V3:
		case LOV_USER_MAGIC_SPECIFIC:
			lum_size = ll_lov_user_md_size(&lumv1);
			if (lum_size < 0)
				return lum_size;
			lumv3 = kzalloc(lum_size, GFP_NOFS);
			if (!lumv3)
				return -ENOMEM;
			if (copy_from_user(lumv3, lumv3p, lum_size)) {
				rc = -EFAULT;
				goto out;
			}
			lumv1_ptr = (struct lov_user_md_v1 *)lumv3;
			break;
		case LOV_USER_MAGIC_V1:
			break;
		default:
			rc = -ENOTSUPP;
			goto out;
		}

		/* in v1 and v3 cases lumv1 points to data */
		rc = ll_dir_setstripe(inode, lumv1_ptr, set_default);
out:
		kfree(lumv3);
		return rc;
	}
	case LL_IOC_LMV_GETSTRIPE: {
		struct lmv_user_md __user *ulmv = uarg;
		struct lmv_user_md lum;
		struct ptlrpc_request *request = NULL;
		struct lmv_user_md *tmp = NULL;
		union lmv_mds_md *lmm = NULL;
		u64 valid = 0;
		int max_stripe_count;
		int stripe_count;
		int mdt_index;
		int lum_size;
		int lmmsize;
		int rc;
		int i;

		if (copy_from_user(&lum, ulmv, sizeof(*ulmv)))
			return -EFAULT;

		/* get default LMV */
		if (lum.lum_magic == LMV_USER_MAGIC &&
		    lum.lum_type != LMV_TYPE_RAW) {
			rc = ll_dir_get_default_lmv(inode, &lum);
			if (rc)
				return rc;

			if (copy_to_user(ulmv, &lum, sizeof(lum)))
				return -EFAULT;

			return 0;
		}

		max_stripe_count = lum.lum_stripe_count;
		/* lum_magic will indicate which stripe the ioctl will like
		 * to get, LMV_MAGIC_V1 is for normal LMV stripe, LMV_USER_MAGIC
		 * is for default LMV stripe
		 */
		if (lum.lum_magic == LMV_MAGIC_V1)
			valid |= OBD_MD_MEA;
		else if (lum.lum_magic == LMV_USER_MAGIC)
			valid |= OBD_MD_DEFAULT_MEA;
		else
			return -EINVAL;

		rc = ll_dir_getstripe_default(inode, (void **)&lmm, &lmmsize,
					      &request, NULL, valid);
		if (rc)
			goto finish_req;

		/* get default LMV in raw mode */
		if (lum.lum_magic == LMV_USER_MAGIC) {
			if (copy_to_user(ulmv, lmm, lmmsize))
				rc = -EFAULT;

			goto finish_req;
		}

		/* if foreign LMV case, fake stripes number */
		if (lmm->lmv_magic == LMV_MAGIC_FOREIGN) {
			struct lmv_foreign_md *lfm;

			lfm = (struct lmv_foreign_md *)lmm;
			if (lfm->lfm_length < XATTR_SIZE_MAX -
			    offsetof(typeof(*lfm), lfm_value)) {
				u32 size = lfm->lfm_length +
					   offsetof(typeof(*lfm), lfm_value);

				stripe_count = lmv_foreign_to_md_stripes(size);
			} else {
				CERROR("%s: invalid %d foreign size returned: rc = %d\n",
				       sbi->ll_fsname, lfm->lfm_length,
				       -EINVAL);
				return -EINVAL;
			}
		} else {
			stripe_count = lmv_mds_md_stripe_count_get(lmm);
		}
		if (max_stripe_count < stripe_count) {
			lum.lum_stripe_count = stripe_count;
			if (copy_to_user(ulmv, &lum, sizeof(lum))) {
				rc = -EFAULT;
				goto finish_req;
			}
			rc = -E2BIG;
			goto finish_req;
		}

		/* enough room on user side and foreign case */
		if (lmm->lmv_magic == LMV_MAGIC_FOREIGN) {
			struct lmv_foreign_md *lfm;
			u32 size;

			lfm = (struct lmv_foreign_md *)lmm;
			size = lfm->lfm_length +
			       offsetof(struct lmv_foreign_md, lfm_value);
			if (copy_to_user(ulmv, lfm, size))
				rc = -EFAULT;
			goto finish_req;
		}

		lum_size = lmv_user_md_size(stripe_count,
					    LMV_USER_MAGIC_SPECIFIC);
		tmp = kzalloc(lum_size, GFP_NOFS);
		if (!tmp) {
			rc = -ENOMEM;
			goto finish_req;
		}

		mdt_index = ll_get_mdt_idx(inode);
		if (mdt_index < 0) {
			rc = -ENOMEM;
			goto out_tmp;
		}
		tmp->lum_magic = LMV_MAGIC_V1;
		tmp->lum_stripe_count = 0;
		tmp->lum_stripe_offset = mdt_index;
		tmp->lum_hash_type = lmv_mds_md_hash_type_get(lmm);
		for (i = 0; i < stripe_count; i++) {
			struct lu_fid fid;

			fid_le_to_cpu(&fid, &lmm->lmv_md_v1.lmv_stripe_fids[i]);
			if (fid_is_sane(&fid)) {
				mdt_index = ll_get_mdt_idx_by_fid(sbi, &fid);
				if (mdt_index < 0) {
					rc = mdt_index;
					goto out_tmp;
				}
				tmp->lum_objects[i].lum_mds = mdt_index;
				tmp->lum_objects[i].lum_fid = fid;
			}

			tmp->lum_stripe_count++;
		}

		if (copy_to_user(ulmv, tmp, lum_size)) {
			rc = -EFAULT;
			goto out_tmp;
		}
out_tmp:
		kfree(tmp);
finish_req:
		ptlrpc_req_finished(request);
		return rc;
	}
	case LL_IOC_RMFID:
		return ll_rmfid(file, uarg);
	case LL_IOC_LOV_SWAP_LAYOUTS:
		return -EPERM;
	case LL_IOC_LOV_GETSTRIPE:
	case LL_IOC_LOV_GETSTRIPE_NEW:
	case LL_IOC_MDC_GETINFO_V1:
	case LL_IOC_MDC_GETINFO_V2:
	case IOC_MDC_GETFILEINFO_V1:
	case IOC_MDC_GETFILEINFO_V2:
	case IOC_MDC_GETFILESTRIPE: {
		struct ptlrpc_request *request = NULL;
		struct ptlrpc_request *root_request = NULL;
		struct lov_user_md __user *lump;
		struct lov_mds_md *lmm = NULL;
		struct mdt_body *body;
		char *filename = NULL;
		lstat_t __user *statp = NULL;
		struct statx __user *stxp = NULL;
		u64 __user *flagsp = NULL;
		u32 __user *lmmsizep = NULL;
		struct lu_fid __user *fidp = NULL;
		int lmmsize;
		bool api32;

		if (cmd == IOC_MDC_GETFILEINFO_V1 ||
		    cmd == IOC_MDC_GETFILEINFO_V2 ||
		    cmd == IOC_MDC_GETFILESTRIPE) {
			filename = ll_getname(uarg);
			if (IS_ERR(filename))
				return PTR_ERR(filename);

			rc = ll_lov_getstripe_ea_info(inode, filename, &lmm,
						      &lmmsize, &request);
		} else {
			rc = ll_dir_getstripe_default(inode, (void **)&lmm,
						      &lmmsize, &request,
						      &root_request, 0);
		}

		if (request) {
			body = req_capsule_server_get(&request->rq_pill,
						      &RMF_MDT_BODY);
			LASSERT(body);
		} else {
			goto out_req;
		}

		if (rc == -ENODATA && (cmd == IOC_MDC_GETFILEINFO_V1 ||
				       cmd == LL_IOC_MDC_GETINFO_V1 ||
				       cmd == IOC_MDC_GETFILEINFO_V2 ||
				       cmd == LL_IOC_MDC_GETINFO_V2)) {
			lmmsize = 0;
			rc = 0;
		}

		if (rc < 0)
			goto out_req;

		if (cmd == IOC_MDC_GETFILESTRIPE ||
		    cmd == LL_IOC_LOV_GETSTRIPE ||
		    cmd == LL_IOC_LOV_GETSTRIPE_NEW) {
			lump = uarg;
		} else if (cmd == IOC_MDC_GETFILEINFO_V1 ||
			   cmd == LL_IOC_MDC_GETINFO_V1) {
			struct lov_user_mds_data_v1 __user *lmdp = uarg;

			statp = &lmdp->lmd_st;
			lump = &lmdp->lmd_lmm;
		} else {
			struct lov_user_mds_data __user *lmdp = uarg;

			fidp = &lmdp->lmd_fid;
			stxp = &lmdp->lmd_stx;
			flagsp = &lmdp->lmd_flags;
			lmmsizep = &lmdp->lmd_lmmsize;
			lump = &lmdp->lmd_lmm;
		}

		if (lmmsize == 0) {
			/* If the file has no striping then zero out *lump so
			 * that the caller isn't confused by garbage.
			 */
			if (clear_user(lump, sizeof(*lump))) {
				rc = -EFAULT;
				goto out_req;
			}
		} else if (copy_to_user(lump, lmm, lmmsize)) {
			if (copy_to_user(lump, lmm, sizeof(*lump))) {
				rc = -EFAULT;
				goto out_req;
			}
			rc = -EOVERFLOW;
		}
		api32 = test_bit(LL_SBI_32BIT_API, sbi->ll_flags);

		if (cmd == IOC_MDC_GETFILEINFO_V1 ||
		    cmd == LL_IOC_MDC_GETINFO_V1) {
			lstat_t st = { 0 };

			st.st_dev = inode->i_sb->s_dev;
			st.st_mode = body->mbo_mode;
			st.st_nlink = body->mbo_nlink;
			st.st_uid = body->mbo_uid;
			st.st_gid = body->mbo_gid;
			st.st_rdev = body->mbo_rdev;
			if (fscrypt_require_key(inode) == -ENOKEY)
				st.st_size = round_up(st.st_size,
						      LUSTRE_ENCRYPTION_UNIT_SIZE);
			else
				st.st_size = body->mbo_size;

			st.st_blksize = PAGE_SIZE;
			st.st_blocks = body->mbo_blocks;
			st.st_atime = body->mbo_atime;
			st.st_mtime = body->mbo_mtime;
			st.st_ctime = body->mbo_ctime;
			st.st_ino = cl_fid_build_ino(&body->mbo_fid1, api32);

			if (copy_to_user(statp, &st, sizeof(st))) {
				rc = -EFAULT;
				goto out_req;
			}
		} else if (cmd == IOC_MDC_GETFILEINFO_V2 ||
			   cmd == LL_IOC_MDC_GETINFO_V2) {
			struct statx stx = { 0 };
			u64 valid = body->mbo_valid;

			stx.stx_blksize = PAGE_SIZE;
			stx.stx_nlink = body->mbo_nlink;
			stx.stx_uid = body->mbo_uid;
			stx.stx_gid = body->mbo_gid;
			stx.stx_mode = body->mbo_mode;
			stx.stx_ino = cl_fid_build_ino(&body->mbo_fid1,
						       api32);
			if (fscrypt_require_key(inode) == -ENOKEY)
				stx.stx_size = round_up(stx.stx_size,
						   LUSTRE_ENCRYPTION_UNIT_SIZE);
			else
				stx.stx_size = body->mbo_size;
			stx.stx_blocks = body->mbo_blocks;
			stx.stx_atime.tv_sec = body->mbo_atime;
			stx.stx_ctime.tv_sec = body->mbo_ctime;
			stx.stx_mtime.tv_sec = body->mbo_mtime;
			stx.stx_btime.tv_sec = body->mbo_btime;
			stx.stx_rdev_major = MAJOR(body->mbo_rdev);
			stx.stx_rdev_minor = MINOR(body->mbo_rdev);
			stx.stx_dev_major = MAJOR(inode->i_sb->s_dev);
			stx.stx_dev_minor = MINOR(inode->i_sb->s_dev);
			stx.stx_mask |= STATX_BASIC_STATS | STATX_BTIME;

			/* For a striped directory, the size and blocks returned
			 * from MDT is not correct.
			 * The size and blocks are aggregated by client across
			 * all stripes.
			 * Thus for a striped directory, do not return the valid
			 * FLSIZE and FLBLOCKS flags to the caller.
			 * However, this whould be better decided by the MDS
			 * instead of the client.
			 */
			if (cmd == LL_IOC_MDC_GETINFO_V2 &&
			    ll_i2info(inode)->lli_lsm_md)
				valid &= ~(OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);

			if (flagsp && copy_to_user(flagsp, &valid,
						   sizeof(*flagsp))) {
				rc = -EFAULT;
				goto out_req;
			}

			if (fidp && copy_to_user(fidp, &body->mbo_fid1,
						 sizeof(*fidp))) {
				rc = -EFAULT;
				goto out_req;
			}

			if (!(valid & OBD_MD_FLSIZE))
				stx.stx_mask &= ~STATX_SIZE;
			if (!(valid & OBD_MD_FLBLOCKS))
				stx.stx_mask &= ~STATX_BLOCKS;

			if (stxp && copy_to_user(stxp, &stx, sizeof(stx))) {
				rc = -EFAULT;
				goto out_req;
			}

			if (lmmsizep && copy_to_user(lmmsizep, &lmmsize,
						     sizeof(*lmmsizep))) {
				rc = -EFAULT;
				goto out_req;
			}
		}

out_req:
		ptlrpc_req_finished(request);
		ptlrpc_req_finished(root_request);
		kfree(filename);
		return rc;
	}
	case OBD_IOC_QUOTACTL: {
		struct if_quotactl *qctl;
		int qctl_len = sizeof(*qctl) + LOV_MAXPOOLNAME + 1;

		qctl = kzalloc(qctl_len, GFP_NOFS);
		if (!qctl)
			return -ENOMEM;

		if (copy_from_user(qctl, uarg, sizeof(*qctl))) {
			rc = -EFAULT;
			goto out_quotactl;
		}

		if (LUSTRE_Q_CMD_IS_POOL(qctl->qc_cmd)) {
			char __user *from = uarg +
					    offsetof(typeof(*qctl), qc_poolname);

			if (copy_from_user(qctl->qc_poolname, from,
					   LOV_MAXPOOLNAME + 1)) {
				rc = -EFAULT;
				goto out_quotactl;
			}
		}

		rc = quotactl_ioctl(inode->i_sb, qctl);
		if ((rc == 0 || rc == -ENODATA) &&
		    copy_to_user(uarg, qctl, sizeof(*qctl)))
			rc = -EFAULT;
out_quotactl:
		kfree(qctl);
		return rc;
	}
	case LL_IOC_GETOBDCOUNT: {
		u32 count, vallen;
		struct obd_export *exp;

		if (copy_from_user(&count, uarg, sizeof(count)))
			return -EFAULT;

		/* get ost count when count is zero, get mdt count otherwise */
		exp = count ? sbi->ll_md_exp : sbi->ll_dt_exp;
		vallen = sizeof(count);
		rc = obd_get_info(NULL, exp, sizeof(KEY_TGT_COUNT),
				  KEY_TGT_COUNT, &vallen, &count);
		if (rc) {
			CERROR("%s: get target count failed: rc = %d\n",
			       sbi->ll_fsname, rc);
			return rc;
		}

		if (copy_to_user(uarg, &count, sizeof(count)))
			return -EFAULT;

		return 0;
	}
	case LL_IOC_GET_CONNECT_FLAGS:
		return obd_iocontrol(cmd, sbi->ll_md_exp, 0, NULL, uarg);
	case LL_IOC_FID2MDTIDX: {
		struct obd_export *exp = ll_i2mdexp(inode);
		struct lu_fid fid;
		u32 index;

		if (copy_from_user(&fid, uarg, sizeof(fid)))
			return -EFAULT;

		/* Call mdc_iocontrol */
		rc = obd_iocontrol(LL_IOC_FID2MDTIDX, exp, sizeof(fid), &fid,
				   (u32 __user *)&index);
		if (rc)
			return rc;

		return index;
	}
	case LL_IOC_HSM_REQUEST: {
		struct hsm_user_request	*hur;
		ssize_t	totalsize;

		hur = memdup_user(uarg, sizeof(*hur));
		if (IS_ERR(hur))
			return PTR_ERR(hur);

		/* Compute the whole struct size */
		totalsize = hur_len(hur);
		kfree(hur);
		if (totalsize < 0)
			return -E2BIG;

		/* Final size will be more than double totalsize */
		if (totalsize >= MDS_MAXREQSIZE / 3)
			return -E2BIG;

		hur = kzalloc(totalsize, GFP_NOFS);
		if (!hur)
			return -ENOMEM;

		/* Copy the whole struct */
		if (copy_from_user(hur, uarg, totalsize)) {
			rc = -EFAULT;
			goto out_hur;
		}

		if (hur->hur_request.hr_action == HUA_RELEASE) {
			const struct lu_fid *fid;
			struct inode *f;
			int i;

			for (i = 0; i < hur->hur_request.hr_itemcount; i++) {
				fid = &hur->hur_user_item[i].hui_fid;
				f = search_inode_for_lustre(inode->i_sb, fid);
				if (IS_ERR(f)) {
					rc = PTR_ERR(f);
					break;
				}

				rc = ll_hsm_release(f);
				iput(f);
				if (rc != 0)
					break;
			}
		} else {
			rc = obd_iocontrol(cmd, ll_i2mdexp(inode), totalsize,
					   hur, NULL);
		}
out_hur:
		kvfree(hur);

		return rc;
	}
	case LL_IOC_HSM_PROGRESS: {
		struct hsm_progress_kernel hpk;
		struct hsm_progress hp;

		if (copy_from_user(&hp, uarg, sizeof(hp)))
			return -EFAULT;

		hpk.hpk_fid = hp.hp_fid;
		hpk.hpk_cookie = hp.hp_cookie;
		hpk.hpk_extent = hp.hp_extent;
		hpk.hpk_flags = hp.hp_flags;
		hpk.hpk_errval = hp.hp_errval;
		hpk.hpk_data_version = 0;

		/* File may not exist in Lustre; all progress
		 * reported to Lustre root
		 */
		rc = obd_iocontrol(cmd, sbi->ll_md_exp, sizeof(hpk), &hpk,
				   NULL);
		return rc;
	}
	case LL_IOC_HSM_CT_START:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		rc = copy_and_ct_start(cmd, sbi->ll_md_exp, uarg);
		return rc;

	case LL_IOC_HSM_COPY_START: {
		struct hsm_copy	*copy;
		int rc;

		copy = memdup_user(uarg, sizeof(*copy));
		if (IS_ERR(copy))
			return PTR_ERR(copy);

		rc = ll_ioc_copy_start(inode->i_sb, copy);
		if (copy_to_user(uarg, copy, sizeof(*copy)))
			rc = -EFAULT;

		kfree(copy);
		return rc;
	}
	case LL_IOC_HSM_COPY_END: {
		struct hsm_copy	*copy;
		int rc;

		copy = memdup_user(uarg, sizeof(*copy));
		if (IS_ERR(copy))
			return PTR_ERR(copy);

		rc = ll_ioc_copy_end(inode->i_sb, copy);
		if (copy_to_user(uarg, copy, sizeof(*copy)))
			rc = -EFAULT;

		kfree(copy);
		return rc;
	}
	case LL_IOC_MIGRATE: {
		struct lmv_user_md *lum;
		char *filename;
		int namelen = 0;
		u32 flags;
		int len;
		int rc;

		rc = obd_ioctl_getdata(&data, &len, uarg);
		if (rc)
			return rc;

		if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2 ||
		    !data->ioc_inllen1 || !data->ioc_inllen2) {
			rc = -EINVAL;
			goto migrate_free;
		}

		filename = data->ioc_inlbuf1;
		namelen = data->ioc_inllen1;
		flags = data->ioc_type;

		if (namelen < 1 || namelen != strlen(filename) + 1) {
			CDEBUG(D_INFO, "IOC_MDC_LOOKUP missing filename\n");
			rc = -EINVAL;
			goto migrate_free;
		}

		lum = (struct lmv_user_md *)data->ioc_inlbuf2;
		if (lum->lum_magic != LMV_USER_MAGIC &&
		    lum->lum_magic != LMV_USER_MAGIC_SPECIFIC) {
			rc = -EINVAL;
			CERROR("%s: wrong lum magic %x: rc = %d\n",
			       filename, lum->lum_magic, rc);
			goto migrate_free;
		}

		rc = ll_migrate(inode, file, lum, filename, flags);
migrate_free:
		kvfree(data);

		return rc;
	}
	case LL_IOC_PCC_DETACH_BY_FID: {
		struct lu_pcc_detach_fid *detach;
		struct lu_fid *fid;
		struct inode *inode2;
		unsigned long ino;

		detach = memdup_user(uarg, sizeof(*detach));
		if (IS_ERR(detach))
			return PTR_ERR(detach);


		fid = &detach->pccd_fid;
		ino = cl_fid_build_ino(fid, ll_need_32bit_api(sbi));
		inode2 = ilookup5(inode->i_sb, ino, ll_test_inode_by_fid, fid);
		if (!inode2) {
			/* Target inode is not in inode cache, and PCC file
			 * has aleady released, return immdiately.
			 */
			rc = 0;
			goto out_detach;
		}

		if (!S_ISREG(inode2->i_mode)) {
			rc = -EINVAL;
			goto out_iput;
		}

		if (!inode_owner_or_capable(inode2)) {
			rc = -EPERM;
			goto out_iput;
		}

		rc = pcc_ioctl_detach(inode2, detach->pccd_opt);
out_iput:
		iput(inode2);
out_detach:
		kfree(detach);
		return rc;
	}
	default:
		rc = ll_iocontrol(inode, file, cmd, uarg);
		if (rc == -ENOTTY)
			rc = obd_iocontrol(cmd, sbi->ll_dt_exp, 0, NULL, uarg);
		break;
	}
	return rc;
}

static loff_t ll_dir_seek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_mapping->host;
	struct ll_file_data *fd = file->private_data;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	bool api32 = ll_need_32bit_api(sbi);
	loff_t ret = -EINVAL;

	inode_lock(inode);
	switch (origin) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		offset += file->f_pos;
		break;
	case SEEK_END:
		if (offset > 0)
			goto out;
		if (api32)
			offset += LL_DIR_END_OFF_32BIT;
		else
			offset += LL_DIR_END_OFF;
		break;
	default:
		goto out;
	}

	if (offset >= 0 &&
	    ((api32 && offset <= LL_DIR_END_OFF_32BIT) ||
	     (!api32 && offset <= LL_DIR_END_OFF))) {
		if (offset != file->f_pos) {
			bool hash64;

			hash64 = test_bit(LL_SBI_64BIT_HASH, sbi->ll_flags);
			if ((api32 && offset == LL_DIR_END_OFF_32BIT) ||
			    (!api32 && offset == LL_DIR_END_OFF))
				fd->lfd_pos = MDS_DIR_END_OFF;
			else if (api32 && hash64)
				fd->lfd_pos = offset << 32;
			else
				fd->lfd_pos = offset;
			file->f_pos = offset;
			file->f_version = 0;
		}
		ret = offset;
	}

out:
	inode_unlock(inode);
	return ret;
}

static int ll_dir_open(struct inode *inode, struct file *file)
{
	return ll_file_open(inode, file);
}

static int ll_dir_release(struct inode *inode, struct file *file)
{
	return ll_file_release(inode, file);
}

/* notify error if partially read striped directory */
static int ll_dir_flush(struct file *file, fl_owner_t id)
{
	struct ll_file_data *lfd = file->private_data;
	int rc = lfd->fd_partial_readdir_rc;

	lfd->fd_partial_readdir_rc = 0;

	return rc;
}

const struct file_operations ll_dir_operations = {
	.llseek			= ll_dir_seek,
	.open			= ll_dir_open,
	.release		= ll_dir_release,
	.read			= generic_read_dir,
	.iterate_shared		= ll_readdir,
	.unlocked_ioctl		= ll_dir_ioctl,
	.fsync			= ll_fsync,
	.flush			= ll_dir_flush,
};

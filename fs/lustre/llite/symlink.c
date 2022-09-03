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
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/stat.h>
#define DEBUG_SUBSYSTEM S_LLITE

#include "llite_internal.h"

/* Must be called with lli_size_mutex locked */
/* iop->get_link is defined from kernel 4.5, whereas
 * IS_ENCRYPTED is brought by kernel 4.14.
 * So there is no need to handle encryption case otherwise.
 */
static int ll_readlink_internal(struct inode *inode,
				struct ptlrpc_request **request,
				char **symname, struct delayed_call *done)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	int rc, symlen = i_size_read(inode) + 1;
	struct mdt_body *body;
	struct md_op_data *op_data;

	*request = NULL;

	if (lli->lli_symlink_name) {
		int print_limit = min_t(int, PAGE_SIZE - 128, symlen);

		*symname = lli->lli_symlink_name;
		/*
		 * If the total CDEBUG() size is larger than a page, it
		 * will print a warning to the console, avoid this by
		 * printing just the last part of the symlink.
		 */
		CDEBUG(D_INODE, "using cached symlink %s%.*s, len = %d\n",
		       print_limit < symlen ? "..." : "", print_limit,
		       (*symname) + symlen - print_limit, symlen);
		return 0;
	}

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, symlen,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	op_data->op_valid = OBD_MD_LINKNAME;
	rc = md_getattr(sbi->ll_md_exp, op_data, request);
	ll_finish_md_op_data(op_data);
	if (rc) {
		if (rc != -ENOENT)
			CERROR("%s: inode " DFID ": rc = %d\n",
			       ll_i2sbi(inode)->ll_fsname,
			       PFID(ll_inode2fid(inode)), rc);
		goto failed;
	}

	body = req_capsule_server_get(&(*request)->rq_pill, &RMF_MDT_BODY);
	if ((body->mbo_valid & OBD_MD_LINKNAME) == 0) {
		CERROR("OBD_MD_LINKNAME not set on reply\n");
		rc = -EPROTO;
		goto failed;
	}

	LASSERT(symlen != 0);
	if (body->mbo_eadatasize != symlen) {
		CERROR("%s: inode " DFID ": symlink length %d not expected %d\n",
		       sbi->ll_fsname, PFID(ll_inode2fid(inode)),
		       body->mbo_eadatasize - 1, symlen - 1);
		rc = -EPROTO;
		goto failed;
	}

	*symname = req_capsule_server_get(&(*request)->rq_pill, &RMF_MDT_MD);
	if (!*symname ||
	    (!IS_ENCRYPTED(inode) &&
	     strnlen(*symname, symlen) != symlen - 1)) {
		/* not full/NULL terminated */
		CERROR("%s: inode " DFID ": symlink not NULL terminated string of length %d\n",
		       ll_i2sbi(inode)->ll_fsname,
		       PFID(ll_inode2fid(inode)), symlen - 1);
		rc = -EPROTO;
		goto failed;
	}

	if (IS_ENCRYPTED(inode)) {
		const char *target = fscrypt_get_symlink(inode, *symname,
							 symlen, done);
		if (IS_ERR(target))
			return PTR_ERR(target);
		symlen = strlen(target) + 1;
		*symname = (char *)target;

		/* Do not cache symlink targets encoded without the key,
		 * since those become outdated once the key is added.
		 */
		if (!fscrypt_has_encryption_key(inode))
			return 0;
	}

	lli->lli_symlink_name = kzalloc(symlen, GFP_NOFS);
	/* do not return an error if we cannot cache the symlink locally */
	if (lli->lli_symlink_name) {
		memcpy(lli->lli_symlink_name, *symname, symlen);
		*symname = lli->lli_symlink_name;
	}
	return 0;

failed:
	return rc;
}

static void ll_put_link(void *p)
{
	ptlrpc_req_finished(p);
}

static const char *ll_get_link(struct dentry *dentry,
			       struct inode *inode,
			       struct delayed_call *done)
{
	struct ptlrpc_request *request = NULL;
	int rc;
	char *symname = NULL;

	CDEBUG(D_VFSTRACE, "VFS Op:name=%pd, inode="DFID"(%p)\n",
	       dentry, PFID(ll_inode2fid(inode)), inode);
	if (!dentry)
		return ERR_PTR(-ECHILD);
	ll_inode_size_lock(inode);
	rc = ll_readlink_internal(inode, &request, &symname, done);
	ll_inode_size_unlock(inode);
	if (rc) {
		ptlrpc_req_finished(request);
		return ERR_PTR(rc);
	}

	/*
	 * symname may contain a pointer to the request message buffer,
	 * we delay request releasing then.
	 */
	set_delayed_call(done, ll_put_link, request);
	return symname;
}

/**
 * ll_getattr_link() - link-specific getattr to set the correct st_size
 *		       for encrypted symlinks
 *
 * Override st_size of encrypted symlinks to be the length of the decrypted
 * symlink target (or the no-key encoded symlink target, if the key is
 * unavailable) rather than the length of the encrypted symlink target. This is
 * necessary for st_size to match the symlink target that userspace actually
 * sees.  POSIX requires this, and some userspace programs depend on it.
 *
 * For non encrypted symlinks, this is a just calling ll_getattr().
 * For encrypted symlinks, this additionally requires reading the symlink target
 * from disk if needed, setting up the inode's encryption key if possible, and
 * then decrypting or encoding the symlink target.  This makes lstat() more
 * heavyweight than is normally the case.  However, decrypted symlink targets
 * will be cached in ->i_link, so usually the symlink won't have to be read and
 * decrypted again later if/when it is actually followed, readlink() is called,
 * or lstat() is called again.
 *
 * Return: 0 on success, -errno on failure
 */
static int ll_getattr_link(const struct path *path, struct kstat *stat,
			   u32 request_mask, unsigned int flags)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = d_inode(dentry);
	DEFINE_DELAYED_CALL(done);
	const char *link;
	int rc;

	rc = ll_getattr(path, stat, request_mask, flags);
	if (rc || !IS_ENCRYPTED(inode))
		return rc;

	/*
	 * To get the symlink target that userspace will see (whether it's the
	 * decrypted target or the no-key encoded target), we can just get it
	 * in the same way the VFS does during path resolution and readlink().
	 */
	link = READ_ONCE(inode->i_link);
	if (!link) {
		link = inode->i_op->get_link(dentry, inode, &done);
		if (IS_ERR(link))
			return PTR_ERR(link);
	}
	stat->size = strlen(link);
	do_delayed_call(&done);
	return 0;
}


const struct inode_operations ll_fast_symlink_inode_operations = {
	.setattr	= ll_setattr,
	.get_link	= ll_get_link,
	.getattr	= ll_getattr_link,
	.permission	= ll_inode_permission,
	.listxattr	= ll_listxattr,
};

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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/xattr.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_dlm.h>
#include <lustre_swab.h>

#include "llite_internal.h"

const struct xattr_handler *get_xattr_type(const char *name)
{
	int i;

	for (i = 0; ll_xattr_handlers[i]; i++) {
		const char *prefix = xattr_prefix(ll_xattr_handlers[i]);
		size_t prefix_len = strlen(prefix);

		if (!strncmp(prefix, name, prefix_len))
			return ll_xattr_handlers[i];
	}

	return NULL;
}

static int xattr_type_filter(struct ll_sb_info *sbi,
			     const struct xattr_handler *handler)
{
	/* No handler means XATTR_OTHER_T */
	if (!handler)
		return -EOPNOTSUPP;

	if ((handler->flags == XATTR_ACL_ACCESS_T ||
	     handler->flags == XATTR_ACL_DEFAULT_T) &&
	   !(sbi->ll_flags & LL_SBI_ACL))
		return -EOPNOTSUPP;

	if (handler->flags == XATTR_USER_T &&
	    !(sbi->ll_flags & LL_SBI_USER_XATTR))
		return -EOPNOTSUPP;

	if (handler->flags == XATTR_TRUSTED_T &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return 0;
}

static int ll_xattr_set_common(const struct xattr_handler *handler,
			       struct dentry *dentry, struct inode *inode,
			       const char *name, const void *value, size_t size,
			       int flags)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	const char *pv = value;
	char *fullname;
	ktime_t kstart = ktime_get();
	u64 valid;
	int rc;

	/* When setxattr() is called with a size of 0 the value is
	 * unconditionally replaced by "". When removexattr() is
	 * called we get a NULL value and XATTR_REPLACE for flags.
	 */
	if (!value && flags == XATTR_REPLACE)
		valid = OBD_MD_FLXATTRRM;
	else
		valid = OBD_MD_FLXATTR;

	rc = xattr_type_filter(sbi, handler);
	if (rc)
		return rc;

	if ((handler->flags == XATTR_ACL_ACCESS_T ||
	     handler->flags == XATTR_ACL_DEFAULT_T) &&
	    !inode_owner_or_capable(inode))
		return -EPERM;

	/* b10667: ignore lustre special xattr for now */
	if (!strcmp(name, "hsm") ||
	    ((handler->flags == XATTR_TRUSTED_T && !strcmp(name, "lov")) ||
	     (handler->flags == XATTR_LUSTRE_T && !strcmp(name, "lov"))))
		return 0;

	/*FIXME: enable IMA when the conditions are ready */
	if (handler->flags == XATTR_SECURITY_T &&
	    (!strcmp(name, "ima") || !strcmp(name, "evm")))
		return -EOPNOTSUPP;

	/*
	 * In user.* namespace, only regular files and directories can have
	 * extended attributes.
	 */
	if (handler->flags == XATTR_USER_T) {
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return -EPERM;
	}

	fullname = kasprintf(GFP_KERNEL, "%s%s", xattr_prefix(handler), name);
	if (!fullname)
		return -ENOMEM;

	rc = md_setxattr(sbi->ll_md_exp, ll_inode2fid(inode), valid, fullname,
			 pv, size, flags, ll_i2suppgid(inode), &req);
	kfree(fullname);
	if (rc) {
		if (rc == -EOPNOTSUPP && handler->flags == XATTR_USER_T) {
			LCONSOLE_INFO("Disabling user_xattr feature because it is not supported on the server\n");
			spin_lock(&sbi->ll_lock);
			sbi->ll_flags &= ~LL_SBI_USER_XATTR;
			spin_unlock(&sbi->ll_lock);
		}
		return rc;
	}

	ptlrpc_req_finished(req);

	ll_stats_ops_tally(ll_i2sbi(inode), valid == OBD_MD_FLXATTRRM ?
				LPROC_LL_REMOVEXATTR : LPROC_LL_SETXATTR,
			   ktime_us_delta(ktime_get(), kstart));

	return 0;
}

static int get_hsm_state(struct inode *inode, u32 *hus_states)
{
	struct md_op_data *op_data;
	struct hsm_user_state *hus;
	int rc;

	hus = kzalloc(sizeof(*hus), GFP_NOFS);
	if (!hus)
		return -ENOMEM;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, hus);
	if (!IS_ERR(op_data)) {
		rc = obd_iocontrol(LL_IOC_HSM_STATE_GET, ll_i2mdexp(inode),
				   sizeof(*op_data), op_data, NULL);
		if (!rc)
			*hus_states = hus->hus_states;
		else
			CDEBUG(D_VFSTRACE, "obd_iocontrol failed. rc = %d\n",
			       rc);

		ll_finish_md_op_data(op_data);
	} else {
		rc = PTR_ERR(op_data);
		CDEBUG(D_VFSTRACE, "Could not prepare the opdata. rc = %d\n",
		       rc);
	}
	kfree(hus);
	return rc;
}

static int ll_adjust_lum(struct inode *inode, struct lov_user_md *lump)
{
	struct lov_comp_md_v1 *comp_v1 = (struct lov_comp_md_v1 *)lump;
	struct lov_user_md *v1 = lump;
	bool need_clear_release = false;
	bool release_checked = false;
	bool is_composite = false;
	u16 entry_count = 1;
	int rc = 0;
	int i;

	if (!lump)
		return 0;

	if (lump->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		entry_count = comp_v1->lcm_entry_count;
		is_composite = true;
	}

	for (i = 0; i < entry_count; i++) {
		if (lump->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
			void *ptr = comp_v1;

			ptr += comp_v1->lcm_entries[i].lcme_offset;
			v1 = (struct lov_user_md *)ptr;
		}

		/* Attributes that are saved via getxattr will always have
		 * the stripe_offset as 0.  Instead, the MDS should be
		 * allowed to pick the starting OST index.   b=17846
		 */
		if (!is_composite && v1->lmm_stripe_offset == 0)
			v1->lmm_stripe_offset = -1;

		/* Avoid anyone directly setting the RELEASED flag. */
		if (v1->lmm_pattern & LOV_PATTERN_F_RELEASED) {
			if (!release_checked) {
				u32 state = HS_NONE;

				rc = get_hsm_state(inode, &state);
				if (rc)
					return rc;

				if (!(state & HS_ARCHIVED))
					need_clear_release = true;
				release_checked = true;
			}
			if (need_clear_release)
				v1->lmm_pattern ^= LOV_PATTERN_F_RELEASED;
		}
	}

	return rc;
}

static int ll_setstripe_ea(struct dentry *dentry, struct lov_user_md *lump,
			   size_t size)
{
	struct inode *inode = d_inode(dentry);
	int rc = 0;

	/*
	 * It is possible to set an xattr to a "" value of zero size.
	 * For this case we are going to treat it as a removal.
	 */
	if (!size && lump)
		lump = NULL;

	if (size && size < sizeof(*lump)) {
		/* ll_adjust_lum() or ll_lov_user_md_size() might access
		 * before size - just give up now.
		 */
		return -ERANGE;
	}

	rc = ll_adjust_lum(inode, lump);
	if (rc)
		return rc;

	if (lump && S_ISREG(inode->i_mode)) {
		u64 it_flags = FMODE_WRITE;
		ssize_t lum_size;

		lum_size = ll_lov_user_md_size(lump);
		if (lum_size < 0 || size < lum_size)
			return -ERANGE;

		rc = ll_lov_setstripe_ea_info(inode, dentry, it_flags, lump,
					      lum_size);
		/**
		 * b=10667: ignore -EEXIST.
		 * Silently eat error on setting trusted.lov/lustre.lov
		 * attribute for platforms that added the default option
		 * to copy all attributes in 'cp' command. Both rsync and
		 * tar --xattrs also will try to set LOVEA for existing
		 * files.
		 */
		if (rc == -EEXIST)
			rc = 0;
	} else if (S_ISDIR(inode->i_mode)) {
		if (size != 0 && size < sizeof(struct lov_user_md))
			return -EINVAL;

		rc = ll_dir_setstripe(inode, lump, 0);
	}

	return rc;
}

static int ll_xattr_set(const struct xattr_handler *handler,
			struct dentry *dentry, struct inode *inode,
			const char *name, const void *value, size_t size,
			int flags)
{
	ktime_t kstart = ktime_get();
	int op_type = flags == XATTR_REPLACE ? LPROC_LL_REMOVEXATTR :
					       LPROC_LL_SETXATTR;
	int rc;

	LASSERT(inode);
	LASSERT(name);

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p), xattr %s\n",
	       PFID(ll_inode2fid(inode)), inode, name);

	/* lustre/trusted.lov.xxx would be passed through xattr API */
	if (!strcmp(name, "lov")) {
		rc = ll_setstripe_ea(dentry, (struct lov_user_md *)value,
				       size);
		ll_stats_ops_tally(ll_i2sbi(inode), op_type,
				   ktime_us_delta(ktime_get(), kstart));
		return rc;
	} else if (!strcmp(name, "lma") || !strcmp(name, "link")) {
		ll_stats_ops_tally(ll_i2sbi(inode), op_type,
				   ktime_us_delta(ktime_get(), kstart));
		return 0;
	}

	if (strncmp(name, "lov.", 4) == 0 &&
	    (__swab32(((struct lov_user_md *)value)->lmm_magic) &
	    le32_to_cpu(LOV_MAGIC_MASK)) == le32_to_cpu(LOV_MAGIC_MAGIC))
		lustre_swab_lov_user_md((struct lov_user_md *)value, 0);

	return ll_xattr_set_common(handler, dentry, inode, name, value, size,
				   flags);
}

int ll_xattr_list(struct inode *inode, const char *name, int type, void *buffer,
		  size_t size, u64 valid)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	void *xdata;
	int rc;

	if (sbi->ll_xattr_cache_enabled && type != XATTR_ACL_ACCESS_T &&
	    (type != XATTR_SECURITY_T || strcmp(name, "security.selinux"))) {
		rc = ll_xattr_cache_get(inode, name, buffer, size, valid);
		if (rc == -EAGAIN)
			goto getxattr_nocache;
		if (rc < 0)
			goto out_xattr;

		/* Add "system.posix_acl_access" to the list */
		if (lli->lli_posix_acl && valid & OBD_MD_FLXATTRLS) {
			if (size == 0) {
				rc += sizeof(XATTR_NAME_ACL_ACCESS);
			} else if (size - rc >= sizeof(XATTR_NAME_ACL_ACCESS)) {
				memcpy(buffer + rc, XATTR_NAME_ACL_ACCESS,
				       sizeof(XATTR_NAME_ACL_ACCESS));
				rc += sizeof(XATTR_NAME_ACL_ACCESS);
			} else {
				rc = -ERANGE;
				goto out_xattr;
			}
		}
	} else {
getxattr_nocache:
		rc = md_getxattr(sbi->ll_md_exp, ll_inode2fid(inode), valid,
				 name, size, &req);
		if (rc < 0)
			goto out_xattr;

		/* only detect the xattr size */
		if (size == 0)
			goto out;

		if (size < rc) {
			rc = -ERANGE;
			goto out;
		}

		/* do not need swab xattr data */
		xdata = req_capsule_server_sized_get(&req->rq_pill, &RMF_EADATA,
						     rc);
		if (!xdata) {
			rc = -EPROTO;
			goto out;
		}

		memcpy(buffer, xdata, rc);
	}

out_xattr:
	if (rc == -EOPNOTSUPP && type == XATTR_USER_T) {
		LCONSOLE_INFO(
			"%s: disabling user_xattr feature because it is not supported on the server: rc = %d\n",
			sbi->ll_fsname, rc);
		spin_lock(&sbi->ll_lock);
		sbi->ll_flags &= ~LL_SBI_USER_XATTR;
		spin_unlock(&sbi->ll_lock);
	}
out:
	ptlrpc_req_finished(req);
	return rc;
}

static int ll_xattr_get_common(const struct xattr_handler *handler,
			       struct dentry *dentry, struct inode *inode,
			       const char *name, void *buffer, size_t size)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	ktime_t kstart = ktime_get();
	char *fullname;
	int rc;

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);

	rc = xattr_type_filter(sbi, handler);
	if (rc)
		return rc;

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	/* posix acl is under protection of LOOKUP lock. when calling to this,
	 * we just have path resolution to the target inode, so we have great
	 * chance that cached ACL is uptodate.
	 */
	if (handler->flags == XATTR_ACL_ACCESS_T) {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct posix_acl *acl;

		spin_lock(&lli->lli_lock);
		acl = posix_acl_dup(lli->lli_posix_acl);
		spin_unlock(&lli->lli_lock);

		if (!acl)
			return -ENODATA;

		rc = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
		posix_acl_release(acl);
		return rc;
	}
	if (handler->flags == XATTR_ACL_DEFAULT_T && !S_ISDIR(inode->i_mode))
		return -ENODATA;
#endif
	fullname = kasprintf(GFP_KERNEL, "%s%s", xattr_prefix(handler), name);
	if (!fullname)
		return -ENOMEM;

	rc = ll_xattr_list(inode, fullname, handler->flags, buffer, size,
			   OBD_MD_FLXATTR);
	kfree(fullname);
	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_GETXATTR,
			   ktime_us_delta(ktime_get(), kstart));

	return rc;
}

static ssize_t ll_getxattr_lov(struct inode *inode, void *buf, size_t buf_size)
{
	ssize_t rc;

	if (S_ISREG(inode->i_mode)) {
		struct cl_object *obj = ll_i2info(inode)->lli_clob;
		struct cl_layout cl = {
			.cl_buf.lb_buf = buf,
			.cl_buf.lb_len = buf_size,
		};
		struct lu_env *env;
		u16 refcheck;

		if (!obj)
			return -ENODATA;

		env = cl_env_get(&refcheck);
		if (IS_ERR(env))
			return PTR_ERR(env);

		rc = cl_object_layout_get(env, obj, &cl);
		if (rc < 0)
			goto out_env;

		if (!cl.cl_size) {
			rc = -ENODATA;
			goto out_env;
		}

		rc = cl.cl_size;

		if (!buf_size)
			goto out_env;

		LASSERT(buf && rc <= buf_size);

		/*
		 * Do not return layout gen for getxattr() since
		 * otherwise it would confuse tar --xattr by
		 * recognizing layout gen as stripe offset when the
		 * file is restored. See LU-2809.
		 */
		if ((((struct lov_mds_md *)buf)->lmm_magic &
		    __swab32(LOV_MAGIC_MAGIC)) == __swab32(LOV_MAGIC_MAGIC))
			lustre_swab_lov_user_md((struct lov_user_md *)buf,
						cl.cl_size);

		switch (((struct lov_mds_md *)buf)->lmm_magic) {
		case LOV_MAGIC_V1:
		case LOV_MAGIC_V3:
		case LOV_MAGIC_SPECIFIC:
			((struct lov_mds_md *)buf)->lmm_layout_gen = 0;
			break;
		case LOV_MAGIC_COMP_V1:
		case LOV_MAGIC_FOREIGN:
			goto out_env;
		default:
			CERROR("Invalid LOV magic %08x\n",
			       ((struct lov_mds_md *)buf)->lmm_magic);
			rc = -EINVAL;
			goto out_env;
		}

out_env:
		cl_env_put(env, &refcheck);

		return rc;
	} else if (S_ISDIR(inode->i_mode)) {
		struct ptlrpc_request *req = NULL;
		struct ptlrpc_request *root_req = NULL;
		struct lov_mds_md *lmm = NULL;
		int lmm_size = 0;

		rc = ll_dir_getstripe_default(inode, (void **)&lmm, &lmm_size,
					      &req, &root_req, 0);
		if (rc < 0)
			goto out_req;

		if (!buf_size) {
			rc = lmm_size;
			goto out_req;
		}

		if (buf_size < lmm_size) {
			rc = -ERANGE;
			goto out_req;
		}

		memcpy(buf, lmm, lmm_size);
		rc = lmm_size;
out_req:
		if (req)
			ptlrpc_req_finished(req);
		if (root_req)
			ptlrpc_req_finished(root_req);

		return rc;
	} else {
		return -ENODATA;
	}
}

static int ll_xattr_get(const struct xattr_handler *handler,
			struct dentry *dentry, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	LASSERT(inode);
	LASSERT(name);

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p), xattr %s\n",
	       PFID(ll_inode2fid(inode)), inode, name);

	if (!strcmp(name, "lov")) {
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_GETXATTR, 1);

		return ll_getxattr_lov(inode, buffer, size);
	}

	return ll_xattr_get_common(handler, dentry, inode, name, buffer, size);
}

ssize_t ll_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = d_inode(dentry);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	ktime_t kstart = ktime_get();
	char *xattr_name;
	ssize_t rc, rc2;
	size_t len, rem;

	LASSERT(inode);

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);

	rc = ll_xattr_list(inode, NULL, XATTR_OTHER_T, buffer, size,
			   OBD_MD_FLXATTRLS);
	if (rc < 0)
		return rc;

	/*
	 * If we're being called to get the size of the xattr list
	 * (size == 0) then just assume that a lustre.lov xattr
	 * exists.
	 */
	if (!size)
		goto out;

	xattr_name = buffer;
	rem = rc;

	while (rem > 0) {
		len = strnlen(xattr_name, rem - 1) + 1;
		rem -= len;
		if (!xattr_type_filter(sbi, get_xattr_type(xattr_name))) {
			/* Skip OK xattr type, leave it in buffer. */
			xattr_name += len;
			continue;
		}

		/*
		 * Move up remaining xattrs in buffer
		 * removing the xattr that is not OK.
		 */
		memmove(xattr_name, xattr_name + len, rem);
		rc -= len;
	}

	rc2 = ll_getxattr_lov(inode, NULL, 0);
	if (rc2 == -ENODATA)
		return rc;

	if (rc2 < 0)
		return rc2;

	if (size < rc + sizeof(XATTR_LUSTRE_LOV))
		return -ERANGE;

	memcpy(buffer + rc, XATTR_LUSTRE_LOV, sizeof(XATTR_LUSTRE_LOV));

out:
	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LISTXATTR,
			   ktime_us_delta(ktime_get(), kstart));

	return rc + sizeof(XATTR_LUSTRE_LOV);
}

static const struct xattr_handler ll_user_xattr_handler = {
	.prefix		= XATTR_USER_PREFIX,
	.flags		= XATTR_USER_T,
	.get		= ll_xattr_get_common,
	.set		= ll_xattr_set_common,
};

static const struct xattr_handler ll_trusted_xattr_handler = {
	.prefix		= XATTR_TRUSTED_PREFIX,
	.flags		= XATTR_TRUSTED_T,
	.get		= ll_xattr_get,
	.set		= ll_xattr_set,
};

static const struct xattr_handler ll_security_xattr_handler = {
	.prefix		= XATTR_SECURITY_PREFIX,
	.flags		= XATTR_SECURITY_T,
	.get		= ll_xattr_get_common,
	.set		= ll_xattr_set_common,
};

static const struct xattr_handler ll_acl_access_xattr_handler = {
	.name		= XATTR_NAME_POSIX_ACL_ACCESS,
	.flags		= XATTR_ACL_ACCESS_T,
	.get		= ll_xattr_get_common,
	.set		= ll_xattr_set_common,
};

static const struct xattr_handler ll_acl_default_xattr_handler = {
	.name		= XATTR_NAME_POSIX_ACL_DEFAULT,
	.flags		= XATTR_ACL_DEFAULT_T,
	.get		= ll_xattr_get_common,
	.set		= ll_xattr_set_common,
};

static const struct xattr_handler ll_lustre_xattr_handler = {
	.prefix		= XATTR_LUSTRE_PREFIX,
	.flags		= XATTR_LUSTRE_T,
	.get		= ll_xattr_get,
	.set		= ll_xattr_set,
};

const struct xattr_handler *ll_xattr_handlers[] = {
	&ll_user_xattr_handler,
	&ll_trusted_xattr_handler,
	&ll_security_xattr_handler,
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	&ll_acl_access_xattr_handler,
	&ll_acl_default_xattr_handler,
#endif
	&ll_lustre_xattr_handler,
	NULL,
};

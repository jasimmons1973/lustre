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
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LLITE

#define D_MOUNT (D_SUPER | D_CONFIG/*|D_WARNING */)

#include <linux/module.h>
#include <linux/types.h>
#include <lustre_ha.h>
#include <lustre_dlm.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <lprocfs_status.h>
#include "llite_internal.h"
#include "vvp_internal.h"

static struct kmem_cache *ll_inode_cachep;

static struct inode *ll_alloc_inode(struct super_block *sb)
{
	struct ll_inode_info *lli;

	lli = kmem_cache_zalloc(ll_inode_cachep, GFP_NOFS);
	if (!lli)
		return NULL;

	inode_init_once(&lli->lli_vfs_inode);
	lli->lli_open_thrsh_count = UINT_MAX;

	return &lli->lli_vfs_inode;
}

static void ll_inode_destroy_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct ll_inode_info *ptr = ll_i2info(inode);

	fscrypt_free_inode(inode);
	kmem_cache_free(ll_inode_cachep, ptr);
}

static void ll_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, ll_inode_destroy_callback);
}

static int ll_drop_inode(struct inode *inode)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	int drop;

	if (!sbi->ll_inode_cache_enabled)
		return 1;

	drop = generic_drop_inode(inode);
	if (!drop)
		drop = fscrypt_drop_inode(inode);

	return drop;
}

/* exported operations */
const struct super_operations lustre_super_operations = {
	.alloc_inode		= ll_alloc_inode,
	.destroy_inode		= ll_destroy_inode,
	.drop_inode		= ll_drop_inode,
	.evict_inode		= ll_delete_inode,
	.put_super		= ll_put_super,
	.statfs			= ll_statfs,
	.umount_begin		= ll_umount_begin,
	.remount_fs		= ll_remount_fs,
	.show_options		= ll_show_options,
};

/**
 * This is the entry point for the mount call into Lustre.
 * This is called when a server or client is mounted,
 * and this is where we start setting things up.
 *
 * @lmd2data	Mount options (e.g. -o flock,abort_recov)
 */
static int lustre_fill_super(struct super_block *sb, void *lmd2_data,
			     int silent)
{
	struct lustre_mount_data *lmd;
	struct lustre_sb_info *lsi;
	int rc;

	CDEBUG(D_MOUNT | D_VFSTRACE, "VFS Op: sb %p\n", sb);

	lsi = lustre_init_lsi(sb);
	if (!lsi)
		return -ENOMEM;
	lmd = lsi->lsi_lmd;

	/*
	 * Disable lockdep during mount, because mount locking patterns are
	 * `special'.
	 */
	lockdep_off();

	/*
	 * LU-639: the obd cleanup of last mount may not finish yet, wait here.
	 */
	obd_zombie_barrier();

	/* Figure out the lmd from the mount options */
	if (lmd_parse(lmd2_data, lmd)) {
		rc = -EINVAL;
		goto out_put_lsi;
	}

	if (!lmd_is_client(lmd)) {
		rc = -ENODEV;
		CERROR("%s: This is client-side-only module, cannot handle server mount: rc = %d\n",
		       lmd->lmd_profile, rc);
		goto out_put_lsi;
	}

	CDEBUG(D_MOUNT, "Mounting client %s\n", lmd->lmd_profile);
	rc = ptlrpc_inc_ref();
	if (rc)
		goto out_put_lsi;

	rc = lustre_start_mgc(sb);
	if (rc) {
		/* This will put_lsi and ptlrpc_dec_ref */
		ll_common_put_super(sb);
		goto out;
	}
	/* Connect and start */
	rc = ll_fill_super(sb);
	/* ll_file_super will call lustre_common_put_super on failure,
	 * which takes care of the module reference.
	 *
	 * If error happens in fill_super() call, @lsi will be killed there.
	 * This is why we do not put it here.
	 */
	goto out;
out_put_lsi:
	lustre_put_lsi(sb);
out:
	if (rc) {
		CERROR("llite: Unable to mount %s: rc = %d\n",
		       s2lsi(sb) ? lmd->lmd_dev : "<unknown>", rc);
	} else {
		CDEBUG(D_SUPER, "%s: Mount complete\n",
		       lmd->lmd_dev);
	}
	lockdep_on();
	return rc;
}

/***************** FS registration ******************/
static struct dentry *lustre_mount(struct file_system_type *fs_type, int flags,
				   const char *devname, void *data)
{
	return mount_nodev(fs_type, flags, data, lustre_fill_super);
}

static void lustre_kill_super(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);

	if (lsi)
		ll_kill_super(sb);

	kill_anon_super(sb);
}

/** Register the "lustre" fs type
 */
static struct file_system_type lustre_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "lustre",
	.mount		= lustre_mount,
	.kill_sb	= lustre_kill_super,
	.fs_flags	= FS_RENAME_DOES_D_MOVE,
};
MODULE_ALIAS_FS("lustre");

static int __init lustre_init(void)
{
	int rc;

	BUILD_BUG_ON(sizeof(LUSTRE_VOLATILE_HDR) !=
		     LUSTRE_VOLATILE_HDR_LEN + 1);

	rc = libcfs_setup();
	if (rc)
		return rc;

	/* print an address of _any_ initialized kernel symbol from this
	 * module, to allow debugging with gdb that doesn't support data
	 * symbols from modules.
	 */
	CDEBUG(D_INFO, "Lustre client module (%p).\n",
	       &lustre_super_operations);

	rc = -ENOMEM;
	ll_inode_cachep = kmem_cache_create("lustre_inode_cache",
					    sizeof(struct ll_inode_info), 0,
					    SLAB_HWCACHE_ALIGN |
					    SLAB_RECLAIM_ACCOUNT |
					    SLAB_ACCOUNT |
					    SLAB_MEM_SPREAD |
					    SLAB_ACCOUNT,
					    NULL);
	if (!ll_inode_cachep)
		goto out_cache;

	ll_file_data_slab = kmem_cache_create("ll_file_data",
					      sizeof(struct ll_file_data), 0,
					      SLAB_HWCACHE_ALIGN, NULL);
	if (!ll_file_data_slab)
		goto out_cache;

	pcc_inode_slab = kmem_cache_create("ll_pcc_inode",
					   sizeof(struct pcc_inode), 0,
					   SLAB_HWCACHE_ALIGN, NULL);
	if (!pcc_inode_slab) {
		rc = -ENOMEM;
		goto out_cache;
	}

	rc = llite_tunables_register();
	if (rc)
		goto out_cache;

	rc = vvp_global_init();
	if (rc != 0)
		goto out_tunables;

	cl_inode_fini_env = cl_env_alloc(&cl_inode_fini_refcheck,
					 LCT_REMEMBER | LCT_NOREF);
	if (IS_ERR(cl_inode_fini_env)) {
		rc = PTR_ERR(cl_inode_fini_env);
		goto out_vvp;
	}

	cl_inode_fini_env->le_ctx.lc_cookie = 0x4;

	rc = ll_xattr_init();
	if (rc != 0)
		goto out_inode_fini_env;

	rc = register_filesystem(&lustre_fs_type);
	if (rc)
		goto out_xattr;

	return 0;

out_xattr:
	ll_xattr_fini();
out_inode_fini_env:
	cl_env_put(cl_inode_fini_env, &cl_inode_fini_refcheck);
out_vvp:
	vvp_global_fini();
out_tunables:
	llite_tunables_unregister();
out_cache:
	kmem_cache_destroy(ll_inode_cachep);
	kmem_cache_destroy(ll_file_data_slab);
	kmem_cache_destroy(pcc_inode_slab);
	return rc;
}

static void __exit lustre_exit(void)
{
	unregister_filesystem(&lustre_fs_type);

	llite_tunables_unregister();

	ll_xattr_fini();
	cl_env_put(cl_inode_fini_env, &cl_inode_fini_refcheck);
	vvp_global_fini();

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(ll_inode_cachep);
	kmem_cache_destroy(ll_file_data_slab);
	kmem_cache_destroy(pcc_inode_slab);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Client File System");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(lustre_init);
module_exit(lustre_exit);

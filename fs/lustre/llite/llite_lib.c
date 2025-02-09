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
 *
 * lustre/llite/llite_lib.c
 *
 * Lustre Light Super operations
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/cpu.h>

#include <linux/delay.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/statfs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/uuid.h>

#include <linux/libcfs/libcfs_cpu.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_ioctl_old.h>
#include <lustre_ha.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>
#include <lustre_disk.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_log.h>
#include <cl_object.h>
#include <obd_cksum.h>
#include "llite_internal.h"

struct kmem_cache *ll_file_data_slab;

#ifndef log2
#define log2(n) ffz(~(n))
#endif

/**
 * If there is only one number of core visible to Lustre,
 * async readahead will be disabled, to avoid massive over
 * subscription, we use 1/2 of active cores as default max
 * async readahead requests.
 */
static inline unsigned int ll_get_ra_async_max_active(void)
{
	return cfs_cpt_weight(cfs_cpt_tab, CFS_CPT_ANY) >> 1;
}

static struct ll_sb_info *ll_init_sbi(struct lustre_sb_info *lsi)
{
	struct ll_sb_info *sbi = NULL;
	unsigned long pages;
	unsigned long lru_page_max;
	struct sysinfo si;
	int rc;

	sbi = kzalloc(sizeof(*sbi), GFP_NOFS);
	if (!sbi)
		return ERR_PTR(-ENOMEM);

	rc = pcc_super_init(&sbi->ll_pcc_super);
	if (rc < 0)
		goto out_sbi;

	spin_lock_init(&sbi->ll_lock);
	mutex_init(&sbi->ll_lco.lco_lock);
	spin_lock_init(&sbi->ll_pp_extent_lock);
	spin_lock_init(&sbi->ll_process_lock);
	sbi->lsi = lsi;
	sbi->ll_rw_stats_on = 0;
	sbi->ll_statfs_max_age = OBD_STATFS_CACHE_SECONDS;

	si_meminfo(&si);
	pages = si.totalram - si.totalhigh;
	lru_page_max = pages / 2;

	sbi->ll_ra_info.ra_async_max_active = ll_get_ra_async_max_active();
	sbi->ll_ra_info.ll_readahead_wq =
		cfs_cpt_bind_workqueue("ll-readahead-wq", cfs_cpt_tab,
				       0, CFS_CPT_ANY,
				       sbi->ll_ra_info.ra_async_max_active);
	if (IS_ERR(sbi->ll_ra_info.ll_readahead_wq)) {
		rc = PTR_ERR(sbi->ll_ra_info.ll_readahead_wq);
		goto out_pcc;
	}

	sbi->ll_cache = cl_cache_init(lru_page_max);
	if (!sbi->ll_cache) {
		rc = -ENOMEM;
		goto out_destroy_ra;
	}

	/* initialize foreign symlink prefix path */
	sbi->ll_foreign_symlink_prefix = kasprintf(GFP_KERNEL, "/mnt/");
	if (!sbi->ll_foreign_symlink_prefix) {
		rc = -ENOMEM;
		goto out_destroy_ra;
	}
	sbi->ll_foreign_symlink_prefix_size = sizeof("/mnt/");

	/* initialize foreign symlink upcall path, none by default */
	sbi->ll_foreign_symlink_upcall = kasprintf(GFP_KERNEL, "none");
	if (!sbi->ll_foreign_symlink_upcall) {
		rc = -ENOMEM;
		goto out_destroy_ra;
	}

	sbi->ll_foreign_symlink_upcall_items = NULL;
	sbi->ll_foreign_symlink_upcall_nb_items = 0;
	init_rwsem(&sbi->ll_foreign_symlink_sem);
	/* foreign symlink support (LL_SBI_FOREIGN_SYMLINK in ll_flags)
	 * not enabled by default
	 */

	sbi->ll_secctx_name = NULL;
	sbi->ll_secctx_name_size = 0;

	sbi->ll_ra_info.ra_max_pages =
		min(pages / 32, SBI_DEFAULT_READ_AHEAD_MAX);
	sbi->ll_ra_info.ra_max_pages_per_file =
		min(sbi->ll_ra_info.ra_max_pages / 4,
		    SBI_DEFAULT_READ_AHEAD_PER_FILE_MAX);
	sbi->ll_ra_info.ra_async_pages_per_file_threshold =
				sbi->ll_ra_info.ra_max_pages_per_file;
	sbi->ll_ra_info.ra_range_pages = SBI_DEFAULT_RA_RANGE_PAGES;
	sbi->ll_ra_info.ra_max_read_ahead_whole_pages = -1;
	atomic_set(&sbi->ll_ra_info.ra_async_inflight, 0);

	set_bit(LL_SBI_VERBOSE, sbi->ll_flags);
	set_bit(LL_SBI_CHECKSUM, sbi->ll_flags);
	set_bit(LL_SBI_FLOCK, sbi->ll_flags);
	set_bit(LL_SBI_LRU_RESIZE, sbi->ll_flags);
	set_bit(LL_SBI_LAZYSTATFS, sbi->ll_flags);

	/* metadata statahead is enabled by default */
	sbi->ll_sa_running_max = LL_SA_RUNNING_DEF;
	sbi->ll_sa_batch_max = LL_SA_BATCH_DEF;
	sbi->ll_sa_max = LL_SA_RPC_DEF;
	atomic_set(&sbi->ll_sa_total, 0);
	atomic_set(&sbi->ll_sa_wrong, 0);
	atomic_set(&sbi->ll_sa_running, 0);
	atomic_set(&sbi->ll_agl_total, 0);
	atomic_set(&sbi->ll_sa_hit_total, 0);
	atomic_set(&sbi->ll_sa_miss_total, 0);
	set_bit(LL_SBI_AGL_ENABLED, sbi->ll_flags);
	set_bit(LL_SBI_FAST_READ, sbi->ll_flags);
	set_bit(LL_SBI_TINY_WRITE, sbi->ll_flags);
	set_bit(LL_SBI_PARALLEL_DIO, sbi->ll_flags);
	ll_sbi_set_encrypt(sbi, true);
	ll_sbi_set_name_encrypt(sbi, true);

	/* root squash */
	sbi->ll_squash.rsi_uid = 0;
	sbi->ll_squash.rsi_gid = 0;
	INIT_LIST_HEAD(&sbi->ll_squash.rsi_nosquash_nids);
	spin_lock_init(&sbi->ll_squash.rsi_lock);

	/* Per-filesystem file heat */
	sbi->ll_heat_decay_weight = SBI_DEFAULT_HEAT_DECAY_WEIGHT;
	sbi->ll_heat_period_second = SBI_DEFAULT_HEAT_PERIOD_SECOND;

	/* Per-fs open heat level before requesting open lock */
	sbi->ll_oc_thrsh_count = SBI_DEFAULT_OPENCACHE_THRESHOLD_COUNT;
	sbi->ll_oc_max_ms = SBI_DEFAULT_OPENCACHE_THRESHOLD_MAX_MS;
	sbi->ll_oc_thrsh_ms = SBI_DEFAULT_OPENCACHE_THRESHOLD_MS;
	return sbi;
out_destroy_ra:
	kfree(sbi->ll_foreign_symlink_upcall);
	kfree(sbi->ll_foreign_symlink_prefix);
	if (sbi->ll_cache) {
		cl_cache_decref(sbi->ll_cache);
		sbi->ll_cache = NULL;
	}
	destroy_workqueue(sbi->ll_ra_info.ll_readahead_wq);
out_pcc:
	pcc_super_fini(&sbi->ll_pcc_super);
out_sbi:
	kfree(sbi);
	return ERR_PTR(rc);
}

static void ll_free_sbi(struct super_block *sb)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	if (!list_empty(&sbi->ll_squash.rsi_nosquash_nids))
		cfs_free_nidlist(&sbi->ll_squash.rsi_nosquash_nids);
	if (sbi->ll_ra_info.ll_readahead_wq)
		destroy_workqueue(sbi->ll_ra_info.ll_readahead_wq);
	if (sbi->ll_cache) {
		cl_cache_decref(sbi->ll_cache);
		sbi->ll_cache = NULL;
	}
	kfree(sbi->ll_foreign_symlink_prefix);
	sbi->ll_foreign_symlink_prefix = NULL;
	kfree(sbi->ll_foreign_symlink_upcall);
	sbi->ll_foreign_symlink_upcall = NULL;
	if (sbi->ll_foreign_symlink_upcall_items) {
		int i;
		int nb_items = sbi->ll_foreign_symlink_upcall_nb_items;
		struct ll_foreign_symlink_upcall_item *items;

		items = sbi->ll_foreign_symlink_upcall_items;
		for (i = 0 ; i < nb_items; i++)
			if (items[i].type == STRING_TYPE)
				kfree(items[i].string);

		kvfree(items);
		sbi->ll_foreign_symlink_upcall_items = NULL;
	}
	ll_secctx_name_free(sbi);

	ll_free_rw_stats_info(sbi);
	pcc_super_fini(&sbi->ll_pcc_super);
	kfree(sbi);
}

static int client_common_fill_super(struct super_block *sb, char *md, char *dt)
{
	struct inode *root = NULL;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct obd_statfs *osfs = NULL;
	struct ptlrpc_request *request = NULL;
	struct obd_connect_data *data = NULL;
	struct obd_uuid *uuid;
	struct md_op_data *op_data;
	struct lustre_md lmd;
	u64 valid;
	int size, err, checksum;
	bool api32;
	void *encctx;
	int encctxlen;

	sbi->ll_md_obd  = class_name2obd(md);
	if (!sbi->ll_md_obd) {
		CERROR("MD %s: not setup or attached\n", md);
		return -EINVAL;
	}

	data = kzalloc(sizeof(*data), GFP_NOFS);
	if (!data)
		return -ENOMEM;

	osfs = kzalloc(sizeof(*osfs), GFP_NOFS);
	if (!osfs) {
		kfree(data);
		return -ENOMEM;
	}

	/*
	 * pass client page size via ocd_grant_blkbits, the server should report
	 * back its backend blocksize for grant calculation purpose
	 */
	data->ocd_grant_blkbits = PAGE_SHIFT;

	/* indicate MDT features supported by this client */
	data->ocd_connect_flags = OBD_CONNECT_IBITS	| OBD_CONNECT_NODEVOH  |
				  OBD_CONNECT_ATTRFID	| OBD_CONNECT_GRANT    |
				  OBD_CONNECT_VERSION	| OBD_CONNECT_BRW_SIZE |
				  OBD_CONNECT_SRVLOCK	|
				  OBD_CONNECT_CANCELSET | OBD_CONNECT_FID      |
				  OBD_CONNECT_AT	| OBD_CONNECT_LOV_V3   |
				  OBD_CONNECT_VBR	| OBD_CONNECT_FULL20   |
				  OBD_CONNECT_64BITHASH |
				  OBD_CONNECT_EINPROGRESS |
				  OBD_CONNECT_JOBSTATS	| OBD_CONNECT_LVB_TYPE |
				  OBD_CONNECT_LAYOUTLOCK  |
				  OBD_CONNECT_PINGLESS	|
				  OBD_CONNECT_MAX_EASIZE  |
				  OBD_CONNECT_FLOCK_DEAD  |
				  OBD_CONNECT_DISP_STRIPE | OBD_CONNECT_LFSCK |
				  OBD_CONNECT_OPEN_BY_FID |
				  OBD_CONNECT_DIR_STRIPE |
				  OBD_CONNECT_BULK_MBITS | OBD_CONNECT_CKSUM |
				  OBD_CONNECT_SUBTREE	 |
				  OBD_CONNECT_MULTIMODRPCS |
				  OBD_CONNECT_GRANT_PARAM |
				  OBD_CONNECT_GRANT_SHRINK |
				  OBD_CONNECT_SHORTIO | OBD_CONNECT_FLAGS2;

	data->ocd_connect_flags2 = OBD_CONNECT2_DIR_MIGRATE |
				   OBD_CONNECT2_SUM_STATFS |
				   OBD_CONNECT2_OVERSTRIPING |
				   OBD_CONNECT2_FLR |
				   OBD_CONNECT2_LOCK_CONVERT |
				   OBD_CONNECT2_ARCHIVE_ID_ARRAY |
				   OBD_CONNECT2_INC_XID |
				   OBD_CONNECT2_LSOM |
				   OBD_CONNECT2_ASYNC_DISCARD |
				   OBD_CONNECT2_PCC |
				   OBD_CONNECT2_CRUSH | OBD_CONNECT2_LSEEK |
				   OBD_CONNECT2_GETATTR_PFID |
				   OBD_CONNECT2_DOM_LVB |
				   OBD_CONNECT2_REP_MBITS |
				   OBD_CONNECT2_ATOMIC_OPEN_LOCK |
				   OBD_CONNECT2_BATCH_RPC |
				   OBD_CONNECT2_DMV_IMP_INHERIT;

	if (test_bit(LL_SBI_LRU_RESIZE, sbi->ll_flags))
		data->ocd_connect_flags |= OBD_CONNECT_LRU_RESIZE;
	data->ocd_connect_flags |= OBD_CONNECT_ACL_FLAGS;

	data->ocd_cksum_types = obd_cksum_types_supported_client();

	if (CFS_FAIL_CHECK(OBD_FAIL_MDC_LIGHTWEIGHT))
		/* flag mdc connection as lightweight, only used for test
		 * purpose, use with care
		 */
		data->ocd_connect_flags |= OBD_CONNECT_LIGHTWEIGHT;

	data->ocd_ibits_known = MDS_INODELOCK_FULL;
	data->ocd_version = LUSTRE_VERSION_CODE;

	if (sb_rdonly(sb))
		data->ocd_connect_flags |= OBD_CONNECT_RDONLY;
	if (test_bit(LL_SBI_USER_XATTR, sbi->ll_flags))
		data->ocd_connect_flags |= OBD_CONNECT_XATTR;

	/* Setting this indicates we correctly support S_NOSEC (See kernel
	 * commit 9e1f1de02c2275d7172e18dc4e7c2065777611bf)
	 */
	sb->s_flags |= SB_NOSEC;

	sbi->ll_fop = ll_select_file_operations(sbi);

	/* always ping even if server suppress_pings */
	if (test_bit(LL_SBI_ALWAYS_PING, sbi->ll_flags))
		data->ocd_connect_flags &= ~OBD_CONNECT_PINGLESS;

	obd_connect_set_secctx(data);
	if (ll_sbi_has_encrypt(sbi)) {
		obd_connect_set_enc_fid2path(data);
		obd_connect_set_name_enc(data);
		obd_connect_set_enc(data);
	}

#if defined(CONFIG_SECURITY)
	data->ocd_connect_flags2 |= OBD_CONNECT2_SELINUX_POLICY;
#endif

	data->ocd_brw_size = MD_MAX_BRW_SIZE;

retry_connect:
	if (sb_rdonly(sb))
		data->ocd_connect_flags |= OBD_CONNECT_RDONLY;
	err = obd_connect(NULL, &sbi->ll_md_exp, sbi->ll_md_obd,
			  &sbi->ll_sb_uuid, data, sbi->ll_cache);
	if (err == -EBUSY) {
		LCONSOLE_ERROR_MSG(0x14f,
				   "An MDT (md %s) is performing recovery, of which this client is not a part. Please wait for recovery to complete, abort, or time out.\n",
				   md);
		goto out;
	}

	if (err) {
		CERROR("cannot connect to %s: rc = %d\n", md, err);
		goto out;
	}

	sbi->ll_md_exp->exp_connect_data = *data;

	/* Don't change value if it was specified in the config log */
	if (sbi->ll_ra_info.ra_max_read_ahead_whole_pages == -1) {
		sbi->ll_ra_info.ra_max_read_ahead_whole_pages =
			max_t(unsigned long, SBI_DEFAULT_READ_AHEAD_WHOLE_MAX,
			      (data->ocd_brw_size >> PAGE_SHIFT));
		if (sbi->ll_ra_info.ra_max_read_ahead_whole_pages >
		    sbi->ll_ra_info.ra_max_pages_per_file)
			sbi->ll_ra_info.ra_max_read_ahead_whole_pages =
				sbi->ll_ra_info.ra_max_pages_per_file;
	}

	err = obd_fid_init(sbi->ll_md_exp->exp_obd, sbi->ll_md_exp,
			   LUSTRE_SEQ_METADATA);
	if (err) {
		CERROR("%s: Can't init metadata layer FID infrastructure, rc = %d\n",
		       sbi->ll_md_exp->exp_obd->obd_name, err);
		goto out_md;
	}

	/* For mount, we only need fs info from MDT0, and also in DNE, it
	 * can make sure the client can be mounted as long as MDT0 is
	 * available
	 */
	err = obd_statfs(NULL, sbi->ll_md_exp, osfs,
			 ktime_get_seconds() - sbi->ll_statfs_max_age,
			 OBD_STATFS_FOR_MDT0);
	if (err == -EROFS && !sb_rdonly(sb)) {
		/* We got -EROFS from the server, maybe it is imposing
		 * read-only mount. So just retry like this.
		 */
		LCONSOLE_INFO("Forcing read-only mount.\n\r");
		CERROR("%s: mount failed with %d, forcing read-only mount.\n",
		       sbi->ll_md_exp->exp_obd->obd_name, err);
		sb->s_flags |= SB_RDONLY;
		obd_fid_fini(sbi->ll_md_exp->exp_obd);
		obd_disconnect(sbi->ll_md_exp);
		goto retry_connect;
	} else if (err) {
		goto out_md_fid;
	}

	/* This needs to be after statfs to ensure connect has finished.
	 * Note that "data" does NOT contain the valid connect reply.
	 * If connecting to a 1.8 server there will be no LMV device, so
	 * we can access the MDC export directly and exp_connect_flags will
	 * be non-zero, but if accessing an upgraded 2.1 server it will
	 * have the correct flags filled in.
	 * XXX: fill in the LMV exp_connect_flags from MDC(s).
	 */
	valid = exp_connect_flags(sbi->ll_md_exp) & CLIENT_CONNECT_MDT_REQD;
	if (exp_connect_flags(sbi->ll_md_exp) != 0 &&
	    valid != CLIENT_CONNECT_MDT_REQD) {
		char *buf;

		buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!buf) {
			err = -ENOMEM;
			goto out_md_fid;
		}
		obd_connect_flags2str(buf, PAGE_SIZE,
				      valid ^ CLIENT_CONNECT_MDT_REQD, 0, ",");
		LCONSOLE_ERROR_MSG(0x170,
				   "Server %s does not support feature(s) needed for correct operation of this client (%s). Please upgrade server or downgrade client.\n",
				   sbi->ll_md_exp->exp_obd->obd_name, buf);
		kfree(buf);
		err = -EPROTO;
		goto out_md_fid;
	}

	size = sizeof(*data);
	err = obd_get_info(NULL, sbi->ll_md_exp, sizeof(KEY_CONN_DATA),
			   KEY_CONN_DATA,  &size, data);
	if (err) {
		CERROR("%s: Get connect data failed: rc = %d\n",
		       sbi->ll_md_exp->exp_obd->obd_name, err);
		goto out_md_fid;
	}

	LASSERT(osfs->os_bsize);
	sb->s_blocksize = osfs->os_bsize;
	sb->s_blocksize_bits = log2(osfs->os_bsize);
	sb->s_magic = LL_SUPER_MAGIC;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sbi->ll_inode_cache_enabled = 1;
	sbi->ll_namelen = osfs->os_namelen;
	sbi->ll_mnt.mnt = current->fs->root.mnt;
	sbi->ll_mnt_ns = current->nsproxy->mnt_ns;

	if (test_bit(LL_SBI_USER_XATTR, sbi->ll_flags) &&
	    !(data->ocd_connect_flags & OBD_CONNECT_XATTR)) {
		LCONSOLE_INFO("Disabling user_xattr feature because it is not supported on the server\n");
		clear_bit(LL_SBI_USER_XATTR, sbi->ll_flags);
	}

	if (data->ocd_connect_flags & OBD_CONNECT_ACL) {
		sb->s_flags |= SB_POSIXACL;
		set_bit(LL_SBI_ACL, sbi->ll_flags);
	} else {
		LCONSOLE_INFO("client wants to enable acl, but mdt not!\n");
		sb->s_flags &= ~SB_POSIXACL;
		clear_bit(LL_SBI_ACL, sbi->ll_flags);
	}

	if (data->ocd_connect_flags & OBD_CONNECT_64BITHASH)
		set_bit(LL_SBI_64BIT_HASH, sbi->ll_flags);

	if (data->ocd_connect_flags & OBD_CONNECT_LAYOUTLOCK)
		set_bit(LL_SBI_LAYOUT_LOCK, sbi->ll_flags);

	if (obd_connect_has_secctx(data))
		set_bit(LL_SBI_FILE_SECCTX, sbi->ll_flags);

	if (ll_sbi_has_encrypt(sbi) && !obd_connect_has_enc(data)) {
		if (ll_sb_has_test_dummy_encryption(sb))
			LCONSOLE_WARN("%s: server %s does not support encryption feature, encryption deactivated.\n",
				      sbi->ll_fsname,
				      sbi->ll_md_exp->exp_obd->obd_name);
		ll_sbi_set_encrypt(sbi, false);
	}

	if (ll_sbi_has_name_encrypt(sbi) && !obd_connect_has_name_enc(data)) {
		struct  lustre_sb_info *lsi = s2lsi(sb);

		if (ll_sb_has_test_dummy_encryption(sb))
			LCONSOLE_WARN("%s: server %s does not support name encryption, not using it.\n",
				      sbi->ll_fsname,
				      sbi->ll_md_exp->exp_obd->obd_name);
		lsi->lsi_flags &= ~LSI_FILENAME_ENC_B64_OLD_CLI;
		ll_sbi_set_name_encrypt(sbi, false);
	}

	if (data->ocd_ibits_known & MDS_INODELOCK_XATTR) {
		if (!(data->ocd_connect_flags & OBD_CONNECT_MAX_EASIZE)) {
			LCONSOLE_INFO("%s: disabling xattr cache due to unknown maximum xattr size.\n",
				      dt);
		} else if (!sbi->ll_xattr_cache_set) {
			/* If xattr_cache is already set (no matter 0 or 1)
			 * during processing llog, it won't be enabled here.
			 */
			spin_lock(&sbi->ll_lock);
			set_bit(LL_SBI_XATTR_CACHE, sbi->ll_flags);
			spin_unlock(&sbi->ll_lock);
			sbi->ll_xattr_cache_enabled = 1;
		}
	}

	sbi->ll_dt_obd  = class_name2obd(dt);
	if (!sbi->ll_dt_obd) {
		CERROR("DT %s: not setup or attached\n", dt);
		err = -ENODEV;
		goto out_md_fid;
	}

	/* indicate OST features supported by this client */
	data->ocd_connect_flags = OBD_CONNECT_GRANT     | OBD_CONNECT_VERSION  |
				  OBD_CONNECT_REQPORTAL | OBD_CONNECT_BRW_SIZE |
				  OBD_CONNECT_CANCELSET | OBD_CONNECT_FID      |
				  OBD_CONNECT_SRVLOCK   |
				  OBD_CONNECT_AT	| OBD_CONNECT_OSS_CAPA |
				  OBD_CONNECT_VBR	| OBD_CONNECT_FULL20   |
				  OBD_CONNECT_64BITHASH | OBD_CONNECT_MAXBYTES |
				  OBD_CONNECT_EINPROGRESS |
				  OBD_CONNECT_JOBSTATS	| OBD_CONNECT_LVB_TYPE |
				  OBD_CONNECT_LAYOUTLOCK  |
				  OBD_CONNECT_PINGLESS	| OBD_CONNECT_LFSCK |
				  OBD_CONNECT_BULK_MBITS  | OBD_CONNECT_SHORTIO |
				  OBD_CONNECT_FLAGS2 | OBD_CONNECT_GRANT_SHRINK;

	data->ocd_connect_flags2 = OBD_CONNECT2_LOCKAHEAD |
				   OBD_CONNECT2_INC_XID | OBD_CONNECT2_LSEEK |
				   OBD_CONNECT2_REP_MBITS;

	if (!CFS_FAIL_CHECK(OBD_FAIL_OSC_CONNECT_GRANT_PARAM))
		data->ocd_connect_flags |= OBD_CONNECT_GRANT_PARAM;

	/* OBD_CONNECT_CKSUM should always be set, even if checksums are
	 * disabled by default, because it can still be enabled on the
	 * fly via /sys. As a consequence, we still need to come to an
	 * agreement on the supported algorithms at connect time
	 */
	data->ocd_connect_flags |= OBD_CONNECT_CKSUM;

	if (CFS_FAIL_CHECK(OBD_FAIL_OSC_CKSUM_ADLER_ONLY))
		data->ocd_cksum_types = OBD_CKSUM_ADLER;
	else
		data->ocd_cksum_types = obd_cksum_types_supported_client();

	data->ocd_connect_flags |= OBD_CONNECT_LRU_RESIZE;

	/* always ping even if server suppress_pings */
	if (test_bit(LL_SBI_ALWAYS_PING, sbi->ll_flags))
		data->ocd_connect_flags &= ~OBD_CONNECT_PINGLESS;

	if (ll_sbi_has_encrypt(sbi))
		obd_connect_set_enc(data);

	CDEBUG(D_RPCTRACE,
	       "ocd_connect_flags: %#llx ocd_version: %d ocd_grant: %d\n",
	       data->ocd_connect_flags,
	       data->ocd_version, data->ocd_grant);

	sbi->ll_dt_obd->obd_upcall.onu_owner = &sbi->ll_lco;
	sbi->ll_dt_obd->obd_upcall.onu_upcall = cl_ocd_update;

	data->ocd_brw_size = DT_MAX_BRW_SIZE;

	err = obd_connect(NULL, &sbi->ll_dt_exp, sbi->ll_dt_obd,
			  &sbi->ll_sb_uuid, data, sbi->ll_cache);
	if (err == -EBUSY) {
		LCONSOLE_ERROR_MSG(0x150,
				   "An OST (dt %s) is performing recovery, of which this client is not a part.  Please wait for recovery to complete, abort, or time out.\n",
				   dt);
		goto out_md_fid;
	} else if (err) {
		CERROR("%s: Cannot connect to %s: rc = %d\n",
		       sbi->ll_dt_exp->exp_obd->obd_name, dt, err);
		goto out_md_fid;
	}

	if (ll_sbi_has_encrypt(sbi) &&
	    !obd_connect_has_enc(&sbi->ll_dt_obd->u.lov.lov_ocd)) {
		if (ll_sb_has_test_dummy_encryption(sb))
			LCONSOLE_WARN("%s: server %s does not support encryption feature, encryption deactivated.\n",
				      sbi->ll_fsname, dt);
		ll_sbi_set_encrypt(sbi, false);
	} else if (ll_sb_has_test_dummy_encryption(sb)) {
		LCONSOLE_WARN("Test dummy encryption mode enabled\n");
	}

	sbi->ll_dt_exp->exp_connect_data = *data;

	/* Don't change value if it was specified in the config log */
	if (sbi->ll_ra_info.ra_max_read_ahead_whole_pages == -1)
		sbi->ll_ra_info.ra_max_read_ahead_whole_pages =
			max_t(unsigned long, SBI_DEFAULT_READ_AHEAD_WHOLE_MAX,
			      (data->ocd_brw_size >> PAGE_SHIFT));

	err = obd_fid_init(sbi->ll_dt_exp->exp_obd, sbi->ll_dt_exp,
			   LUSTRE_SEQ_METADATA);
	if (err) {
		CERROR("%s: Can't init data layer FID infrastructure, rc = %d\n",
		       sbi->ll_dt_exp->exp_obd->obd_name, err);
		goto out_dt;
	}

	mutex_lock(&sbi->ll_lco.lco_lock);
	sbi->ll_lco.lco_flags = data->ocd_connect_flags;
	sbi->ll_lco.lco_md_exp = sbi->ll_md_exp;
	sbi->ll_lco.lco_dt_exp = sbi->ll_dt_exp;
	mutex_unlock(&sbi->ll_lco.lco_lock);

	fid_zero(&sbi->ll_root_fid);
	err = md_get_root(sbi->ll_md_exp, get_mount_fileset(sb),
			  &sbi->ll_root_fid);
	if (err) {
		CERROR("cannot mds_connect: rc = %d\n", err);
		goto out_lock_cn_cb;
	}
	if (!fid_is_sane(&sbi->ll_root_fid)) {
		CERROR("%s: Invalid root fid " DFID " during mount\n",
		       sbi->ll_md_exp->exp_obd->obd_name,
		       PFID(&sbi->ll_root_fid));
		err = -EINVAL;
		goto out_lock_cn_cb;
	}
	CDEBUG(D_SUPER, "rootfid " DFID "\n", PFID(&sbi->ll_root_fid));

	sb->s_op = &lustre_super_operations;
	sb->s_xattr = ll_xattr_handlers;
#if THREAD_SIZE >= 8192 /*b=17630*/
	sb->s_export_op = &lustre_export_operations;
#endif

	fscrypt_set_ops(sb, &lustre_cryptops);
	/* make root inode
	 * XXX: move this to after cbd setup?
	 */
	valid = OBD_MD_FLGETATTR | OBD_MD_FLBLOCKS | OBD_MD_FLMODEASIZE |
		OBD_MD_ENCCTX;
	if (test_bit(LL_SBI_ACL, sbi->ll_flags))
		valid |= OBD_MD_FLACL;

	op_data = kzalloc(sizeof(*op_data), GFP_NOFS);
	if (!op_data) {
		err = -ENOMEM;
		goto out_lock_cn_cb;
	}

	op_data->op_fid1 = sbi->ll_root_fid;
	op_data->op_mode = 0;
	op_data->op_valid = valid;

	err = md_getattr(sbi->ll_md_exp, op_data, &request);

	/* We need enc ctx info, so reset it in op_data to
	 * prevent it from being freed.
	 */
	encctx = op_data->op_file_encctx;
	encctxlen = op_data->op_file_encctx_size;
	op_data->op_file_encctx = NULL;
	op_data->op_file_encctx_size = 0;
	kfree(op_data);
	if (err) {
		CERROR("%s: md_getattr failed for root: rc = %d\n",
		       sbi->ll_md_exp->exp_obd->obd_name, err);
		goto out_lock_cn_cb;
	}

	err = md_get_lustre_md(sbi->ll_md_exp, &request->rq_pill,
			       sbi->ll_dt_exp, sbi->ll_md_exp, &lmd);
	if (err) {
		CERROR("failed to understand root inode md: rc = %d\n", err);
		ptlrpc_req_finished(request);
		goto out_lock_cn_cb;
	}

	LASSERT(fid_is_sane(&sbi->ll_root_fid));
	api32 = test_bit(LL_SBI_32BIT_API, sbi->ll_flags);
	root = ll_iget(sb, cl_fid_build_ino(&sbi->ll_root_fid, api32), &lmd);
	md_free_lustre_md(sbi->ll_md_exp, &lmd);

	if (IS_ERR(root)) {
		lmd_clear_acl(&lmd);
		err = IS_ERR(root) ? PTR_ERR(root) : -EBADF;
		root = NULL;
		CERROR("%s: bad ll_iget() for root: rc = %d\n",
		       sbi->ll_fsname, err);
		ptlrpc_req_finished(request);
		goto out_root;
	}

	err = ll_secctx_name_store(root);
	if (err < 0 && ll_security_xattr_wanted(root))
		CWARN("%s: file security contextes not supported: rc = %d\n",
		      sbi->ll_fsname, err);

	err = 0;
	if (encctxlen) {
		CDEBUG(D_SEC,
		       "server returned encryption ctx for root inode "DFID"\n",
		       PFID(&sbi->ll_root_fid));
		err = ll_set_encflags(root, encctx, encctxlen, true);
		if (err)
			CWARN("%s: cannot set enc ctx for "DFID": rc = %d\n",
			      sbi->ll_fsname,
			      PFID(&sbi->ll_root_fid), err);
	}
	ptlrpc_req_finished(request);

	checksum = test_bit(LL_SBI_CHECKSUM, sbi->ll_flags);
	if (sbi->ll_checksum_set) {
		err = obd_set_info_async(NULL, sbi->ll_dt_exp,
					 sizeof(KEY_CHECKSUM), KEY_CHECKSUM,
					 sizeof(checksum), &checksum, NULL);
		if (err) {
			CERROR("%s: Set checksum failed: rc = %d\n",
			       sbi->ll_dt_exp->exp_obd->obd_name, err);
			goto out_root;
		}
	}
	cl_sb_init(sb);

	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		err = -ENOMEM;
		CERROR("%s: can't make root dentry, rc = %d\n",
		       sbi->ll_fsname, err);
		goto out_lock_cn_cb;
	}

	sbi->ll_sdev_orig = sb->s_dev;

	/* We set sb->s_dev equal on all lustre clients in order to support
	 * NFS export clustering.  NFSD requires that the FSID be the same
	 * on all clients.
	 */
	/* s_dev is also used in lt_compare() to compare two fs, but that is
	 * only a node-local comparison.
	 */
	uuid = obd_get_uuid(sbi->ll_md_exp);
	if (uuid)
		sb->s_dev = get_uuid2int(uuid->uuid, strlen(uuid->uuid));

	kfree(data);
	kfree(osfs);

	if (sbi->ll_dt_obd) {
		err = sysfs_create_link(&sbi->ll_kset.kobj,
					&sbi->ll_dt_obd->obd_kset.kobj,
					sbi->ll_dt_obd->obd_type->typ_name);
		if (err < 0) {
			CERROR("%s: could not register %s in llite: rc = %d\n",
			       dt, sbi->ll_fsname, err);
			err = 0;
		}
	}

	if (sbi->ll_md_obd) {
		err = sysfs_create_link(&sbi->ll_kset.kobj,
					&sbi->ll_md_obd->obd_kset.kobj,
					sbi->ll_md_obd->obd_type->typ_name);
		if (err < 0) {
			CERROR("%s: could not register %s in llite: rc = %d\n",
			       md, sbi->ll_fsname, err);
			err = 0;
		}
	}

	return err;
out_root:
	iput(root);
out_lock_cn_cb:
	obd_fid_fini(sbi->ll_dt_exp->exp_obd);
out_dt:
	obd_disconnect(sbi->ll_dt_exp);
	sbi->ll_dt_exp = NULL;
	sbi->ll_dt_obd = NULL;
out_md_fid:
	obd_fid_fini(sbi->ll_md_exp->exp_obd);
out_md:
	obd_disconnect(sbi->ll_md_exp);
	sbi->ll_md_exp = NULL;
out:
	kfree(data);
	kfree(osfs);
	return err;
}

int ll_get_max_mdsize(struct ll_sb_info *sbi, int *lmmsize)
{
	int size, rc;

	size = sizeof(*lmmsize);
	rc = obd_get_info(NULL, sbi->ll_dt_exp, sizeof(KEY_MAX_EASIZE),
			  KEY_MAX_EASIZE, &size, lmmsize);
	if (rc) {
		CERROR("%s: cannot get max LOV EA size: rc = %d\n",
		       sbi->ll_dt_exp->exp_obd->obd_name, rc);
		return rc;
	}

	CDEBUG(D_INFO, "max LOV ea size: %d\n", *lmmsize);

	size = sizeof(int);
	rc = obd_get_info(NULL, sbi->ll_md_exp, sizeof(KEY_MAX_EASIZE),
			  KEY_MAX_EASIZE, &size, lmmsize);
	if (rc)
		CERROR("Get max mdsize error rc %d\n", rc);

	CDEBUG(D_INFO, "max LMV ea size: %d\n", *lmmsize);

	return rc;
}

/**
 * Get the value of the default_easize parameter.
 *
 * \see client_obd::cl_default_mds_easize
 *
 * @sbi:	superblock info for this filesystem
 * @lmmsize:	pointer to storage location for value
 *
 * Returns:	0 on success
 *		negated errno on failure
 */
int ll_get_default_mdsize(struct ll_sb_info *sbi, int *lmmsize)
{
	int size, rc;

	size = sizeof(int);
	rc = obd_get_info(NULL, sbi->ll_md_exp, sizeof(KEY_DEFAULT_EASIZE),
			  KEY_DEFAULT_EASIZE, &size, lmmsize);
	if (rc)
		CERROR("Get default mdsize error rc %d\n", rc);

	return rc;
}

/**
 * Set the default_easize parameter to the given value.
 *
 * \see client_obd::cl_default_mds_easize
 *
 * @sbi:	superblock info for this filesystem
 * @lmmsize:	the size to set
 *
 * Return:	0 on success
 *		negated errno on failure
 */
int ll_set_default_mdsize(struct ll_sb_info *sbi, int lmmsize)
{
	if (lmmsize < sizeof(struct lov_mds_md) ||
	    lmmsize > OBD_MAX_DEFAULT_EA_SIZE)
		return -EINVAL;

	return obd_set_info_async(NULL, sbi->ll_md_exp,
				  sizeof(KEY_DEFAULT_EASIZE),
				  KEY_DEFAULT_EASIZE,
				  sizeof(int), &lmmsize, NULL);
}

static void client_common_put_super(struct super_block *sb)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	cl_sb_fini(sb);

	obd_fid_fini(sbi->ll_dt_exp->exp_obd);
	obd_disconnect(sbi->ll_dt_exp);
	sbi->ll_dt_exp = NULL;

	ll_debugfs_unregister_super(sb);

	obd_fid_fini(sbi->ll_md_exp->exp_obd);
	obd_disconnect(sbi->ll_md_exp);
	sbi->ll_md_exp = NULL;
}

void ll_kill_super(struct super_block *sb)
{
	struct ll_sb_info *sbi;

	/* not init sb ?*/
	if (!(sb->s_flags & SB_ACTIVE))
		return;

	sbi = ll_s2sbi(sb);
	/* we need to restore s_dev from changed for clustered NFS before
	 * put_super because new kernels have cached s_dev and change sb->s_dev
	 * in put_super not affected real removing devices
	 */
	if (sbi) {
		sb->s_dev = sbi->ll_sdev_orig;

		/* wait running statahead threads to quit */
		while (atomic_read(&sbi->ll_sa_running) > 0)
			schedule_timeout_uninterruptible(HZ >> 3);
	}
}

/* Since we use this table for ll_sbi_flags_seq_show make
 * sure what you want displayed for a specific token that
 * is listed more than once below be listed first. For
 * example we want "checksum" displayed, not "nochecksum"
 * for the sbi_flags.
 */
static const match_table_t ll_sbi_flags_name = {
	{LL_SBI_NOLCK,			"nolock"},
	{LL_SBI_CHECKSUM,		"checksum"},
	{LL_SBI_CHECKSUM,		"nochecksum"},
	{LL_SBI_LOCALFLOCK,		"localflock"},
	{LL_SBI_FLOCK,			"flock"},
	{LL_SBI_FLOCK,			"noflock"},
	{LL_SBI_USER_XATTR,		"user_xattr"},
	{LL_SBI_USER_XATTR,		"nouser_xattr"},
	{LL_SBI_LRU_RESIZE,		"lruresize"},
	{LL_SBI_LRU_RESIZE,		"nolruresize"},
	{LL_SBI_LAZYSTATFS,		"lazystatfs"},
	{LL_SBI_LAZYSTATFS,		"nolazystatfs"},
	{LL_SBI_32BIT_API,		"32bitapi"},
	{LL_SBI_USER_FID2PATH,		"user_fid2path"},
	{LL_SBI_USER_FID2PATH,		"nouser_fid2path"},
	{LL_SBI_VERBOSE,		"verbose"},
	{LL_SBI_VERBOSE,		"noverbose"},
	{LL_SBI_ALWAYS_PING,		"always_ping"},
	{LL_SBI_TEST_DUMMY_ENCRYPTION,	"test_dummy_encryption=%s"},
	{LL_SBI_TEST_DUMMY_ENCRYPTION,	"test_dummy_encryption"},
	{LL_SBI_ENCRYPT,		"encrypt"},
	{LL_SBI_ENCRYPT,		"noencrypt"},
	{LL_SBI_FOREIGN_SYMLINK,	"foreign_symlink=%s"},
	{LL_SBI_NUM_MOUNT_OPT,		NULL},

	{LL_SBI_ACL,			"acl"},
	{LL_SBI_AGL_ENABLED,		"agl"},
	{LL_SBI_64BIT_HASH,		"64bit_hash"},
	{LL_SBI_LAYOUT_LOCK,		"layout"},
	{LL_SBI_XATTR_CACHE,		"xattr_cache"},
	{LL_SBI_NOROOTSQUASH,		"norootsquash"},
	{LL_SBI_FAST_READ,		"fast_read"},
	{LL_SBI_FILE_SECCTX,		"file_secctx"},
	{LL_SBI_TINY_WRITE,		"tiny_write"},
	{LL_SBI_FILE_HEAT,		"file_heat"},
	{LL_SBI_PARALLEL_DIO,		"parallel_dio"},
	{LL_SBI_ENCRYPT_NAME,		"name_encrypt"},
};

int ll_sbi_flags_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	int i;

	for (i = 0; i < LL_SBI_NUM_FLAGS; i++) {
		int j;

		if (!test_bit(i, ll_s2sbi(sb)->ll_flags))
			continue;

		for (j = 0; j < ARRAY_SIZE(ll_sbi_flags_name); j++) {
			if (ll_sbi_flags_name[j].token == i &&
			    ll_sbi_flags_name[j].pattern) {
				seq_printf(m, "%s ",
					   ll_sbi_flags_name[j].pattern);
				break;
			}
		}
	}
	seq_puts(m, "\b\n");
	return 0;
}

/* non-client-specific mount options are parsed in lmd_parse */
static int ll_options(char *options, struct super_block *sb)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	char *s2, *s1, *opts;
	int err = 0;

	if (!options)
		return 0;

	/* Don't stomp on lmd_opts */
	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;
	s1 = opts;
	s2 = opts;

	CDEBUG(D_CONFIG, "Parsing opts %s\n", options);

	while ((s1 = strsep(&opts, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		bool turn_off = false;
		int token;

		if (!*s1)
			continue;

		CDEBUG(D_SUPER, "next opt=%s\n", s1);
		if (strncmp(s1, "no", 2) == 0)
			turn_off = true;

		/*
		 * Initialize args struct so we know whether arg was
		 * found; some options take optional arguments.
		 */
		args[0].to = NULL;
		args[0].from = NULL;
		token = match_token(s1, ll_sbi_flags_name, args);
		if (token == LL_SBI_NUM_MOUNT_OPT) {
			if (match_wildcard("context", s1) ||
			    match_wildcard("fscontext", s1) ||
			    match_wildcard("defcontext", s1) ||
			    match_wildcard("rootcontext", s1))
				continue;

			LCONSOLE_ERROR_MSG(0x152,
					   "Unknown option '%s', won't mount.\n",
					   s1);
			return -EINVAL;
		}

		switch (token) {
		case LL_SBI_NOLCK:
		case LL_SBI_32BIT_API:
		case LL_SBI_64BIT_HASH:
		case LL_SBI_ALWAYS_PING:
			set_bit(token, sbi->ll_flags);
			break;

		case LL_SBI_FLOCK:
			clear_bit(LL_SBI_LOCALFLOCK, sbi->ll_flags);
			if (turn_off)
				clear_bit(LL_SBI_FLOCK, sbi->ll_flags);
			else
				set_bit(token, sbi->ll_flags);
			break;

		case LL_SBI_LOCALFLOCK:
			clear_bit(LL_SBI_FLOCK, sbi->ll_flags);
			set_bit(token, sbi->ll_flags);
			break;

		case LL_SBI_CHECKSUM:
			sbi->ll_checksum_set = 1;
			fallthrough;
		case LL_SBI_USER_XATTR:
		case LL_SBI_USER_FID2PATH:
		case LL_SBI_LRU_RESIZE:
		case LL_SBI_LAZYSTATFS:
		case LL_SBI_VERBOSE:
			if (turn_off)
				clear_bit(token, sbi->ll_flags);
			else
				set_bit(token, sbi->ll_flags);
			break;
		case LL_SBI_TEST_DUMMY_ENCRYPTION: {
#ifdef CONFIG_FS_ENCRYPTION
			struct lustre_sb_info *lsi = s2lsi(sb);

			err = fscrypt_set_test_dummy_encryption(sb, &args[0],
								&lsi->lsi_dummy_enc_ctx);
			if (!err)
				break;

			if (err == -EEXIST)
				LCONSOLE_WARN("Can't change test_dummy_encryption");
			else if (err == -EINVAL)
				LCONSOLE_WARN("Value of option \"%s\" unrecognized",
					      options);
			else
				LCONSOLE_WARN("Error processing option \"%s\" [%d]",
					      options, err);
			err = -1;
#else
			LCONSOLE_WARN("Test dummy encryption mount option ignored: encryption not supported\n");
#endif
			break;
		}
		case LL_SBI_ENCRYPT:
#ifdef CONFIG_FS_ENCRYPTION
			if (turn_off)
				clear_bit(token, sbi->ll_flags);
			else
				set_bit(token, sbi->ll_flags);
#else
			LCONSOLE_WARN("noencrypt or encrypt mount option ignored: encryption not supported\n");
#endif
			break;
		case LL_SBI_FOREIGN_SYMLINK:
			/* non-default prefix provided ? */
			if (args->from) {
				size_t old_len;
				char *old;

				/* path must be absolute */
				if (args->from[0] != '/') {
					LCONSOLE_ERROR_MSG(0x152,
							   "foreign prefix '%s' must be an absolute path\n",
							   args->from);
					return -EINVAL;
				}
				old_len = sbi->ll_foreign_symlink_prefix_size;
				old = sbi->ll_foreign_symlink_prefix;
				/* alloc for path length and '\0' */
				sbi->ll_foreign_symlink_prefix = match_strdup(args);
				if (!sbi->ll_foreign_symlink_prefix) {
					/* restore previous */
					sbi->ll_foreign_symlink_prefix = old;
					sbi->ll_foreign_symlink_prefix_size =
						old_len;
					return -ENOMEM;
				}
				sbi->ll_foreign_symlink_prefix_size =
					args->to - args->from + 1;
				kfree(old);

				/* enable foreign symlink support */
				set_bit(token, sbi->ll_flags);
			} else {
				LCONSOLE_ERROR_MSG(0x152,
						   "invalid %s option\n", s1);
			}
		fallthrough;
		default:
			break;
		}
	}
	kfree(opts);
	return err;
}

void ll_lli_init(struct ll_inode_info *lli)
{
	lli->lli_inode_magic = LLI_INODE_MAGIC;
	lli->lli_flags = 0;
	rwlock_init(&lli->lli_lock);
	lli->lli_posix_acl = NULL;
	/* Do not set lli_fid, it has been initialized already. */
	fid_zero(&lli->lli_pfid);
	lli->lli_mds_read_och = NULL;
	lli->lli_mds_write_och = NULL;
	lli->lli_mds_exec_och = NULL;
	lli->lli_open_fd_read_count = 0;
	lli->lli_open_fd_write_count = 0;
	lli->lli_open_fd_exec_count = 0;
	mutex_init(&lli->lli_och_mutex);
	spin_lock_init(&lli->lli_agl_lock);
	spin_lock_init(&lli->lli_layout_lock);
	ll_layout_version_set(lli, CL_LAYOUT_GEN_NONE);
	lli->lli_clob = NULL;

	init_rwsem(&lli->lli_xattrs_list_rwsem);
	mutex_init(&lli->lli_xattrs_enq_lock);

	LASSERT(lli->lli_vfs_inode.i_mode != 0);
	if (S_ISDIR(lli->lli_vfs_inode.i_mode)) {
		lli->lli_opendir_key = NULL;
		lli->lli_sai = NULL;
		spin_lock_init(&lli->lli_sa_lock);
		lli->lli_opendir_pid = 0;
		lli->lli_sa_enabled = 0;
		init_rwsem(&lli->lli_lsm_sem);
	} else {
		mutex_init(&lli->lli_size_mutex);
		mutex_init(&lli->lli_setattr_mutex);
		lli->lli_symlink_name = NULL;
		ll_trunc_sem_init(&lli->lli_trunc_sem);
		range_lock_tree_init(&lli->lli_write_tree);
		init_rwsem(&lli->lli_glimpse_sem);
		lli->lli_glimpse_time = ktime_set(0, 0);
		INIT_LIST_HEAD(&lli->lli_agl_list);
		lli->lli_agl_index = 0;
		lli->lli_async_rc = 0;
		spin_lock_init(&lli->lli_heat_lock);
		obd_heat_clear(lli->lli_heat_instances, OBD_HEAT_COUNT);
		lli->lli_heat_flags = 0;
		mutex_init(&lli->lli_pcc_lock);
		lli->lli_pcc_state = PCC_STATE_FL_NONE;
		lli->lli_pcc_inode = NULL;
		lli->lli_pcc_dsflags = PCC_DATASET_INVALID;
		lli->lli_pcc_generation = 0;
		mutex_init(&lli->lli_group_mutex);
		lli->lli_group_users = 0;
		lli->lli_group_gid = 0;
		memset(lli->lli_jobid, 0, sizeof(lli->lli_jobid));
		lli->lli_uid = (u32) -1;
		lli->lli_gid = (u32) -1;
	}
	mutex_init(&lli->lli_layout_mutex);
	/* ll_cl_context initialize */
	INIT_LIST_HEAD(&lli->lli_lccs);
	seqlock_init(&lli->lli_page_inv_lock);
}

int ll_fill_super(struct super_block *sb)
{
	struct lustre_profile *lprof = NULL;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct ll_sb_info *sbi = NULL;
	char *dt = NULL, *md = NULL;
	char *profilenm = get_profile_name(sb);
	struct config_llog_instance *cfg;
	char name[MAX_OBD_NAME];
	uuid_t uuid;
	char *ptr;
	int len;
	int err;

	CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);

	CFS_RACE(OBD_FAIL_LLITE_RACE_MOUNT);

	cfg = kzalloc(sizeof(*cfg), GFP_NOFS);
	if (!cfg) {
		err = -ENOMEM;
		goto out_free;
	}

	/* client additional sb info */
	sbi = ll_init_sbi(lsi);
	lsi->lsi_llsbi = sbi;
	if (IS_ERR(sbi)) {
		err = PTR_ERR(sbi);
		goto out_free;
	}

	err = ll_options(lsi->lsi_lmd->lmd_opts, sb);
	if (err)
		goto out_free;

	/* kernel >= 2.6.38 store dentry operations in sb->s_d_op. */
	sb->s_d_op = &ll_d_ops;

	/* UUID handling */
	generate_random_uuid(uuid.b);
	snprintf(sbi->ll_sb_uuid.uuid, sizeof(sbi->ll_sb_uuid), "%pU", uuid.b);

	CDEBUG(D_CONFIG, "llite sb uuid: %s\n", sbi->ll_sb_uuid.uuid);

	/* Get fsname */
	len = strlen(lsi->lsi_lmd->lmd_profile);
	ptr = strrchr(lsi->lsi_lmd->lmd_profile, '-');
	if (ptr && (strcmp(ptr, "-client") == 0))
		len -= 7;

	if (len > LUSTRE_MAXFSNAME) {
		if (unlikely(len >= MAX_OBD_NAME))
			len = MAX_OBD_NAME - 1;
		strncpy(name, profilenm, len);
		name[len] = '\0';
		err = -ENAMETOOLONG;
		CERROR("%s: fsname longer than %u characters: rc = %d\n",
		       name, LUSTRE_MAXFSNAME, err);
		goto out_free;
	}
	strncpy(sbi->ll_fsname, profilenm, len);
	sbi->ll_fsname[len] = '\0';

	/* Mount info */
	snprintf(name, sizeof(name), "%.*s-%px", len,
		 lsi->lsi_lmd->lmd_profile, sb);

	err = super_setup_bdi_name(sb, "%s", name);
	if (err)
		goto out_free;

	/* disable kernel readahead */
	sb->s_bdi->ra_pages = 0;
	sb->s_bdi->io_pages = 0;

	/* Call ll_debugsfs_register_super() before lustre_process_log()
	 * so that "llite.*.*" params can be processed correctly.
	 */
	err = ll_debugfs_register_super(sb, name);
	if (err < 0) {
		CERROR("%s: could not register mountpoint in llite: rc = %d\n",
		       sbi->ll_fsname, err);
		err = 0;
	}

	/* Generate a string unique to this super, in case some joker tries
	 * to mount the same fs at two mount points.
	 * Use the address of the super itself.
	 */
	cfg->cfg_instance = sb;
	cfg->cfg_uuid = lsi->lsi_llsbi->ll_sb_uuid;
	cfg->cfg_callback = class_config_llog_handler;
	cfg->cfg_sub_clds = CONFIG_SUB_CLIENT;
	/* set up client obds */
	err = lustre_process_log(sb, profilenm, cfg);
	if (err < 0)
		goto out_debugfs;

	/* Profile set with LCFG_MOUNTOPT so we can find our mdc and osc obds */
	lprof = class_get_profile(profilenm);
	if (!lprof) {
		LCONSOLE_ERROR_MSG(0x156,
				   "The client profile '%s' could not be read from the MGS.  Does that filesystem exist?\n",
				   profilenm);
		err = -EINVAL;
		goto out_debugfs;
	}
	CDEBUG(D_CONFIG, "Found profile %s: mdc=%s osc=%s\n", profilenm,
	       lprof->lp_md, lprof->lp_dt);

	dt = kasprintf(GFP_NOFS, "%s-%px", lprof->lp_dt, cfg->cfg_instance);
	if (!dt) {
		err = -ENOMEM;
		goto out_debugfs;
	}

	md = kasprintf(GFP_NOFS, "%s-%px", lprof->lp_md, cfg->cfg_instance);
	if (!md) {
		err = -ENOMEM;
		goto out_debugfs;
	}

	/* connections, registrations, sb setup */
	err = client_common_fill_super(sb, md, dt);
	if (!err)
		sbi->ll_client_common_fill_super_succeeded = 1;

out_debugfs:
	if (err < 0)
		ll_debugfs_unregister_super(sb);
out_free:
	kfree(md);
	kfree(dt);
	if (lprof)
		class_put_profile(lprof);
	kfree(cfg);
	if (err)
		ll_put_super(sb);
	else if (test_bit(LL_SBI_VERBOSE, sbi->ll_flags))
		LCONSOLE_WARN("Mounted %s%s\n", profilenm,
			      sb_rdonly(sb) ? " read-only" : "");
	return err;
} /* ll_fill_super */

void ll_common_put_super(struct super_block *sb)
{
	lustre_common_put_super(sb);
	ptlrpc_dec_ref();
}

void ll_put_super(struct super_block *sb)
{
	struct config_llog_instance cfg, params_cfg;
	struct obd_device *obd;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	char *profilenm = get_profile_name(sb);
	int next, force = 1, rc = 0;
	long ccc_count;

	if (IS_ERR(sbi))
		goto out_no_sbi;

	CDEBUG(D_VFSTRACE, "VFS Op: sb %p - %s\n", sb, profilenm);

	cfg.cfg_instance = sb;
	lustre_end_log(sb, profilenm, &cfg);

	params_cfg.cfg_instance = sb;
	lustre_end_log(sb, PARAMS_FILENAME, &params_cfg);

	if (sbi->ll_md_exp) {
		obd = class_exp2obd(sbi->ll_md_exp);
		if (obd)
			force = obd->obd_force;
	}

	/* Wait for unstable pages to be committed to stable storage */
	if (!force)
		rc = l_wait_event_abortable(sbi->ll_cache->ccc_unstable_waitq,
					    !atomic_long_read(&sbi->ll_cache->ccc_unstable_nr));

	ccc_count = atomic_long_read(&sbi->ll_cache->ccc_unstable_nr);
	if (!force && rc != -ERESTARTSYS)
		LASSERTF(!ccc_count, "count: %li\n", ccc_count);

	/* We need to set force before the lov_disconnect in
	 * lustre_common_put_super, since l_d cleans up osc's as well.
	 */
	if (force) {
		next = 0;
		while ((obd = class_devices_in_group(&sbi->ll_sb_uuid,
						     &next)) != NULL) {
			obd->obd_force = force;
		}
	}

	if (sbi->ll_client_common_fill_super_succeeded) {
		/* Only if client_common_fill_super succeeded */
		client_common_put_super(sb);
	}

	/* imitate failed cleanup */
	if (CFS_FAIL_CHECK(OBD_FAIL_OBD_CLEANUP))
		goto skip_cleanup;

	next = 0;
	while ((obd = class_devices_in_group(&sbi->ll_sb_uuid, &next)))
		class_manual_cleanup(obd);

skip_cleanup:
	if (test_bit(LL_SBI_VERBOSE, sbi->ll_flags))
		LCONSOLE_WARN("Unmounted %s\n", profilenm ? profilenm : "");

	if (profilenm)
		class_del_profile(profilenm);

	fscrypt_free_dummy_context(&lsi->lsi_dummy_enc_ctx);
	ll_free_sbi(sb);
	lsi->lsi_llsbi = NULL;

out_no_sbi:
	ll_common_put_super(sb);

	cl_env_cache_purge(~0);
} /* client_put_super */

struct inode *ll_inode_from_resource_lock(struct ldlm_lock *lock)
{
	struct inode *inode = NULL;

	/* NOTE: we depend on atomic igrab() -bzzz */
	lock_res_and_lock(lock);
	if (lock->l_resource->lr_lvb_inode) {
		struct ll_inode_info *lli;

		lli = ll_i2info(lock->l_resource->lr_lvb_inode);
		if (lli->lli_inode_magic == LLI_INODE_MAGIC) {
			inode = igrab(lock->l_resource->lr_lvb_inode);
		} else {
			inode = lock->l_resource->lr_lvb_inode;
			LDLM_DEBUG_LIMIT(inode->i_state & I_FREEING ?  D_INFO :
					 D_WARNING, lock,
					 "lr_lvb_inode %p is bogus: magic %08x",
					 lock->l_resource->lr_lvb_inode,
					 lli->lli_inode_magic);
			inode = NULL;
		}
	}
	unlock_res_and_lock(lock);
	return inode;
}

void ll_dir_clear_lsm_md(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);

	LASSERT(S_ISDIR(inode->i_mode));

	if (lli->lli_lsm_md) {
		lmv_free_memmd(lli->lli_lsm_md);
		lli->lli_lsm_md = NULL;
	}

	if (lli->lli_default_lsm_md) {
		lmv_free_memmd(lli->lli_default_lsm_md);
		lli->lli_default_lsm_md = NULL;
	}
}

static struct inode *ll_iget_anon_dir(struct super_block *sb,
				      const struct lu_fid *fid,
				      struct lustre_md *md)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct ll_inode_info *lli;
	struct mdt_body *body = md->body;
	struct inode *inode;
	ino_t ino;

	LASSERT(md->lmv);
	ino = cl_fid_build_ino(fid, test_bit(LL_SBI_32BIT_API, sbi->ll_flags));
	inode = iget_locked(sb, ino);
	if (!inode) {
		CERROR("%s: failed get simple inode " DFID ": rc = -ENOENT\n",
		       sbi->ll_fsname, PFID(fid));
		return ERR_PTR(-ENOENT);
	}

	lli = ll_i2info(inode);
	if (inode->i_state & I_NEW) {
		inode->i_mode = (inode->i_mode & ~S_IFMT) |
				(body->mbo_mode & S_IFMT);
		LASSERTF(S_ISDIR(inode->i_mode), "Not slave inode " DFID "\n",
			 PFID(fid));

		inode->i_mtime.tv_sec = 0;
		inode->i_atime.tv_sec = 0;
		inode->i_ctime.tv_sec = 0;
		inode->i_rdev = 0;

		inode->i_op = &ll_dir_inode_operations;
		inode->i_fop = &ll_dir_operations;
		lli->lli_fid = *fid;
		ll_lli_init(lli);

		/* master object FID */
		lli->lli_pfid = body->mbo_fid1;
		CDEBUG(D_INODE, "lli %p slave " DFID " master " DFID "\n",
		       lli, PFID(fid), PFID(&lli->lli_pfid));
		unlock_new_inode(inode);
	} else {
		/* in directory restripe/auto-split, a directory will be
		 * transformed to a stripe if it's plain, set its pfid here,
		 * otherwise ll_lock_cancel_bits() can't find the master inode.
		 */
		lli->lli_pfid = body->mbo_fid1;
	}

	return inode;
}

static int ll_init_lsm_md(struct inode *inode, struct lustre_md *md)
{
	struct lmv_stripe_md *lsm = md->lmv;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lu_fid *fid;
	int i;

	LASSERT(lsm);

	CDEBUG(D_INODE, "%s: "DFID" set dir layout:\n",
	       ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid));
	lsm_md_dump(D_INODE, lsm);

	if (!lmv_dir_striped(lsm))
		goto out;

	/*
	 * XXX sigh, this lsm_root initialization should be in
	 * LMV layer, but it needs ll_iget right now, so we
	 * put this here right now.
	 */
	for (i = 0; i < lsm->lsm_md_stripe_count; i++) {
		fid = &lsm->lsm_md_oinfo[i].lmo_fid;
		LASSERT(!lsm->lsm_md_oinfo[i].lmo_root);

		if (!fid_is_sane(fid))
			continue;

		/* Unfortunately ll_iget will call ll_update_inode,
		 * where the initialization of slave inode is slightly
		 * different, so it reset lsm_md to NULL to avoid
		 * initializing lsm for slave inode.
		 */
		lsm->lsm_md_oinfo[i].lmo_root =
			ll_iget_anon_dir(inode->i_sb, fid, md);
		if (IS_ERR(lsm->lsm_md_oinfo[i].lmo_root)) {
			int rc = PTR_ERR(lsm->lsm_md_oinfo[i].lmo_root);

			lsm->lsm_md_oinfo[i].lmo_root = NULL;
			while (i-- > 0) {
				iput(lsm->lsm_md_oinfo[i].lmo_root);
				lsm->lsm_md_oinfo[i].lmo_root = NULL;
			}
			return rc;
		}
	}
out:
	lli->lli_lsm_md = lsm;

	return 0;
}

static void ll_update_default_lsm_md(struct inode *inode, struct lustre_md *md)
{
	struct ll_inode_info *lli = ll_i2info(inode);

	if (!md->default_lmv) {
		/* clear default lsm */
		if (lli->lli_default_lsm_md && lli->lli_default_lmv_set) {
			down_write(&lli->lli_lsm_sem);
			if (lli->lli_default_lsm_md &&
			    lli->lli_default_lmv_set) {
				lmv_free_memmd(lli->lli_default_lsm_md);
				lli->lli_default_lsm_md = NULL;
				lli->lli_inherit_depth = 0;
				lli->lli_default_lmv_set = 0;
			}
			up_write(&lli->lli_lsm_sem);
		}
		return;
	}

	if (lli->lli_default_lsm_md) {
		/* do nonthing if default lsm isn't changed */
		down_read(&lli->lli_lsm_sem);
		if (lli->lli_default_lsm_md &&
		    lsm_md_eq(lli->lli_default_lsm_md, md->default_lmv)) {
			up_read(&lli->lli_lsm_sem);
			return;
		}
		up_read(&lli->lli_lsm_sem);
	}

	down_write(&lli->lli_lsm_sem);
	if (lli->lli_default_lsm_md)
		lmv_free_memmd(lli->lli_default_lsm_md);
	lli->lli_default_lsm_md = md->default_lmv;
	lli->lli_default_lmv_set = 1;
	lsm_md_dump(D_INODE, md->default_lmv);
	md->default_lmv = NULL;
	up_write(&lli->lli_lsm_sem);
}

static int ll_update_lsm_md(struct inode *inode, struct lustre_md *md)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lmv_stripe_md *lsm = md->lmv;
	struct cl_attr	*attr;
	int rc = 0;

	LASSERT(S_ISDIR(inode->i_mode));
	CDEBUG(D_INODE, "update lsm %p of " DFID "\n", lli->lli_lsm_md,
	       PFID(ll_inode2fid(inode)));

	/* update default LMV */
	if (md->default_lmv)
		ll_update_default_lsm_md(inode, md);

	/* after dir migration/restripe, a stripe may be turned into a
	 * directory, in this case, zero out its lli_pfid.
	 */
	if (unlikely(fid_is_norm(&lli->lli_pfid)))
		fid_zero(&lli->lli_pfid);

	/*
	 * no striped information from request, lustre_md from req does not
	 * include stripeEA, see ll_md_setattr()
	 */
	if (!lsm)
		return 0;

	/*
	 * normally dir layout doesn't change, only take read lock to check
	 * that to avoid blocking other MD operations.
	 */
	down_read(&lli->lli_lsm_sem);

	/* some current lookup initialized lsm, and unchanged */
	if (lli->lli_lsm_md && lsm_md_eq(lli->lli_lsm_md, lsm))
		goto unlock;

	/* if dir layout doesn't match, check whether version is increased,
	 * which means layout is changed, this happens in dir split/merge and
	 * lfsck.
	 *
	 * foreign LMV should not change.
	 */
	if (lli->lli_lsm_md && lmv_dir_striped(lli->lli_lsm_md) &&
	    lsm->lsm_md_layout_version <=
	    lli->lli_lsm_md->lsm_md_layout_version) {
		CERROR("%s: " DFID " dir layout mismatch:\n",
		       ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid));
		lsm_md_dump(D_ERROR, lli->lli_lsm_md);
		lsm_md_dump(D_ERROR, lsm);
		rc = -EINVAL;
		goto unlock;
	}

	up_read(&lli->lli_lsm_sem);
	down_write(&lli->lli_lsm_sem);
	/* clear existing lsm */
	if (lli->lli_lsm_md) {
		lmv_free_memmd(lli->lli_lsm_md);
		lli->lli_lsm_md = NULL;
	}

	rc = ll_init_lsm_md(inode, md);
	up_write(&lli->lli_lsm_sem);

	if (rc)
		return rc;

	/* set md->lmv to NULL, so the following free lustre_md will not free
	 * this lsm.
	 */
	md->lmv = NULL;

	/* md_merge_attr() may take long, since lsm is already set, switch to
	 * read lock.
	 */
	down_read(&lli->lli_lsm_sem);

	if (!lmv_dir_striped(lli->lli_lsm_md))
		goto unlock;

	attr = kzalloc(sizeof(*attr), GFP_NOFS);
	if (!attr) {
		rc = -ENOMEM;
		goto unlock;
	}

	/* validate the lsm */
	rc = md_merge_attr(ll_i2mdexp(inode), lli->lli_lsm_md, attr,
			   ll_md_blocking_ast);
	if (!rc) {
		if (md->body->mbo_valid & OBD_MD_FLNLINK)
			md->body->mbo_nlink = attr->cat_nlink;
		if (md->body->mbo_valid & OBD_MD_FLSIZE)
			md->body->mbo_size = attr->cat_size;
		if (md->body->mbo_valid & OBD_MD_FLATIME)
			md->body->mbo_atime = attr->cat_atime;
		if (md->body->mbo_valid & OBD_MD_FLCTIME)
			md->body->mbo_ctime = attr->cat_ctime;
		if (md->body->mbo_valid & OBD_MD_FLMTIME)
			md->body->mbo_mtime = attr->cat_mtime;
	}

	kfree(attr);
unlock:
	up_read(&lli->lli_lsm_sem);

	return rc;
}

void ll_clear_inode(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);

	if (S_ISDIR(inode->i_mode)) {
		/* these should have been cleared in ll_file_release */
		LASSERT(!lli->lli_opendir_key);
		LASSERT(!lli->lli_sai);
		LASSERT(lli->lli_opendir_pid == 0);
	} else {
		pcc_inode_free(inode);
	}

	md_null_inode(sbi->ll_md_exp, ll_inode2fid(inode));

	LASSERT(!lli->lli_open_fd_write_count);
	LASSERT(!lli->lli_open_fd_read_count);
	LASSERT(!lli->lli_open_fd_exec_count);

	if (lli->lli_mds_write_och)
		ll_md_real_close(inode, FMODE_WRITE);
	if (lli->lli_mds_exec_och)
		ll_md_real_close(inode, FMODE_EXEC);
	if (lli->lli_mds_read_och)
		ll_md_real_close(inode, FMODE_READ);

	if (S_ISLNK(inode->i_mode)) {
		kfree(lli->lli_symlink_name);
		lli->lli_symlink_name = NULL;
	}

	ll_xattr_cache_destroy(inode);

	lli_clear_acl(lli);
	lli->lli_inode_magic = LLI_INODE_DEAD;

	if (S_ISDIR(inode->i_mode))
		ll_dir_clear_lsm_md(inode);
	if (S_ISREG(inode->i_mode) && !is_bad_inode(inode))
		LASSERT(list_empty(&lli->lli_agl_list));

	/*
	 * XXX This has to be done before lsm is freed below, because
	 * cl_object still uses inode lsm.
	 */
	cl_inode_fini(inode);

	fscrypt_put_encryption_info(inode);
}

static int ll_md_setattr(struct dentry *dentry, struct md_op_data *op_data)
{
	struct lustre_md md;
	struct inode *inode = d_inode(dentry);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *request = NULL;
	int rc, ia_valid;

	op_data = ll_prep_md_op_data(op_data, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		return PTR_ERR(op_data);

	/* If this is a chgrp of a regular file, we want to reserve enough
	 * quota to cover the entire file size.
	 */
	if (S_ISREG(inode->i_mode) && op_data->op_attr.ia_valid & ATTR_GID &&
	    from_kgid(&init_user_ns, op_data->op_attr.ia_gid) !=
	    from_kgid(&init_user_ns, inode->i_gid)) {
		op_data->op_xvalid |= OP_XVALID_BLOCKS;
		op_data->op_attr_blocks = inode->i_blocks;
	}

	rc = md_setattr(sbi->ll_md_exp, op_data, NULL, 0, &request);
	if (rc) {
		ptlrpc_req_finished(request);
		if (rc == -ENOENT) {
			clear_nlink(inode);
			/* Unlinked special device node? Or just a race?
			 * Pretend we did everything.
			 */
			if (!S_ISREG(inode->i_mode) &&
			    !S_ISDIR(inode->i_mode)) {
				ia_valid = op_data->op_attr.ia_valid;
				op_data->op_attr.ia_valid &= ~TIMES_SET_FLAGS;
				rc = simple_setattr(dentry, &op_data->op_attr);
				op_data->op_attr.ia_valid = ia_valid;
			}
		} else if (rc != -EPERM && rc != -EACCES && rc != -ETXTBSY) {
			CERROR("md_setattr fails: rc = %d\n", rc);
		}
		return rc;
	}

	rc = md_get_lustre_md(sbi->ll_md_exp, &request->rq_pill, sbi->ll_dt_exp,
			      sbi->ll_md_exp, &md);
	if (rc) {
		ptlrpc_req_finished(request);
		return rc;
	}

	ia_valid = op_data->op_attr.ia_valid;
	/* inode size will be in cl_setattr_ost, can't do it now since dirty
	 * cache is not cleared yet.
	 */
	op_data->op_attr.ia_valid &= ~(TIMES_SET_FLAGS | ATTR_SIZE);
	if (S_ISREG(inode->i_mode))
		inode_lock(inode);
	rc = simple_setattr(dentry, &op_data->op_attr);
	if (S_ISREG(inode->i_mode))
		inode_unlock(inode);
	op_data->op_attr.ia_valid = ia_valid;

	rc = ll_update_inode(inode, &md);
	ptlrpc_req_finished(request);

	return rc;
}

/**
 * Zero portion of page that is part of @inode.
 * This implies, if necessary:
 * - taking cl_lock on range corresponding to concerned page
 * - grabbing vm page
 * - associating cl_page
 * - proceeding to clio read
 * - zeroing range in page
 * - proceeding to cl_page flush
 * - releasing cl_lock
 *
 * @inode	inode
 * @inde	page index
 * @offset	offset in page to start zero from
 * @len	len to zero
 *
 * Return:	0 on success
 *		errno on failure
 */
int ll_io_zero_page(struct inode *inode, pgoff_t index, pgoff_t offset,
		    unsigned int len)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *clob = lli->lli_clob;
	u16 refcheck;
	struct lu_env *env = NULL;
	struct cl_io *io = NULL;
	struct cl_page *clpage = NULL;
	struct page *vmpage = NULL;
	unsigned int from = index << PAGE_SHIFT;
	struct cl_lock *lock = NULL;
	struct cl_lock_descr *descr = NULL;
	struct cl_2queue *queue = NULL;
	struct cl_sync_io *anchor = NULL;
	bool holdinglock = false;
	int rc;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	io = vvp_env_thread_io(env);
	io->ci_obj = clob;
	rc = cl_io_rw_init(env, io, CIT_WRITE, from, PAGE_SIZE);
	if (rc)
		goto putenv;

	lock = vvp_env_lock(env);
	descr = &lock->cll_descr;
	descr->cld_obj = io->ci_obj;
	descr->cld_start = from >> PAGE_SHIFT;
	descr->cld_end = (from + PAGE_SIZE - 1) >> PAGE_SHIFT;
	descr->cld_mode = CLM_WRITE;
	descr->cld_enq_flags = CEF_MUST | CEF_NONBLOCK;

	/* request lock for page */
	rc = cl_lock_request(env, io, lock);
	/* -ECANCELED indicates a matching lock with a different extent
	 * was already present, and -EEXIST indicates a matching lock
	 * on exactly the same extent was already present.
	 * In both cases it means we are covered.
	 */
	if (rc == -ECANCELED || rc == -EEXIST)
		rc = 0;
	else if (rc < 0)
		goto iofini;
	else
		holdinglock = true;

	/* grab page */
	vmpage = grab_cache_page_nowait(inode->i_mapping, index);
	if (!vmpage) {
		rc = -EOPNOTSUPP;
		goto rellock;
	}

	if (!PageDirty(vmpage)) {
		/* associate cl_page */
		clpage = cl_page_find(env, clob, vmpage->index,
				      vmpage, CPT_CACHEABLE);
		if (IS_ERR(clpage)) {
			rc = PTR_ERR(clpage);
			goto pagefini;
		}

		cl_page_assume(env, io, clpage);
	}

	if (!PageUptodate(vmpage) && !PageDirty(vmpage) &&
	    !PageWriteback(vmpage)) {
		/* read page */
		/* Set PagePrivate2 to detect special case of empty page
		 * in osc_brw_fini_request().
		 * It is also used to tell ll_io_read_page() that we do not
		 * want the vmpage to be unlocked.
		 */
		SetPagePrivate2(vmpage);
		rc = ll_io_read_page(env, io, clpage, NULL);
		if (!PagePrivate2(vmpage)) {
			/* PagePrivate2 was cleared in osc_brw_fini_request()
			 * meaning we read an empty page. In this case, in order
			 * to avoid allocating unnecessary block in truncated
			 * file, we must not zero and write as below. Subsequent
			 * server-side truncate will handle things correctly.
			 */
			cl_page_unassume(env, io, clpage);
			rc = 0;
			goto clpfini;
		}
		ClearPagePrivate2(vmpage);
		if (rc)
			goto clpfini;
	}

	/* Thanks to PagePrivate2 flag, ll_io_read_page() did not unlock
	 * the vmpage, so we are good to proceed and zero range in page.
	 */
	zero_user(vmpage, offset, len);

	if (holdinglock && clpage) {
		/* explicitly write newly modified page */
		queue = &io->ci_queue;
		cl_2queue_init(queue);
		anchor = &vvp_env_info(env)->vti_anchor;
		cl_sync_io_init(anchor, 1);
		clpage->cp_sync_io = anchor;
		cl_page_list_add(&queue->c2_qin, clpage, true);
		rc = cl_io_submit_rw(env, io, CRT_WRITE, queue);
		if (rc)
			goto queuefini1;
		rc = cl_sync_io_wait(env, anchor, 0);
		if (rc)
			goto queuefini2;
		cl_page_assume(env, io, clpage);

queuefini2:
		cl_2queue_discard(env, io, queue);
queuefini1:
		cl_2queue_disown(env, queue);
		cl_2queue_fini(env, queue);
	}

clpfini:
	if (clpage)
		cl_page_put(env, clpage);
pagefini:
	unlock_page(vmpage);
	put_page(vmpage);
rellock:
	if (holdinglock)
		cl_lock_release(env, lock);
iofini:
	cl_io_fini(env, io);
putenv:
	if (env)
		cl_env_put(env, &refcheck);

	return rc;
}

/**
 * Get reference file from volatile file name.
 * Volatile file name may look like:
 * <parent>/LUSTRE_VOLATILE_HDR:<mdt_index>:<random>:fd=<fd>
 * where fd is opened descriptor of reference file.
 *
 * \param[in] volatile_name	volatile file name
 * \param[in] volatile_len	volatile file name length
 * \param[out] ref_file		pointer to struct file of reference file
 *
 * \retval 0		on success
 * \retval negative	errno on failure
 */
int volatile_ref_file(const char *volatile_name, int volatile_len,
		      struct file **ref_file)
{
	char *p, *q, *fd_str;
	int fd, rc;

	p = strnstr(volatile_name, ":fd=", volatile_len);
	if (!p || strlen(p + 4) == 0)
		return -EINVAL;

	q = strchrnul(p + 4, ':');
	fd_str = kstrndup(p + 4, q - p - 4, GFP_NOFS);
	if (!fd_str)
		return -ENOMEM;
	rc = kstrtouint(fd_str, 10, &fd);
	kfree(fd_str);
	if (rc)
		return -EINVAL;

	*ref_file = fget(fd);
	if (!(*ref_file))
		return -EINVAL;
	return 0;
}

/* If this inode has objects allocated to it (lsm != NULL), then the OST
 * object(s) determine the file size and mtime.  Otherwise, the MDS will
 * keep these values until such a time that objects are allocated for it.
 * We do the MDS operations first, as it is checking permissions for us.
 * We don't to the MDS RPC if there is nothing that we want to store there,
 * otherwise there is no harm in updating mtime/atime on the MDS if we are
 * going to do an RPC anyways.
 *
 * If we are doing a truncate, we will send the mtime and ctime updates
 * to the OST with the punch RPC, otherwise we do an explicit setattr RPC.
 * I don't believe it is possible to get e.g. ATTR_MTIME_SET and ATTR_SIZE
 * at the same time.
 *
 * In case of HSMimport, we only set attr on MDS.
 */
int ll_setattr_raw(struct dentry *dentry, struct iattr *attr,
		   enum op_xvalid xvalid, bool hsm_import)
{
	struct inode *inode = d_inode(dentry);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct md_op_data *op_data = NULL;
	ktime_t kstart = ktime_get();
	int rc = 0;

	CDEBUG(D_VFSTRACE, "%s: setattr inode " DFID "(%p) from %llu to %llu, valid %x, hsm_import %d\n",
	       ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid), inode,
	       i_size_read(inode), attr->ia_size, attr->ia_valid, hsm_import);

	if (attr->ia_valid & ATTR_SIZE) {
		/* Check new size against VFS/VM file size limit and rlimit */
		rc = inode_newsize_ok(inode, attr->ia_size);
		if (rc)
			return rc;

		/* The maximum Lustre file size is variable, based on the
		 * OST maximum object size and number of stripes.  This
		 * needs another check in addition to the VFS check above.
		 */
		if (attr->ia_size > ll_file_maxbytes(inode)) {
			CDEBUG(D_INODE, "file " DFID " too large %llu > %llu\n",
			       PFID(&lli->lli_fid), attr->ia_size,
			       ll_file_maxbytes(inode));
			return -EFBIG;
		}

		attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
	}

	/* POSIX: check before ATTR_*TIME_SET set (from setattr_prepare) */
	if (attr->ia_valid & TIMES_SET_FLAGS) {
		if ((!uid_eq(current_fsuid(), inode->i_uid)) &&
		    !capable(CAP_FOWNER))
			return -EPERM;
	}

	/* We mark all of the fields "set" so MDS/OST does not re-set them */
	if (!(xvalid & OP_XVALID_CTIME_SET) &&
	    attr->ia_valid & ATTR_CTIME) {
		attr->ia_ctime = current_time(inode);
		xvalid |= OP_XVALID_CTIME_SET;
	}
	if (!(attr->ia_valid & ATTR_ATIME_SET) &&
	    (attr->ia_valid & ATTR_ATIME)) {
		attr->ia_atime = current_time(inode);
		attr->ia_valid |= ATTR_ATIME_SET;
	}
	if (!(attr->ia_valid & ATTR_MTIME_SET) &&
	    (attr->ia_valid & ATTR_MTIME)) {
		attr->ia_mtime = current_time(inode);
		attr->ia_valid |= ATTR_MTIME_SET;
	}

	if (attr->ia_valid & (ATTR_MTIME | ATTR_CTIME))
		CDEBUG(D_INODE, "setting mtime %lld, ctime %lld, now = %lld\n",
		       attr->ia_mtime.tv_sec, attr->ia_ctime.tv_sec,
		       (s64)ktime_get_real_seconds());

	if (S_ISREG(inode->i_mode))
		inode_unlock(inode);

	/*
	 * We always do an MDS RPC, even if we're only changing the size;
	 * only the MDS knows whether truncate() should fail with -ETXTBUSY
	 */
	op_data = kzalloc(sizeof(*op_data), GFP_NOFS);
	if (!op_data) {
		rc = -ENOMEM;
		goto out;
	}

	if (!hsm_import && attr->ia_valid & ATTR_SIZE) {
		/*
		 * If we are changing file size, file content is
		 * modified, flag it.
		 */
		xvalid |= OP_XVALID_OWNEROVERRIDE;
		op_data->op_bias |= MDS_DATA_MODIFIED;
		clear_bit(LLIF_DATA_MODIFIED, &lli->lli_flags);
	}

	if (attr->ia_valid & ATTR_FILE) {
		struct ll_file_data *fd = attr->ia_file->private_data;

		if (fd->fd_lease_och)
			op_data->op_bias |= MDS_TRUNC_KEEP_LEASE;
	}

	op_data->op_attr = *attr;
	op_data->op_xvalid = xvalid;

	rc = ll_md_setattr(dentry, op_data);
	if (rc)
		goto out;
	lli->lli_synced_to_mds = false;

	if (!S_ISREG(inode->i_mode) || hsm_import) {
		rc = 0;
		goto out;
	}

	if (attr->ia_valid & (ATTR_SIZE | ATTR_ATIME | ATTR_ATIME_SET |
			      ATTR_MTIME | ATTR_MTIME_SET | ATTR_CTIME) ||
	    xvalid & OP_XVALID_CTIME_SET) {
		bool cached = false;

		rc = pcc_inode_setattr(inode, attr, &cached);
		if (cached) {
			if (rc) {
				CERROR("%s: PCC inode "DFID" setattr failed: rc = %d\n",
				       ll_i2sbi(inode)->ll_fsname,
				       PFID(&lli->lli_fid), rc);
				goto out;
			}
		} else {
			unsigned int flags = 0;

			/* For truncate and utimes sending attributes to OSTs,
			 * setting mtime/atime to the past will be performed
			 * under PW [0:EOF] extent lock (new_size:EOF for
			 * truncate). It may seem excessive to send mtime/atime
			 * updates to OSTs when not setting times to past, but
			 * it is necessary due to possible time
			 * de-synchronization between MDT inode and OST objects
			 */
			if (S_ISREG(inode->i_mode) && IS_ENCRYPTED(inode)) {
				xvalid |= OP_XVALID_FLAGS;
				flags = LUSTRE_ENCRYPT_FL;
				/* Call to ll_io_zero_page is not necessary if
				 * truncating on PAGE_SIZE boundary, because
				 * whole pages will be wiped.
				 * In case of Direct IO, all we need is to set
				 * new size.
				 */
				if (attr->ia_valid & ATTR_SIZE &&
				    attr->ia_size & ~PAGE_MASK &&
				    !(attr->ia_valid & ATTR_FILE &&
				      attr->ia_file->f_flags & O_DIRECT)) {
					pgoff_t offset;

					offset = attr->ia_size & (PAGE_SIZE - 1);
					rc = ll_io_zero_page(inode,
							     attr->ia_size >> PAGE_SHIFT,
							     offset, PAGE_SIZE - offset);
					if (rc)
						goto out;
				}
				/* If encrypted volatile file without the key,
				 * we need to fetch size from reference file,
				 * and set it on OST objects. This happens when
				 * migrating or extending an encrypted file
				 * without the key.
				 */
				if (filename_is_volatile(dentry->d_name.name,
							 dentry->d_name.len,
							 NULL) &&
				    fscrypt_require_key(inode) == -ENOKEY) {
					struct file *ref_file;
					struct inode *ref_inode;
					struct ll_inode_info *ref_lli;
					struct cl_object *ref_obj;
					struct cl_attr ref_attr = { 0 };
					struct lu_env *env;
					u16 refcheck;

					rc = volatile_ref_file(
						dentry->d_name.name,
						dentry->d_name.len,
						&ref_file);
					if (rc)
						goto out;

					ref_inode = file_inode(ref_file);
					if (!ref_inode) {
						fput(ref_file);
						rc = -EINVAL;
						goto out;
					}

					env = cl_env_get(&refcheck);
					if (IS_ERR(env)) {
						rc = PTR_ERR(env);
						goto out;
					}

					ref_lli = ll_i2info(ref_inode);
					ref_obj = ref_lli->lli_clob;
					cl_object_attr_lock(ref_obj);
					rc = cl_object_attr_get(env, ref_obj,
								&ref_attr);
					cl_object_attr_unlock(ref_obj);
					cl_env_put(env, &refcheck);
					fput(ref_file);
					if (rc)
						goto out;

					attr->ia_valid |= ATTR_SIZE;
					attr->ia_size = ref_attr.cat_size;
				}
			}
			rc = cl_setattr_ost(ll_i2info(inode)->lli_clob,
					    attr, xvalid, flags);
		}
	}

	/*
	 * If the file was restored, it needs to set dirty flag.
	 *
	 * We've already sent MDS_DATA_MODIFIED flag in
	 * ll_md_setattr() for truncate. However, the MDT refuses to
	 * set the HS_DIRTY flag on released files, so we have to set
	 * it again if the file has been restored. Please check how
	 * LLIF_DATA_MODIFIED is set in vvp_io_setattr_fini().
	 *
	 * Please notice that if the file is not released, the previous
	 * MDS_DATA_MODIFIED has taken effect and usually
	 * LLIF_DATA_MODIFIED is not set(see vvp_io_setattr_fini()).
	 * This way we can save an RPC for common open + trunc
	 * operation.
	 */
	if (test_and_clear_bit(LLIF_DATA_MODIFIED, &lli->lli_flags)) {
		struct hsm_state_set hss = {
			.hss_valid = HSS_SETMASK,
			.hss_setmask = HS_DIRTY,
		};
		int rc2;

		rc2 = ll_hsm_state_set(inode, &hss);
		/*
		 * truncate and write can happen at the same time, so that
		 * the file can be set modified even though the file is not
		 * restored from released state, and ll_hsm_state_set() is
		 * not applicable for the file, and rc2 < 0 is normal in this
		 * case.
		 */
		if (rc2 < 0)
			CDEBUG(D_INFO, DFID "HSM set dirty failed: rc2 = %d\n",
			       PFID(ll_inode2fid(inode)), rc2);
	}

out:
	if (op_data)
		ll_finish_md_op_data(op_data);

	if (S_ISREG(inode->i_mode)) {
		inode_lock(inode);
		if ((attr->ia_valid & ATTR_SIZE) && !hsm_import)
			inode_dio_wait(inode);
		/* Once we've got the i_mutex, it's safe to set the S_NOSEC
		 * flag.  ll_update_inode (called from ll_md_setattr), clears
		 * inode flags, so there is a gap where S_NOSEC is not set.
		 * This can cause a writer to take the i_mutex unnecessarily,
		 * but this is safe to do and should be rare.
		 */
		inode_has_no_xattr(inode);
	}

	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(inode), attr->ia_valid & ATTR_SIZE ?
					LPROC_LL_TRUNC : LPROC_LL_SETATTR,
				   ktime_us_delta(ktime_get(), kstart));

	return rc;
}

int ll_setattr(struct dentry *de, struct iattr *attr)
{
	int mode = d_inode(de)->i_mode;
	enum op_xvalid xvalid = 0;
	int rc;

	rc = fscrypt_prepare_setattr(de, attr);
	if (rc)
		return rc;

	if ((attr->ia_valid & (ATTR_CTIME | ATTR_SIZE | ATTR_MODE)) ==
			      (ATTR_CTIME | ATTR_SIZE | ATTR_MODE))
		xvalid |= OP_XVALID_OWNEROVERRIDE;

	if (((attr->ia_valid & (ATTR_MODE | ATTR_FORCE | ATTR_SIZE)) ==
			       (ATTR_SIZE | ATTR_MODE)) &&
	    (((mode & S_ISUID) && !(attr->ia_mode & S_ISUID)) ||
	     (((mode & (S_ISGID | 0010)) == (S_ISGID | 0010)) &&
	      !(attr->ia_mode & S_ISGID))))
		attr->ia_valid |= ATTR_FORCE;

	if ((attr->ia_valid & ATTR_MODE) &&
	    (mode & S_ISUID) &&
	    !(attr->ia_mode & S_ISUID) &&
	    !(attr->ia_valid & ATTR_KILL_SUID))
		attr->ia_valid |= ATTR_KILL_SUID;

	if ((attr->ia_valid & ATTR_MODE) &&
	    ((mode & (S_ISGID | 0010)) == (S_ISGID | 0010)) &&
	    !(attr->ia_mode & S_ISGID) &&
	    !(attr->ia_valid & ATTR_KILL_SGID))
		attr->ia_valid |= ATTR_KILL_SGID;

	return ll_setattr_raw(de, attr, xvalid, false);
}

int ll_statfs_internal(struct ll_sb_info *sbi, struct obd_statfs *osfs,
		       u32 flags)
{
	struct obd_statfs obd_osfs = { 0 };
	time64_t max_age;
	int rc;

	max_age = ktime_get_seconds() - sbi->ll_statfs_max_age;

	if (test_bit(LL_SBI_LAZYSTATFS, sbi->ll_flags))
		flags |= OBD_STATFS_NODELAY;

	rc = obd_statfs(NULL, sbi->ll_md_exp, osfs, max_age, flags);
	if (rc)
		return rc;

	osfs->os_type = LL_SUPER_MAGIC;

	CDEBUG(D_SUPER, "MDC blocks %llu/%llu objects %llu/%llu\n",
	       osfs->os_bavail, osfs->os_blocks, osfs->os_ffree,
	       osfs->os_files);

	if (osfs->os_state & OS_STATFS_SUM)
		goto out;

	rc = obd_statfs(NULL, sbi->ll_dt_exp, &obd_osfs, max_age, flags);
	if (rc) {
		/* Possibly a filesystem with no OSTs.  Report MDT totals. */
		rc = 0;
		goto out;
	}

	CDEBUG(D_SUPER, "OSC blocks %llu/%llu objects %llu/%llu\n",
	       obd_osfs.os_bavail, obd_osfs.os_blocks, obd_osfs.os_ffree,
	       obd_osfs.os_files);

	osfs->os_bsize = obd_osfs.os_bsize;
	osfs->os_blocks = obd_osfs.os_blocks;
	osfs->os_bfree = obd_osfs.os_bfree;
	osfs->os_bavail = obd_osfs.os_bavail;

	/* If we have _some_ OSTs, but don't have as many free objects on the
	 * OSTs as inodes on the MDTs, reduce the reported number of inodes
	 * to compensate, so that the "inodes in use" number is correct.
	 * This should be kept in sync with lod_statfs() behaviour.
	 */
	if (obd_osfs.os_files && obd_osfs.os_ffree < osfs->os_ffree) {
		osfs->os_files = (osfs->os_files - osfs->os_ffree) +
				 obd_osfs.os_ffree;
		osfs->os_ffree = obd_osfs.os_ffree;
	}

out:
	return rc;
}

static int ll_statfs_project(struct inode *inode, struct kstatfs *sfs)
{
	struct if_quotactl qctl = {
		.qc_cmd = LUSTRE_Q_GETQUOTA,
		.qc_type = PRJQUOTA,
		.qc_valid = QC_GENERAL,
	};
	u64 limit, curblock;
	int ret;

	qctl.qc_id = ll_i2info(inode)->lli_projid;
	ret = quotactl_ioctl(inode->i_sb, &qctl);
	if (ret) {
		/* ignore errors if project ID does not have
		 * a quota limit or feature unsupported.
		 */
		if (ret == -ESRCH || ret == -EOPNOTSUPP)
			ret = 0;
		return ret;
	}

	limit = ((qctl.qc_dqblk.dqb_bsoftlimit ?
		 qctl.qc_dqblk.dqb_bsoftlimit :
		 qctl.qc_dqblk.dqb_bhardlimit) * 1024) / sfs->f_bsize;
	if (limit && sfs->f_blocks > limit) {
		curblock = (qctl.qc_dqblk.dqb_curspace +
			    sfs->f_bsize - 1) / sfs->f_bsize;
		sfs->f_blocks = limit;
		sfs->f_bavail =
			(sfs->f_blocks > curblock) ?
			(sfs->f_blocks - curblock) : 0;
		sfs->f_bfree = sfs->f_bavail;
	}

	limit = qctl.qc_dqblk.dqb_isoftlimit ?
		qctl.qc_dqblk.dqb_isoftlimit :
		qctl.qc_dqblk.dqb_ihardlimit;
	if (limit && sfs->f_files > limit) {
		sfs->f_files = limit;
		sfs->f_ffree = (sfs->f_files >
			qctl.qc_dqblk.dqb_curinodes) ?
			(sfs->f_files - qctl.qc_dqblk.dqb_curinodes) : 0;
	}

	return 0;
}

int ll_statfs(struct dentry *de, struct kstatfs *sfs)
{
	struct super_block *sb = de->d_sb;
	struct obd_statfs osfs;
	u64 fsid = huge_encode_dev(sb->s_dev);
	ktime_t kstart = ktime_get();
	int rc;

	CDEBUG(D_VFSTRACE, "VFS Op:sb=%s (%p)\n", sb->s_id, sb);

	/* Some amount of caching on the client is allowed */
	rc = ll_statfs_internal(ll_s2sbi(sb), &osfs, OBD_STATFS_SUM);
	if (rc)
		return rc;

	statfs_unpack(sfs, &osfs);

	/* We need to downshift for all 32-bit kernels, because we can't
	 * tell if the kernel is being called via sys_statfs64() or not.
	 * Stop before overflowing f_bsize - in which case it is better
	 * to just risk EOVERFLOW if caller is using old sys_statfs().
	 */
	if (sizeof(long) < 8) {
		while (osfs.os_blocks > ~0UL && sfs->f_bsize < 0x40000000) {
			sfs->f_bsize <<= 1;

			osfs.os_blocks >>= 1;
			osfs.os_bfree >>= 1;
			osfs.os_bavail >>= 1;
		}
	}

	sfs->f_blocks = osfs.os_blocks;
	sfs->f_bfree = osfs.os_bfree;
	sfs->f_bavail = osfs.os_bavail;
	sfs->f_fsid.val[0] = (u32)fsid;
	sfs->f_fsid.val[1] = (u32)(fsid >> 32);
	if (ll_i2info(de->d_inode)->lli_projid &&
	    test_bit(LLIF_PROJECT_INHERIT, &ll_i2info(de->d_inode)->lli_flags))
		return ll_statfs_project(de->d_inode, sfs);

	ll_stats_ops_tally(ll_s2sbi(sb), LPROC_LL_STATFS,
			   ktime_us_delta(ktime_get(), kstart));

	return 0;
}

void ll_inode_size_lock(struct inode *inode)
{
	struct ll_inode_info *lli;

	LASSERT(!S_ISDIR(inode->i_mode));

	lli = ll_i2info(inode);
	mutex_lock(&lli->lli_size_mutex);
}

void ll_inode_size_unlock(struct inode *inode)
{
	struct ll_inode_info *lli;

	lli = ll_i2info(inode);
	mutex_unlock(&lli->lli_size_mutex);
}

int ll_inode_size_trylock(struct inode *inode)
{
	struct ll_inode_info *lli;

	LASSERT(!S_ISDIR(inode->i_mode));

	lli = ll_i2info(inode);
	return mutex_trylock(&lli->lli_size_mutex);
}

void ll_update_inode_flags(struct inode *inode, unsigned int ext_flags)
{
	struct ll_inode_info *lli = ll_i2info(inode);

	/* do not clear encryption flag */
	ext_flags |= ll_inode_to_ext_flags(inode->i_flags) & LUSTRE_ENCRYPT_FL;
	inode->i_flags = ll_ext_to_inode_flags(ext_flags);
	if (ext_flags & LUSTRE_PROJINHERIT_FL)
		set_bit(LLIF_PROJECT_INHERIT, &lli->lli_flags);
	else
		clear_bit(LLIF_PROJECT_INHERIT, &lli->lli_flags);
}

int ll_update_inode(struct inode *inode, struct lustre_md *md)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct mdt_body *body = md->body;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	bool api32;
	int rc = 0;

	if (body->mbo_valid & OBD_MD_FLEASIZE) {
		rc = cl_file_inode_init(inode, md);
		if (rc)
			return rc;
	}

	if (S_ISDIR(inode->i_mode)) {
		rc = ll_update_lsm_md(inode, md);
		if (rc)
			return rc;
	}

	if (body->mbo_valid & OBD_MD_FLACL)
		lli_replace_acl(lli, md);

	api32 = test_bit(LL_SBI_32BIT_API, sbi->ll_flags);
	inode->i_ino = cl_fid_build_ino(&body->mbo_fid1, api32);
	inode->i_generation = cl_fid_build_gen(&body->mbo_fid1);

	if (body->mbo_valid & OBD_MD_FLATIME) {
		if (body->mbo_atime > inode->i_atime.tv_sec)
			inode->i_atime.tv_sec = body->mbo_atime;
		lli->lli_atime = body->mbo_atime;
	}
	if (body->mbo_valid & OBD_MD_FLMTIME) {
		if (body->mbo_mtime > inode->i_mtime.tv_sec) {
			CDEBUG(D_INODE,
			       "setting ino %lu mtime from %lld to %llu\n",
			       inode->i_ino, inode->i_mtime.tv_sec,
			       body->mbo_mtime);
			inode->i_mtime.tv_sec = body->mbo_mtime;
		}
		lli->lli_mtime = body->mbo_mtime;
	}
	if (body->mbo_valid & OBD_MD_FLCTIME) {
		if (body->mbo_ctime > inode->i_ctime.tv_sec)
			inode->i_ctime.tv_sec = body->mbo_ctime;
		lli->lli_ctime = body->mbo_ctime;
	}

	if (body->mbo_valid & OBD_MD_FLBTIME)
		lli->lli_btime = body->mbo_btime;

	/* Clear i_flags to remove S_NOSEC before permissions are updated */
	if (body->mbo_valid & OBD_MD_FLFLAGS)
		ll_update_inode_flags(inode, body->mbo_flags);

	if (body->mbo_valid & OBD_MD_FLMODE)
		inode->i_mode = (inode->i_mode & S_IFMT) |
				(body->mbo_mode & ~S_IFMT);
	if (body->mbo_valid & OBD_MD_FLTYPE)
		inode->i_mode = (inode->i_mode & ~S_IFMT) |
				(body->mbo_mode & S_IFMT);
	LASSERT(inode->i_mode != 0);
	if (body->mbo_valid & OBD_MD_FLUID)
		inode->i_uid = make_kuid(&init_user_ns, body->mbo_uid);
	if (body->mbo_valid & OBD_MD_FLGID)
		inode->i_gid = make_kgid(&init_user_ns, body->mbo_gid);
	if (body->mbo_valid & OBD_MD_FLPROJID)
		lli->lli_projid = body->mbo_projid;
	if (body->mbo_valid & OBD_MD_FLNLINK) {
		spin_lock(&inode->i_lock);
		set_nlink(inode, body->mbo_nlink);
		spin_unlock(&inode->i_lock);
	}
	if (body->mbo_valid & OBD_MD_FLRDEV)
		inode->i_rdev = old_decode_dev(body->mbo_rdev);

	if (body->mbo_valid & OBD_MD_FLID) {
		/* FID shouldn't be changed! */
		if (fid_is_sane(&lli->lli_fid)) {
			LASSERTF(lu_fid_eq(&lli->lli_fid, &body->mbo_fid1),
				 "Trying to change FID " DFID " to the " DFID ", inode " DFID "(%p)\n",
				 PFID(&lli->lli_fid), PFID(&body->mbo_fid1),
				 PFID(ll_inode2fid(inode)), inode);
		} else {
			lli->lli_fid = body->mbo_fid1;
		}
	}

	LASSERT(fid_seq(&lli->lli_fid) != 0);

	/* In case of encrypted file without the key, please do not lose
	 * clear text size stored into lli_lazysize in ll_merge_attr(),
	 * we will need it in ll_prepare_close().
	 */
	if (lli->lli_attr_valid & OBD_MD_FLLAZYSIZE && lli->lli_lazysize &&
	    fscrypt_require_key(inode) == -ENOKEY)
		lli->lli_attr_valid = body->mbo_valid | OBD_MD_FLLAZYSIZE;
	else
		lli->lli_attr_valid = body->mbo_valid;
	if (body->mbo_valid & OBD_MD_FLSIZE) {
		i_size_write(inode, body->mbo_size);

		CDEBUG(D_VFSTRACE, "inode=" DFID ", updating i_size %llu\n",
		       PFID(ll_inode2fid(inode)),
		       (unsigned long long)body->mbo_size);

		if (body->mbo_valid & OBD_MD_FLBLOCKS)
			inode->i_blocks = body->mbo_blocks;
	} else {
		if (body->mbo_valid & OBD_MD_FLLAZYSIZE)
			lli->lli_lazysize = body->mbo_size;
		if (body->mbo_valid & OBD_MD_FLLAZYBLOCKS)
			lli->lli_lazyblocks = body->mbo_blocks;
	}

	if (body->mbo_valid & OBD_MD_TSTATE) {
		/* Set LLIF_FILE_RESTORING if restore ongoing and
		 * clear it when done to ensure to start again
		 * glimpsing updated attrs
		 */
		if (body->mbo_t_state & MS_RESTORE)
			set_bit(LLIF_FILE_RESTORING, &lli->lli_flags);
		else
			clear_bit(LLIF_FILE_RESTORING, &lli->lli_flags);
	}

	return 0;
}

/* child default LMV is inherited from parent */
static inline bool ll_default_lmv_inherited(struct lmv_stripe_md *pdmv,
					    struct lmv_stripe_md *cdmv)
{
	if (!pdmv || !cdmv)
		return false;

	if (pdmv->lsm_md_magic != cdmv->lsm_md_magic ||
	    pdmv->lsm_md_stripe_count != cdmv->lsm_md_stripe_count ||
	    pdmv->lsm_md_master_mdt_index != cdmv->lsm_md_master_mdt_index ||
	    pdmv->lsm_md_hash_type != cdmv->lsm_md_hash_type)
		return false;

	if (cdmv->lsm_md_max_inherit !=
	    lmv_inherit_next(pdmv->lsm_md_max_inherit))
		return false;

	if (cdmv->lsm_md_max_inherit_rr !=
	    lmv_inherit_rr_next(pdmv->lsm_md_max_inherit_rr))
		return false;

	return true;
}

/* if default LMV is implicitly inherited, subdir default LMV is maintained on
 * client side.
 */
int ll_dir_default_lmv_inherit(struct inode *dir, struct inode *inode)
{
	struct ll_inode_info *plli = ll_i2info(dir);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lmv_stripe_md *plsm;
	struct lmv_stripe_md *lsm;
	int rc = 0;

	/* ROOT default LMV is not inherited */
	if (is_root_inode(dir) ||
	    !(exp_connect_flags2(ll_i2mdexp(dir)) &
				 OBD_CONNECT2_DMV_IMP_INHERIT))
		return 0;

	/* nothing to do if no default LMV on both */
	if (!plli->lli_default_lsm_md && !lli->lli_default_lsm_md)
		return 0;

	/* subdir default LMV comes from disk */
	if (lli->lli_default_lsm_md && lli->lli_default_lmv_set)
		return 0;

	/* delete subdir default LMV if parent's is deleted or becomes
	 * uninheritable.
	 */
	down_read(&plli->lli_lsm_sem);
	plsm = plli->lli_default_lsm_md;
	if (!plsm || !lmv_is_inheritable(plsm->lsm_md_max_inherit)) {
		if (lli->lli_default_lsm_md && !lli->lli_default_lmv_set) {
			down_write(&lli->lli_lsm_sem);
			if (lli->lli_default_lsm_md &&
			    !lli->lli_default_lmv_set) {
				lmv_free_memmd(lli->lli_default_lsm_md);
				lli->lli_default_lsm_md = NULL;
				lli->lli_inherit_depth = 0;
			}
			up_write(&lli->lli_lsm_sem);
		}
		rc = 0;
		goto unlock_parent;
	}

	/* do nothing if inherited LMV is unchanged */
	if (lli->lli_default_lsm_md) {
		rc = 1;
		down_read(&lli->lli_lsm_sem);
		if (!lli->lli_default_lmv_set)
			rc = lsm_md_inherited(plsm, lli->lli_default_lsm_md);
		up_read(&lli->lli_lsm_sem);
		if (rc == 1) {
			rc = 0;
			goto unlock_parent;
		}
	}

	/* inherit default LMV */
	down_write(&lli->lli_lsm_sem);
	if (lli->lli_default_lsm_md) {
		/* checked above, but in case of race, check again with lock */
		if (lli->lli_default_lmv_set) {
			rc = 0;
			goto unlock_child;
		}
		/* always update subdir default LMV in case parent's changed */
		lsm = lli->lli_default_lsm_md;
	} else {
		lsm = kzalloc(sizeof(*lsm), GFP_NOFS);
		if (!lsm) {
			rc = -ENOMEM;
			goto unlock_child;
		}
		lli->lli_default_lsm_md = lsm;
	}

	*lsm = *plsm;
	lsm->lsm_md_max_inherit = lmv_inherit_next(plsm->lsm_md_max_inherit);
	lsm->lsm_md_max_inherit_rr =
			lmv_inherit_rr_next(plsm->lsm_md_max_inherit_rr);
	lli->lli_inherit_depth = plli->lli_inherit_depth + 1;

	lsm_md_dump(D_INODE, lsm);

unlock_child:
	up_write(&lli->lli_lsm_sem);
unlock_parent:
	up_read(&plli->lli_lsm_sem);

	return rc;
}

enum lsm_sem_class {
	LSM_SEM_PARENT,
	LSM_SEM_CHILD,
};

/**
 * Update directory depth and default LMV
 *
 * Update directory depth to ROOT and inherit default LMV from parent if
 * parent's default LMV is inheritable. The default LMV set with command
 * "lfs setdirstripe -D ..." is stored on MDT, while the inherited default LMV
 * is generated at runtime on client side.
 *
 * \param[in]	dir	parent directory inode
 * \param[in]	de	dentry
 */
void ll_update_dir_depth_dmv(struct inode *dir, struct dentry *de)
{
	struct inode *inode = de->d_inode;
	struct ll_inode_info *plli;
	struct ll_inode_info *lli;

	LASSERT(S_ISDIR(inode->i_mode));
	if (inode == dir)
		return;

	plli = ll_i2info(dir);
	lli = ll_i2info(inode);
	lli->lli_dir_depth = plli->lli_dir_depth + 1;
	if (lli->lli_default_lsm_md && lli->lli_default_lmv_set) {
		if (plli->lli_default_lsm_md) {
			down_read_nested(&plli->lli_lsm_sem, LSM_SEM_PARENT);
			down_read_nested(&lli->lli_lsm_sem, LSM_SEM_CHILD);
			if (lsm_md_inherited(plli->lli_default_lsm_md,
					     lli->lli_default_lsm_md))
				lli->lli_inherit_depth =
					plli->lli_inherit_depth + 1;
			else
				/* in case parent default LMV changed */
				lli->lli_inherit_depth = 0;
			up_read(&lli->lli_lsm_sem);
			up_read(&plli->lli_lsm_sem);
		} else {
			/* in case parent default LMV deleted */
			lli->lli_inherit_depth = 0;
		}
	} else {
		ll_dir_default_lmv_inherit(dir, inode);
	}

	if (lli->lli_default_lsm_md)
		CDEBUG(D_INODE,
		       "%s "DFID" depth %hu %s default LMV inherit depth %hu\n",
		       de->d_name.name, PFID(&lli->lli_fid), lli->lli_dir_depth,
		       lli->lli_default_lmv_set ? "server" : "client",
		       lli->lli_inherit_depth);
}

void ll_truncate_inode_pages_final(struct inode *inode, struct cl_io *io)
{
	struct address_space *mapping = &inode->i_data;
	unsigned long nrpages;
	unsigned long flags;

	LASSERTF(io == NULL || inode_is_locked(inode), "io %p (type %d)\n",
		 io, io ? io->ci_type : 0);

	truncate_inode_pages_final(mapping);

	/* Workaround for LU-118: Note nrpages may not be totally updated when
	 * truncate_inode_pages() returns, as there can be a page in the process
	 * of deletion (inside __delete_from_page_cache()) in the specified
	 * range. Thus mapping->nrpages can be non-zero when this function
	 * returns even after truncation of the whole mapping.  Only do this if
	 * npages isn't already zero.
	 */
	nrpages = mapping->nrpages;
	if (nrpages) {
		xa_lock_irqsave(&mapping->i_pages, flags);
		nrpages = mapping->nrpages;
		xa_unlock_irqrestore(&mapping->i_pages, flags);
	} /* Workaround end */

	LASSERTF(nrpages == 0, "%s: inode="DFID"(%p) nrpages=%lu io %p (io_type %d), see https://jira.whamcloud.com/browse/LU-118\n",
		 ll_i2sbi(inode)->ll_fsname,
		 PFID(ll_inode2fid(inode)), inode, nrpages,
		 io, io  ? io->ci_type : 0);
}

int ll_read_inode2(struct inode *inode, void *opaque)
{
	struct lustre_md *md = opaque;
	struct ll_inode_info *lli = ll_i2info(inode);
	int rc;

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p)\n",
	       PFID(&lli->lli_fid), inode);

	/* Core attributes from the MDS first.  This is a new inode, and
	 * the VFS doesn't zero times in the core inode so we have to do
	 * it ourselves.  They will be overwritten by either MDS or OST
	 * attributes - we just need to make sure they aren't newer.
	 */
	inode->i_mtime.tv_sec = 0;
	inode->i_atime.tv_sec = 0;
	inode->i_ctime.tv_sec = 0;
	inode->i_rdev = 0;
	rc = ll_update_inode(inode, md);
	if (rc)
		return rc;

	/* OIDEBUG(inode); */

	if (S_ISREG(inode->i_mode)) {
		struct ll_sb_info *sbi = ll_i2sbi(inode);

		inode->i_op = &ll_file_inode_operations;
		inode->i_fop = sbi->ll_fop;
		inode->i_mapping->a_ops = (struct address_space_operations *)&ll_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ll_dir_inode_operations;
		inode->i_fop = &ll_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &ll_fast_symlink_inode_operations;
	} else {
		inode->i_op = &ll_special_inode_operations;

		init_special_inode(inode, inode->i_mode,
				   inode->i_rdev);
	}

	return 0;
}

void ll_delete_inode(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);

	if (S_ISREG(inode->i_mode) && lli->lli_clob) {
		/* It is last chance to write out dirty pages,
		 * otherwise we may lose data while umount.
		 *
		 * If i_nlink is 0 then just discard data. This is safe because
		 * local inode gets i_nlink 0 from server only for the last
		 * unlink, so that file is not opened somewhere else
		 */
		cl_sync_file_range(inode, 0, OBD_OBJECT_EOF, inode->i_nlink ?
				   CL_FSYNC_LOCAL : CL_FSYNC_DISCARD, 1);
	}

	ll_truncate_inode_pages_final(inode, NULL);
	ll_clear_inode(inode);
	clear_inode(inode);
}

/* ioctl commands shared between files and directories */
int ll_iocontrol(struct inode *inode, struct file *file,
		 unsigned int cmd, void __user *uarg)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	int rc = 0, flags = 0;

	switch (cmd) {
	case BLKSSZGET:
		rc = put_user(PAGE_SIZE, (int __user *)uarg);
		break;
	case LL_IOC_GETVERSION:
	case FS_IOC_GETVERSION:
		rc = put_user(inode->i_generation, (int __user *)uarg);
		break;
	case FS_IOC_GETFLAGS: {
		struct mdt_body *body;
		struct md_op_data *op_data;

		if (!access_ok(uarg, sizeof(int)))
			return -EFAULT;

		op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
					     LUSTRE_OPC_ANY, NULL);
		if (IS_ERR(op_data)) {
			rc = PTR_ERR(op_data);
			break;
		}
		op_data->op_valid = OBD_MD_FLFLAGS;
		rc = md_getattr(sbi->ll_md_exp, op_data, &req);
		ll_finish_md_op_data(op_data);
		if (rc) {
			CERROR("%s: failure inode " DFID ": rc = %d\n",
			       sbi->ll_md_exp->exp_obd->obd_name,
			       PFID(ll_inode2fid(inode)), rc);
			rc = -abs(rc);
			break;
		}

		body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);

		flags = body->mbo_flags;
		/* if Lustre specific LUSTRE_ENCRYPT_FL flag is set, also set
		 * ext4 equivalent to please lsattr and other e2fsprogs tools
		 */
		if (flags & LUSTRE_ENCRYPT_FL)
			flags |= STATX_ATTR_ENCRYPTED;

		ptlrpc_req_finished(req);

		rc = put_user(flags, (int __user *)uarg);
		break;
	}
	case FS_IOC_SETFLAGS: {
		struct md_op_data *op_data;
		struct cl_object *obj;
		struct iattr *attr;
		struct fsxattr fa = { 0 };

		if (get_user(flags, (int __user *)uarg)) {
			rc = -EFAULT;
			break;
		}

		fa.fsx_projid = ll_i2info(inode)->lli_projid;
		if (flags & LUSTRE_PROJINHERIT_FL)
			fa.fsx_xflags = FS_XFLAG_PROJINHERIT;

		rc = ll_ioctl_check_project(inode, fa.fsx_xflags,
					    fa.fsx_projid);
		if (rc)
			break;

		op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
					     LUSTRE_OPC_ANY, NULL);
		if (IS_ERR(op_data)) {
			rc = PTR_ERR(op_data);
			break;
		}

		op_data->op_attr_flags = flags;
		op_data->op_xvalid |= OP_XVALID_FLAGS;
		rc = md_setattr(sbi->ll_md_exp, op_data, NULL, 0, &req);
		ll_finish_md_op_data(op_data);
		ptlrpc_req_finished(req);
		if (rc)
			break;

		ll_update_inode_flags(inode, flags);

		obj = ll_i2info(inode)->lli_clob;
		if (!obj)
			break;

		attr = kzalloc(sizeof(*attr), GFP_NOFS);
		if (!attr) {
			rc = -ENOMEM;
			break;
		}

		rc = cl_setattr_ost(obj, attr, OP_XVALID_FLAGS, flags);
		kfree(attr);
		break;
	}
	case FS_IOC_FSGETXATTR:
		rc = ll_ioctl_fsgetxattr(inode, cmd, uarg);
		break;
	case FS_IOC_FSSETXATTR:
		rc = ll_ioctl_fssetxattr(inode, cmd, uarg);
		break;
	case LL_IOC_PROJECT:
		rc = ll_ioctl_project(file, cmd, uarg);
		break;
	case IOC_OBD_STATFS:
		rc = ll_obd_statfs(inode, uarg);
		break;
	case LL_IOC_GET_MDTIDX: {
		if (!access_ok(uarg, sizeof(rc)))
			return -EFAULT;

		rc = ll_get_mdt_idx(inode);
		if (rc < 0)
			break;

		if (put_user(rc, (int __user *)uarg))
			rc = -EFAULT;

		break;
	}
	case LL_IOC_FLUSHCTX:
		rc = ll_flush_ctx(inode);
		break;
#ifdef CONFIG_FS_ENCRYPTION
	case FS_IOC_ADD_ENCRYPTION_KEY:
		if (ll_sbi_has_encrypt(ll_i2sbi(inode)))
			rc = fscrypt_ioctl_add_key(file, uarg);
		else
			rc = -EOPNOTSUPP;
		break;
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
		if (ll_sbi_has_encrypt(ll_i2sbi(inode)))
			rc = fscrypt_ioctl_get_key_status(file, uarg);
		else
			rc = -EOPNOTSUPP;
		break;
	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
		if (ll_sbi_has_encrypt(ll_i2sbi(inode)))
			rc = fscrypt_ioctl_get_policy_ex(file, uarg);
		else
			rc = -EOPNOTSUPP;
		break;
	case FS_IOC_SET_ENCRYPTION_POLICY:
		if (ll_sbi_has_encrypt(ll_i2sbi(inode)))
			rc = fscrypt_ioctl_set_policy(file, uarg);
		else
			rc = -EOPNOTSUPP;
		break;
	case FS_IOC_REMOVE_ENCRYPTION_KEY:
		if (ll_sbi_has_encrypt(ll_i2sbi(inode)))
			rc = fscrypt_ioctl_remove_key(file, uarg);
		else
			rc = -EOPNOTSUPP;
		break;
	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
		if (ll_sbi_has_encrypt(ll_i2sbi(inode)))
			rc = fscrypt_ioctl_remove_key_all_users(file, uarg);
		else
			rc = -EOPNOTSUPP;
		break;
#endif
	case LL_IOC_GETPARENT:
		rc = ll_getparent(file, uarg);
		break;
	case LL_IOC_PATH2FID:
		if (copy_to_user(uarg, ll_inode2fid(inode),
				 sizeof(struct lu_fid)))
			rc = -EFAULT;
		break;
	case LL_IOC_UNLOCK_FOREIGN: {
		struct dentry *dentry = file_dentry(file);

		/* if not a foreign symlink do nothing */
		if (ll_foreign_is_removable(dentry, true)) {
			CDEBUG(D_INFO,
			       "prevent unlink of non-foreign file ("DFID")\n",
			       PFID(ll_inode2fid(inode)));
			rc = -EOPNOTSUPP;
		}
		break;
	}
	case OBD_IOC_FID2PATH:
		rc = ll_fid2path(inode, uarg);
		break;
#ifdef OBD_IOC_GETNAME_OLD
	case_OBD_IOC_DEPRECATED_FT(OBD_IOC_GETNAME_OLD,
				   sbi->ll_md_exp->exp_obd->obd_name, 2, 16);
#endif
	case OBD_IOC_GETDTNAME:
		fallthrough;
	case OBD_IOC_GETMDNAME:
		rc = ll_get_obd_name(inode, cmd, uarg);
		break;
	default:
		rc = ENOTTY;
		break;
	}

	return rc;
}

int ll_flush_ctx(struct inode *inode)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	CDEBUG(D_SEC, "flush context for user %d\n",
	       from_kuid(&init_user_ns, current_uid()));

	obd_set_info_async(NULL, sbi->ll_md_exp,
			   sizeof(KEY_FLUSH_CTX), KEY_FLUSH_CTX,
			   0, NULL, NULL);
	obd_set_info_async(NULL, sbi->ll_dt_exp,
			   sizeof(KEY_FLUSH_CTX), KEY_FLUSH_CTX,
			   0, NULL, NULL);
	return 0;
}

/* umount -f client means force down, don't save state */
void ll_umount_begin(struct super_block *sb)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct obd_device *obd;
	struct obd_ioctl_data *ioc_data;
	int cnt = 0;

	CDEBUG(D_VFSTRACE, "VFS Op: superblock %p count %d active %d\n", sb,
	       sb->s_count, atomic_read(&sb->s_active));

	obd = class_exp2obd(sbi->ll_md_exp);
	if (!obd) {
		CERROR("Invalid MDC connection handle %#llx\n",
		       sbi->ll_md_exp->exp_handle.h_cookie);
		return;
	}
	obd->obd_force = 1;

	obd = class_exp2obd(sbi->ll_dt_exp);
	if (!obd) {
		CERROR("Invalid LOV connection handle %#llx\n",
		       sbi->ll_dt_exp->exp_handle.h_cookie);
		return;
	}
	obd->obd_force = 1;

	ioc_data = kzalloc(sizeof(*ioc_data), GFP_NOFS);
	if (ioc_data) {
		obd_iocontrol(OBD_IOC_SET_ACTIVE, sbi->ll_md_exp,
			      sizeof(*ioc_data), ioc_data, NULL);

		obd_iocontrol(OBD_IOC_SET_ACTIVE, sbi->ll_dt_exp,
			      sizeof(*ioc_data), ioc_data, NULL);

		kfree(ioc_data);
	}

	/* Really, we'd like to wait until there are no requests outstanding,
	 * and then continue. For now, we just periodically checking for vfs
	 * to decrement mnt_cnt and hope to finish it within 10sec.
	 */
	while (cnt < 10 && !may_umount(sbi->ll_mnt.mnt)) {
		ssleep(1);
		cnt++;
	}
}

int ll_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	char *profilenm = get_profile_name(sb);
	int err;
	u32 read_only;

	if ((bool)(*flags & SB_RDONLY) != sb_rdonly(sb)) {
		read_only = *flags & SB_RDONLY;
		err = obd_set_info_async(NULL, sbi->ll_md_exp,
					 sizeof(KEY_READ_ONLY),
					 KEY_READ_ONLY, sizeof(read_only),
					 &read_only, NULL);
		if (err) {
			LCONSOLE_WARN("Failed to remount %s %s (%d)\n",
				      profilenm, read_only ?
				      "read-only" : "read-write", err);
			return err;
		}

		if (read_only)
			sb->s_flags |= SB_RDONLY;
		else
			sb->s_flags &= ~SB_RDONLY;

		if (test_bit(LL_SBI_VERBOSE, sbi->ll_flags))
			LCONSOLE_WARN("Remounted %s %s\n", profilenm,
				      read_only ?  "read-only" : "read-write");
	}
	return 0;
}

/**
 * Cleanup the open handle that is cached on MDT-side.
 *
 * For open case, the client side open handling thread may hit error
 * after the MDT grant the open. Under such case, the client should
 * send close RPC to the MDT as cleanup; otherwise, the open handle
 * on the MDT will be leaked there until the client umount or evicted.
 *
 * In further, if someone unlinked the file, because the open handle
 * holds the reference on such file/object, then it will block the
 * subsequent threads that want to locate such object via FID.
 *
 * @sb:		super block for this file-system
 * @open_req:	pointer to the original open request
 */
void ll_open_cleanup(struct super_block *sb, struct req_capsule *pill)
{
	struct mdt_body	*body;
	struct md_op_data *op_data;
	struct ptlrpc_request *close_req = NULL;
	struct obd_export *exp = ll_s2sbi(sb)->ll_md_exp;

	body = req_capsule_server_get(pill, &RMF_MDT_BODY);
	op_data = kzalloc(sizeof(*op_data), GFP_NOFS);
	if (!op_data)
		return;

	op_data->op_fid1 = body->mbo_fid1;
	op_data->op_open_handle = body->mbo_open_handle;
	op_data->op_mod_time = ktime_get_real_seconds();
	md_close(exp, op_data, NULL, &close_req);
	ptlrpc_req_finished(close_req);
	ll_finish_md_op_data(op_data);
}

/* set filesystem-wide default LMV for subdir mount if it's enabled on ROOT. */
static int ll_fileset_default_lmv_fixup(struct inode *inode,
					struct lustre_md *md)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	union lmv_mds_md *lmm = NULL;
	int size = 0;
	int rc;

	LASSERT(is_root_inode(inode));
	LASSERT(!fid_is_root(&sbi->ll_root_fid));
	LASSERT(!md->default_lmv);

	rc = ll_dir_get_default_layout(inode, (void **)&lmm, &size, &req,
				       OBD_MD_DEFAULT_MEA,
				       GET_DEFAULT_LAYOUT_ROOT);
	if (rc && rc != -ENODATA)
		goto out;

	rc = 0;
	if (lmm && size) {
		rc = md_unpackmd(sbi->ll_md_exp, &md->default_lmv, lmm, size);
		if (rc < 0)
			goto out;
		rc = 0;
	}
out:
	if (req)
		ptlrpc_req_finished(req);
	return rc;
}

int ll_prep_inode(struct inode **inode, struct req_capsule *pill,
		  struct super_block *sb, struct lookup_intent *it)
{
	struct ll_sb_info *sbi = NULL;
	struct lustre_md md = { NULL };
	bool default_lmv_deleted = false;
	int rc;

	LASSERT(*inode || sb);
	sbi = sb ? ll_s2sbi(sb) : ll_i2sbi(*inode);
	rc = md_get_lustre_md(sbi->ll_md_exp, pill, sbi->ll_dt_exp,
			      sbi->ll_md_exp, &md);
	if (rc)
		goto out;

	/*
	 * clear default_lmv only if intent_getattr reply doesn't contain it.
	 * but it needs to be done after iget, check this early because
	 * ll_update_lsm_md() may change md.
	 */
	if (it && (it->it_op & (IT_LOOKUP | IT_GETATTR)) &&
	    S_ISDIR(md.body->mbo_mode) && !md.default_lmv) {
		if (unlikely(*inode && is_root_inode(*inode) &&
			     !fid_is_root(&sbi->ll_root_fid))) {
			rc = ll_fileset_default_lmv_fixup(*inode, &md);
			if (rc)
				goto out;
		}

		if (!md.default_lmv)
			default_lmv_deleted = true;
	}

	if (*inode) {
		rc = ll_update_inode(*inode, &md);
		if (rc)
			goto out;
	} else {
		bool api32 = test_bit(LL_SBI_32BIT_API, sbi->ll_flags);
		struct lu_fid *fid1 = &md.body->mbo_fid1;

		LASSERT(sb);

		/*
		 * At this point server returns to client's same fid as client
		 * generated for creating. So using ->fid1 is okay here.
		 */
		if (!fid_is_sane(fid1)) {
			CERROR("%s: Fid is insane " DFID "\n",
			       sbi->ll_fsname, PFID(fid1));
			rc = -EINVAL;
			goto out;
		}

		*inode = ll_iget(sb, cl_fid_build_ino(fid1, api32), &md);
		if (IS_ERR(*inode)) {
			lmd_clear_acl(&md);
			rc = IS_ERR(*inode) ? PTR_ERR(*inode) : -ENOMEM;
			CERROR("new_inode -fatal: rc %d\n", rc);
			goto out;
		}
	}

	/* Handling piggyback layout lock.
	 * Layout lock can be piggybacked by getattr and open request.
	 * The lsm can be applied to inode only if it comes with a layout lock
	 * otherwise correct layout may be overwritten, for example:
	 * 1. proc1: mdt returns a lsm but not granting layout
	 * 2. layout was changed by another client
	 * 3. proc2: refresh layout and layout lock granted
	 * 4. proc1: to apply a stale layout
	 */
	if (it && it->it_lock_mode != 0) {
		struct lustre_handle lockh;
		struct ldlm_lock *lock;

		lockh.cookie = it->it_lock_handle;
		lock = ldlm_handle2lock(&lockh);
		LASSERT(lock);
		if (ldlm_has_layout(lock)) {
			struct cl_object_conf conf;

			memset(&conf, 0, sizeof(conf));
			conf.coc_opc = OBJECT_CONF_SET;
			conf.coc_inode = *inode;
			conf.coc_lock = lock;
			conf.u.coc_layout = md.layout;
			(void)ll_layout_conf(*inode, &conf);
		}
		LDLM_LOCK_PUT(lock);
	}

	if (default_lmv_deleted)
		ll_update_default_lsm_md(*inode, &md);

	/* we may want to apply some policy for foreign file/dir */
	if (ll_sbi_has_foreign_symlink(sbi))
		rc = ll_manage_foreign(*inode, &md);
out:
	/* cleanup will be done if necessary */
	md_free_lustre_md(sbi->ll_md_exp, &md);

	if (rc != 0 && it && it->it_op & IT_OPEN) {
		ll_intent_drop_lock(it);
		ll_open_cleanup(sb ? sb : (*inode)->i_sb, pill);
	}

	return rc;
}

int ll_obd_statfs(struct inode *inode, void __user *uarg)
{
	struct ll_sb_info *sbi = NULL;
	struct obd_export *exp;
	struct obd_ioctl_data *data = NULL;
	u32 type;
	int len = 0, rc;

	if (!inode) {
		rc = -EINVAL;
		goto out_statfs;
	}

	sbi = ll_i2sbi(inode);
	if (!sbi) {
		rc = -EINVAL;
		goto out_statfs;
	}

	rc = obd_ioctl_getdata(&data, &len, uarg);
	if (rc)
		goto out_statfs;

	if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2 ||
	    !data->ioc_pbuf1 || !data->ioc_pbuf2) {
		rc = -EINVAL;
		goto out_statfs;
	}

	if (data->ioc_inllen1 != sizeof(u32) ||
	    data->ioc_inllen2 != sizeof(u32) ||
	    data->ioc_plen1 != sizeof(struct obd_statfs) ||
	    data->ioc_plen2 != sizeof(struct obd_uuid)) {
		rc = -EINVAL;
		goto out_statfs;
	}

	memcpy(&type, data->ioc_inlbuf1, sizeof(u32));
	if (type & LL_STATFS_LMV) {
		exp = sbi->ll_md_exp;
	} else if (type & LL_STATFS_LOV) {
		exp = sbi->ll_dt_exp;
	} else {
		rc = -ENODEV;
		goto out_statfs;
	}

	rc = obd_iocontrol(IOC_OBD_STATFS, exp, len, data, NULL);
	if (rc)
		goto out_statfs;
out_statfs:
	kvfree(data);
	return rc;
}

/*
 * this is normally called in ll_fini_md_op_data(), but sometimes it needs to
 * be called early to avoid deadlock.
 */
void ll_unlock_md_op_lsm(struct md_op_data *op_data)
{
	if (op_data->op_mea2_sem) {
		up_read_non_owner(op_data->op_mea2_sem);
		op_data->op_mea2_sem = NULL;
	}

	if (op_data->op_mea1_sem) {
		up_read_non_owner(op_data->op_mea1_sem);
		op_data->op_mea1_sem = NULL;
	}
}

/* this function prepares md_op_data hint for passing ot down to MD stack. */
struct md_op_data *ll_prep_md_op_data(struct md_op_data *op_data,
				      struct inode *i1, struct inode *i2,
				      const char *name, size_t namelen,
				      u32 mode, enum md_op_code opc,
				      void *data)
{
	struct fscrypt_name fname = { 0 };
	int rc;

	if (!name) {
		/* Do not reuse namelen for something else. */
		if (namelen)
			return ERR_PTR(-EINVAL);
	} else {
		if ((!IS_ENCRYPTED(i1) ||
		     (opc != LUSTRE_OPC_LOOKUP && opc != LUSTRE_OPC_CREATE)) &&
		    namelen > ll_i2sbi(i1)->ll_namelen)
			return ERR_PTR(-ENAMETOOLONG);

		/* "/" is not valid name, but it's allowed */
		if (!lu_name_is_valid_2(name, namelen) &&
		    strncmp("/", name, namelen) != 0)
			return ERR_PTR(-EINVAL);
	}

	if (!op_data)
		op_data = kzalloc(sizeof(*op_data), GFP_NOFS);

	if (!op_data)
		return ERR_PTR(-ENOMEM);

	ll_i2gids(op_data->op_suppgids, i1, i2);
	/* If the client is using a subdir mount and looks at what it sees as
	 * /.fscrypt, interpret it as the .fscrypt dir at the root of the fs.
	 */
	if (unlikely(i1->i_sb && i1->i_sb->s_root && is_root_inode(i1) &&
		     !fid_is_root(ll_inode2fid(i1)) &&
		     name && namelen == strlen(dot_fscrypt_name) &&
		     strncmp(name, dot_fscrypt_name, namelen) == 0))
		lu_root_fid(&op_data->op_fid1);
	else
		op_data->op_fid1 = *ll_inode2fid(i1);

	if (S_ISDIR(i1->i_mode)) {
		down_read_non_owner(&ll_i2info(i1)->lli_lsm_sem);
		op_data->op_mea1_sem = &ll_i2info(i1)->lli_lsm_sem;
		op_data->op_mea1 = ll_i2info(i1)->lli_lsm_md;
		op_data->op_default_mea1 = ll_i2info(i1)->lli_default_lsm_md;
	}

	if (i2) {
		op_data->op_fid2 = *ll_inode2fid(i2);
		if (S_ISDIR(i2->i_mode)) {
			if (i2 != i1) {
				/* i2 is typically a child of i1, and MUST be
				 * further from the root to avoid deadlocks.
				 */
				down_read_non_owner(&ll_i2info(i2)->lli_lsm_sem);
				op_data->op_mea2_sem =
						&ll_i2info(i2)->lli_lsm_sem;
			}
			op_data->op_mea2 = ll_i2info(i2)->lli_lsm_md;
		}
	} else {
		fid_zero(&op_data->op_fid2);
	}

	if (test_bit(LL_SBI_64BIT_HASH, ll_i2sbi(i1)->ll_flags))
		op_data->op_cli_flags |= CLI_HASH64;

	if (ll_need_32bit_api(ll_i2sbi(i1)))
		op_data->op_cli_flags |= CLI_API32;

	if ((i2 && is_root_inode(i2)) ||
	    opc == LUSTRE_OPC_LOOKUP || opc == LUSTRE_OPC_CREATE) {
		/* In case of lookup, ll_setup_filename() has already been
		 * called in ll_lookup_it(), so just take provided name.
		 * Also take provided name if we are dealing with root inode.
		 */
		fname.disk_name.name = (unsigned char *)name;
		fname.disk_name.len = namelen;
	} else if (name && namelen) {
		struct qstr dname = QSTR_INIT(name, namelen);
		struct inode *dir;
		struct lu_fid *pfid = NULL;
		struct lu_fid fid;
		int lookup;

		if (!S_ISDIR(i1->i_mode) && i2 && S_ISDIR(i2->i_mode)) {
			/* special case when called from ll_link() */
			dir = i2;
			lookup = 0;
		} else {
			dir = i1;
			lookup = (int)(opc == LUSTRE_OPC_ANY);
		}
		if (opc == LUSTRE_OPC_ANY && lookup)
			pfid = &fid;
		rc = ll_setup_filename(dir, &dname, lookup, &fname, pfid);
		if (rc) {
			ll_finish_md_op_data(op_data);
			return ERR_PTR(rc);
		}
		if (pfid && !fid_is_zero(pfid)) {
			if (i2 == NULL)
				op_data->op_fid2 = fid;
			op_data->op_bias = MDS_FID_OP;
		}
		if (fname.disk_name.name &&
		    fname.disk_name.name != (unsigned char *)name) {
			/* op_data->op_name must be freed after use */
			op_data->op_flags |= MF_OPNAME_KMALLOCED;
		}
	}

	/* In fact LUSTRE_OPC_LOOKUP, LUSTRE_OPC_OPEN
	 * are LUSTRE_OPC_ANY
	 */
	if (opc == LUSTRE_OPC_LOOKUP || opc == LUSTRE_OPC_OPEN)
		op_data->op_code = LUSTRE_OPC_ANY;
	else
		op_data->op_code = opc;
	op_data->op_name = fname.disk_name.name;
	op_data->op_namelen = fname.disk_name.len;
	op_data->op_mode = mode;
	op_data->op_mod_time = ktime_get_real_seconds();
	op_data->op_fsuid = from_kuid(&init_user_ns, current_fsuid());
	op_data->op_fsgid = from_kgid(&init_user_ns, current_fsgid());
	op_data->op_cap = current_cap();
	op_data->op_mds = 0;
	if ((opc == LUSTRE_OPC_CREATE) && name &&
	    filename_is_volatile(name, namelen, &op_data->op_mds))
		op_data->op_bias |= MDS_CREATE_VOLATILE;
	op_data->op_data = data;

	return op_data;
}

void ll_finish_md_op_data(struct md_op_data *op_data)
{
	ll_unlock_md_op_lsm(op_data);
	security_release_secctx(op_data->op_file_secctx,
				op_data->op_file_secctx_size);
	if (op_data->op_flags & MF_OPNAME_KMALLOCED)
		/* allocated via ll_setup_filename called
		 * from ll_prep_md_op_data
		 */
		kfree(op_data->op_name);
	kfree(op_data->op_file_encctx);
	kfree(op_data);
}

int ll_show_options(struct seq_file *seq, struct dentry *dentry)
{
	struct ll_sb_info *sbi;
	int i;

	LASSERT(seq && dentry);
	sbi = ll_s2sbi(dentry->d_sb);

	if (test_bit(LL_SBI_NOLCK, sbi->ll_flags))
		seq_puts(seq, "nolock");

	for (i = 1; ll_sbi_flags_name[i].token != LL_SBI_NUM_MOUNT_OPT; i++) {
		/* match_table in some cases has patterns for both enabled and
		 * disabled cases. Ignore 'no'xxx versions if bit is set.
		 */
		if (test_bit(ll_sbi_flags_name[i].token, sbi->ll_flags) &&
		    strncmp(ll_sbi_flags_name[i].pattern, "no", 2)) {
			if (ll_sbi_flags_name[i].token ==
			    LL_SBI_FOREIGN_SYMLINK) {
				seq_show_option(seq, "foreign_symlink",
						sbi->ll_foreign_symlink_prefix);
			} else {
				seq_printf(seq, ",%s",
					   ll_sbi_flags_name[i].pattern);
			}

			/* You can have either localflock or flock but not
			 * both. If localflock is set don't print flock or
			 * noflock.
			 */
			if (ll_sbi_flags_name[i].token == LL_SBI_LOCALFLOCK)
				i += 2;
		} else if (!test_bit(ll_sbi_flags_name[i].token, sbi->ll_flags) &&
			   !strncmp(ll_sbi_flags_name[i].pattern, "no", 2)) {
			seq_printf(seq, ",%s",
				   ll_sbi_flags_name[i].pattern);
		}
	}

	fscrypt_show_test_dummy_encryption(seq, ',', dentry->d_sb);

	return 0;
}

/**
 * Get obd name by cmd, and copy out to user space
 */
int ll_get_obd_name(struct inode *inode, unsigned int cmd, void __user *uarg)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct obd_device *obd;

	if (cmd == OBD_IOC_GETNAME_OLD || cmd == OBD_IOC_GETDTNAME)
		obd = class_exp2obd(sbi->ll_dt_exp);
	else if (cmd == OBD_IOC_GETMDNAME)
		obd = class_exp2obd(sbi->ll_md_exp);
	else
		return -EINVAL;

	if (!obd)
		return -ENOENT;

	if (copy_to_user(uarg, obd->obd_name, strlen(obd->obd_name) + 1))
		return -EFAULT;

	return 0;
}

struct dname_buf {
	struct work_struct db_work;
	struct dentry *db_dentry;
	/* Let's hope the path is not too long, 32 bytes for the work struct
	 * on my kernel
	 */
	char buf[PAGE_SIZE - sizeof(struct work_struct) - sizeof(void *)];
};

static void ll_dput_later(struct work_struct *work)
{
	struct dname_buf *db = container_of(work, struct dname_buf, db_work);

	dput(db->db_dentry);
	free_page((unsigned long)db);
}

void ll_dirty_page_discard_warn(struct inode *inode, int ioret)
{
	struct dname_buf *db;
	char *path = NULL;
	struct dentry *dentry = NULL;

	/* this can be called inside spin lock so use GFP_ATOMIC. */
	db = (struct dname_buf *)__get_free_page(GFP_ATOMIC);
	if (db) {
		dentry = d_find_alias(inode);
		if (dentry)
			path = dentry_path_raw(dentry, db->buf,
					       sizeof(db->buf));
	}

	/* The below message is checked in recovery-small.sh test_24b */
	CDEBUG(D_WARNING,
	       "%s: dirty page discard: %s/fid: " DFID "/%s may get corrupted (rc %d)\n",
	       ll_i2sbi(inode)->ll_fsname,
	       s2lsi(inode->i_sb)->lsi_lmd->lmd_dev,
	       PFID(ll_inode2fid(inode)),
	       (path && !IS_ERR(path)) ? path : "", ioret);

	if (dentry) {
		/* We cannot dput here since if we happen to be the last holder
		 * then we can end up waiting for page evictions that
		 * in turn wait for RPCs that need this instance of ptlrpcd
		 * (callng brw_interpret->*page_completion*->vmpage_error->here)
		 * LU-15340
		 */
		INIT_WORK(&db->db_work, ll_dput_later);
		db->db_dentry = dentry;
		schedule_work(&db->db_work);
	} else {
		if (db)
			free_page((unsigned long)db);
	}
}

ssize_t ll_copy_user_md(const struct lov_user_md __user *md,
			struct lov_user_md **kbuf)
{
	struct lov_user_md lum;
	ssize_t lum_size;

	if (copy_from_user(&lum, md, sizeof(lum))) {
		lum_size = -EFAULT;
		goto no_kbuf;
	}

	lum_size = ll_lov_user_md_size(&lum);
	if (lum_size < 0)
		goto no_kbuf;

	*kbuf = kvzalloc(lum_size, GFP_NOFS);
	if (!*kbuf) {
		lum_size = -ENOMEM;
		goto no_kbuf;
	}

	if (copy_from_user(*kbuf, md, lum_size) != 0) {
		kvfree(*kbuf);
		*kbuf = NULL;
		lum_size = -EFAULT;
	}
no_kbuf:
	return lum_size;
}

/*
 * Compute llite root squash state after a change of root squash
 * configuration setting or add/remove of a lnet nid
 */
void ll_compute_rootsquash_state(struct ll_sb_info *sbi)
{
	struct root_squash_info *squash = &sbi->ll_squash;
	struct lnet_processid id;
	bool matched;
	int i;

	/* Update norootsquash flag */
	spin_lock(&squash->rsi_lock);
	if (list_empty(&squash->rsi_nosquash_nids)) {
		clear_bit(LL_SBI_NOROOTSQUASH, sbi->ll_flags);
	} else {
		/* Do not apply root squash as soon as one of our NIDs is
		 * in the nosquash_nids list
		 */
		matched = false;
		i = 0;

		while (LNetGetId(i++, &id) != -ENOENT) {
			if (nid_is_lo0(&id.nid))
				continue;
			if (cfs_match_nid(&id.nid,
					  &squash->rsi_nosquash_nids)) {
				matched = true;
				break;
			}
		}
		spin_lock(&sbi->ll_lock);
		if (matched)
			set_bit(LL_SBI_NOROOTSQUASH, sbi->ll_flags);
		else
			clear_bit(LL_SBI_NOROOTSQUASH, sbi->ll_flags);
	}
	spin_unlock(&squash->rsi_lock);
}

/**
 * Parse linkea content to extract information about a given hardlink
 *
 * @ldata:		- Initialized linkea data
 * @linkno:		- Link identifier
 * @parent_fid:		- The entry's parent FID
 * @size:		- Entry name destination buffer
 *
 * Returns:		0 on success
 *			Appropriate negative error code on failure
 */
static int ll_linkea_decode(struct linkea_data *ldata, unsigned int linkno,
			    struct lu_fid *parent_fid, struct lu_name *ln)
{
	unsigned int idx;
	int rc;

	rc = linkea_init_with_rec(ldata);
	if (rc < 0)
		return rc;

	if (linkno >= ldata->ld_leh->leh_reccount)
		/* beyond last link */
		return -ENODATA;

	linkea_first_entry(ldata);
	for (idx = 0; ldata->ld_lee; idx++) {
		linkea_entry_unpack(ldata->ld_lee, &ldata->ld_reclen, ln,
				    parent_fid);
		if (idx == linkno)
			break;

		linkea_next_entry(ldata);
	}

	if (idx < linkno)
		return -ENODATA;

	return 0;
}

/**
 * Get parent FID and name of an identified link. Operation is performed for
 * a given link number, letting the caller iterate over linkno to list one or
 * all links of an entry.
 *
 * @file:	- File descriptor against which to perform the operation
 * @arg:	- User-filled structure containing the linkno to operate
 *		  on and the available size. It is eventually filled
 *		  with the requested information or left untouched on
 *		  error
 *
 * Returns:	- 0 on success
 *		- Appropriate negative error code on failure
 */
int ll_getparent(struct file *file, struct getparent __user *arg)
{
	struct inode *inode = file_inode(file);
	struct linkea_data *ldata;
	struct lu_fid parent_fid;
	struct lu_buf buf = {
		.lb_buf = NULL,
		.lb_len = 0
	};
	struct lu_name ln;
	u32 name_size;
	u32 linkno;
	int rc;

	if (!capable(CAP_DAC_READ_SEARCH) &&
	    !test_bit(LL_SBI_USER_FID2PATH, ll_i2sbi(inode)->ll_flags))
		return -EPERM;

	if (get_user(name_size, &arg->gp_name_size))
		return -EFAULT;

	if (get_user(linkno, &arg->gp_linkno))
		return -EFAULT;

	if (name_size > PATH_MAX)
		return -EINVAL;

	ldata = kzalloc(sizeof(*ldata), GFP_NOFS);
	if (!ldata)
		return -ENOMEM;

	rc = linkea_data_new(ldata, &buf);
	if (rc < 0)
		goto ldata_free;

	rc = ll_xattr_list(inode, XATTR_NAME_LINK, XATTR_TRUSTED_T, buf.lb_buf,
			   buf.lb_len, OBD_MD_FLXATTR);
	if (rc < 0)
		goto lb_free;

	rc = ll_linkea_decode(ldata, linkno, &parent_fid, &ln);
	if (rc < 0)
		goto lb_free;

	if (ln.ln_namelen >= name_size) {
		rc = -EOVERFLOW;
		goto lb_free;
	}

	if (copy_to_user(&arg->gp_fid, &parent_fid, sizeof(arg->gp_fid))) {
		rc = -EFAULT;
		goto lb_free;
	}

	if (copy_to_user(&arg->gp_name, ln.ln_name, ln.ln_namelen)) {
		rc = -EFAULT;
		goto lb_free;
	}

	if (put_user('\0', arg->gp_name + ln.ln_namelen)) {
		rc = -EFAULT;
		goto lb_free;
	}

lb_free:
	kvfree(buf.lb_buf);
ldata_free:
	kfree(ldata);
	return rc;
}

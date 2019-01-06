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
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lov/lov_ea.c
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <asm/div64.h>

#include <obd_class.h>
#include <uapi/linux/lustre/lustre_idl.h>

#include "lov_internal.h"

/*
 * Find minimum stripe maxbytes value. For inactive or
 * reconnecting targets use LUSTRE_EXT3_STRIPE_MAXBYTES.
 */
static loff_t lov_tgt_maxbytes(struct lov_tgt_desc *tgt)
{
	loff_t maxbytes = LUSTRE_EXT3_STRIPE_MAXBYTES;
	struct obd_import *imp;

	if (!tgt->ltd_active)
		return maxbytes;

	imp = tgt->ltd_obd->u.cli.cl_import;
	if (!imp)
		return maxbytes;

	spin_lock(&imp->imp_lock);
	if (imp->imp_state == LUSTRE_IMP_FULL &&
	    (imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_MAXBYTES) &&
	     imp->imp_connect_data.ocd_maxbytes > 0)
		maxbytes = imp->imp_connect_data.ocd_maxbytes;

	spin_unlock(&imp->imp_lock);

	return maxbytes;
}

static int lsm_lmm_verify_v1v3(struct lov_mds_md *lmm, size_t lmm_size,
			       u16 stripe_count)
{
	if (stripe_count > LOV_V1_INSANE_STRIPE_COUNT) {
		CERROR("bad stripe count %d\n", stripe_count);
		lov_dump_lmm_common(D_WARNING, lmm);
		return -EINVAL;
	}

	if (lmm_oi_id(&lmm->lmm_oi) == 0) {
		CERROR("zero object id\n");
		lov_dump_lmm_common(D_WARNING, lmm);
		return -EINVAL;
	}

	if (lov_pattern(le32_to_cpu(lmm->lmm_pattern)) != LOV_PATTERN_RAID0) {
		CERROR("bad striping pattern\n");
		lov_dump_lmm_common(D_WARNING, lmm);
		return -EINVAL;
	}

	if (lmm->lmm_stripe_size == 0 ||
	    (le32_to_cpu(lmm->lmm_stripe_size) &
	     (LOV_MIN_STRIPE_SIZE - 1)) != 0) {
		CERROR("bad stripe size %u\n",
		       le32_to_cpu(lmm->lmm_stripe_size));
		lov_dump_lmm_common(D_WARNING, lmm);
		return -EINVAL;
	}
	return 0;
}

static void lsme_free(struct lov_stripe_md_entry *lsme)
{
	unsigned int stripe_count = lsme->lsme_stripe_count;
	unsigned int i;

	for (i = 0; i < stripe_count; i++)
		kmem_cache_free(lov_oinfo_slab, lsme->lsme_oinfo[i]);

	kvfree(lsme);
}

void lsm_free(struct lov_stripe_md *lsm)
{
	unsigned int entry_count = lsm->lsm_entry_count;
	unsigned int i;

	for (i = 0; i < entry_count; i++)
		lsme_free(lsm->lsm_entries[i]);

	kfree(lsm);
}

/**
 * Unpack a struct lov_mds_md into a struct lov_stripe_md_entry.
 *
 * The caller should set id and extent.
 */
static struct lov_stripe_md_entry *
lsme_unpack(struct lov_obd *lov, struct lov_mds_md *lmm, size_t buf_size,
	    const char *pool_name, struct lov_ost_data_v1 *objects,
	    loff_t *maxbytes)
{
	struct lov_stripe_md_entry *lsme;
	loff_t min_stripe_maxbytes = 0;
	unsigned int stripe_count;
	loff_t lov_bytes;
	size_t lsme_size;
	unsigned int i;
	u32 pattern;
	u32 magic;
	int rc;

	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3)
		return ERR_PTR(-EINVAL);

	pattern = le32_to_cpu(lmm->lmm_pattern);
	if (pattern & LOV_PATTERN_F_RELEASED)
		stripe_count = 0;
	else
		stripe_count = le16_to_cpu(lmm->lmm_stripe_count);

	if (buf_size < (magic == LOV_MAGIC_V1 ? sizeof(struct lov_mds_md_v1) :
						sizeof(struct lov_mds_md_v3))) {
		CERROR("LOV EA %s too small: %zu, need %u\n",
		       magic == LOV_MAGIC_V1 ? "V1" : "V3", buf_size,
		       lov_mds_md_size(stripe_count, magic == LOV_MAGIC_V1 ?
				       LOV_MAGIC_V1 : LOV_MAGIC_V3));
		lov_dump_lmm_common(D_WARNING, lmm);
		return ERR_PTR(-EINVAL);
	}

	rc = lsm_lmm_verify_v1v3(lmm, buf_size, stripe_count);
	if (rc < 0)
		return ERR_PTR(rc);

	lsme_size = offsetof(typeof(*lsme), lsme_oinfo[stripe_count]);
	lsme = kvzalloc(lsme_size, GFP_KERNEL);
	if (!lsme)
		return ERR_PTR(-ENOMEM);

	lsme->lsme_magic = magic;
	lsme->lsme_pattern = pattern;
	lsme->lsme_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
	lsme->lsme_stripe_count = stripe_count;
	lsme->lsme_layout_gen = le16_to_cpu(lmm->lmm_layout_gen);

	if (pool_name) {
		size_t pool_name_len;

		pool_name_len = strlcpy(lsme->lsme_pool_name, pool_name,
					sizeof(lsme->lsme_pool_name));
		if (pool_name_len >= sizeof(lsme->lsme_pool_name)) {
			rc = -E2BIG;
			goto out_lsme;
		}
	}

	for (i = 0; i < stripe_count; i++) {
		struct lov_tgt_desc *ltd;
		struct lov_oinfo *loi;

		loi = kmem_cache_zalloc(lov_oinfo_slab, GFP_KERNEL);
		if (!loi) {
			rc = -ENOMEM;
			goto out_lsme;
		}

		lsme->lsme_oinfo[i] = loi;

		ostid_le_to_cpu(&objects[i].l_ost_oi, &loi->loi_oi);
		loi->loi_ost_idx = le32_to_cpu(objects[i].l_ost_idx);
		loi->loi_ost_gen = le32_to_cpu(objects[i].l_ost_gen);
		if (lov_oinfo_is_dummy(loi))
			continue;

		if (loi->loi_ost_idx >= lov->desc.ld_tgt_count &&
		    !lov2obd(lov)->obd_process_conf) {
			CERROR("%s: OST index %d more than OST count %d\n",
			       (char *)lov->desc.ld_uuid.uuid,
			       loi->loi_ost_idx, lov->desc.ld_tgt_count);
			lov_dump_lmm_v1(D_WARNING, lmm);
			rc = -EINVAL;
			goto out_lsme;
		}

		ltd = lov->lov_tgts[loi->loi_ost_idx];
		if (!ltd) {
			CERROR("%s: OST index %d missing\n",
			       (char *)lov->desc.ld_uuid.uuid,
			       loi->loi_ost_idx);
			lov_dump_lmm_v1(D_WARNING, lmm);
			continue;
		}

		lov_bytes = lov_tgt_maxbytes(ltd);
		if (min_stripe_maxbytes == 0 || lov_bytes < min_stripe_maxbytes)
			min_stripe_maxbytes = lov_bytes;
	}

	if (min_stripe_maxbytes == 0)
		min_stripe_maxbytes = LUSTRE_EXT3_STRIPE_MAXBYTES;

	lov_bytes = min_stripe_maxbytes * stripe_count;

	if (maxbytes) {
		if (lov_bytes < min_stripe_maxbytes) /* handle overflow */
			*maxbytes = MAX_LFS_FILESIZE;
		else
			*maxbytes = lov_bytes;
	}

	return lsme;

out_lsme:
	for (i = 0; i < stripe_count; i++) {
		struct lov_oinfo *loi = lsme->lsme_oinfo[i];

		if (loi)
			kmem_cache_free(lov_oinfo_slab, lsme->lsme_oinfo[i]);
	}
	kvfree(lsme);

	return ERR_PTR(rc);
}

static inline struct lov_stripe_md *
lsm_unpackmd_v1v3(struct lov_obd *lov,
		  struct lov_mds_md *lmm, size_t buf_size,
		  const char *pool_name,
		  struct lov_ost_data_v1 *objects)
{
	struct lov_stripe_md_entry *lsme;
	struct lov_stripe_md *lsm;
	size_t lsm_size;
	loff_t maxbytes;
	u32 pattern;

	pattern = le32_to_cpu(lmm->lmm_pattern);

	lsme = lsme_unpack(lov, lmm, buf_size, pool_name, objects, &maxbytes);
	if (IS_ERR(lsme))
		return ERR_CAST(lsme);

	lsme->lsme_extent.e_start = 0;
	lsme->lsme_extent.e_end = LUSTRE_EOF;

	lsm_size = offsetof(typeof(*lsm), lsm_entries[1]);
	lsm = kzalloc(lsm_size, GFP_KERNEL);
	if (!lsm) {
		lsme_free(lsme);
		return ERR_PTR(-ENOMEM);
	}

	atomic_set(&lsm->lsm_refc, 1);
	spin_lock_init(&lsm->lsm_lock);
	lsm->lsm_maxbytes = maxbytes;
	lmm_oi_le_to_cpu(&lsm->lsm_oi, &lmm->lmm_oi);
	lsm->lsm_magic = le32_to_cpu(lmm->lmm_magic);
	lsm->lsm_layout_gen = le16_to_cpu(lmm->lmm_layout_gen);
	lsm->lsm_entry_count = 1;
	lsm->lsm_is_released = pattern & LOV_PATTERN_F_RELEASED;
	lsm->lsm_entries[0] = lsme;

	return lsm;
}

static void
lsm_stripe_by_index_plain(struct lov_stripe_md *lsm, int *stripeno,
			  loff_t *lov_off, loff_t *swidth)
{
	if (swidth)
		*swidth = (loff_t)lsm->lsm_entries[0]->lsme_stripe_size *
			  lsm->lsm_entries[0]->lsme_stripe_count;
}

static void
lsm_stripe_by_offset_plain(struct lov_stripe_md *lsm, int *stripeno,
			   loff_t *lov_off, loff_t *swidth)
{
	if (swidth)
		*swidth = (loff_t)lsm->lsm_entries[0]->lsme_stripe_size *
			  lsm->lsm_entries[0]->lsme_stripe_count;
}

static struct lov_stripe_md *
lsm_unpackmd_v1(struct lov_obd *lov, void *buf, size_t buf_size)
{
	struct lov_mds_md_v1 *lmm = buf;

	return lsm_unpackmd_v1v3(lov, buf, buf_size, NULL, lmm->lmm_objects);
}

const static struct lsm_operations lsm_v1_ops = {
	.lsm_stripe_by_index    = lsm_stripe_by_index_plain,
	.lsm_stripe_by_offset   = lsm_stripe_by_offset_plain,
	.lsm_unpackmd	   = lsm_unpackmd_v1,
};

static struct lov_stripe_md *
lsm_unpackmd_v3(struct lov_obd *lov, void *buf, size_t buf_size)
{
	struct lov_mds_md_v3 *lmm = buf;

	return lsm_unpackmd_v1v3(lov, buf, buf_size, lmm->lmm_pool_name,
				 lmm->lmm_objects);
}

const static struct lsm_operations lsm_v3_ops = {
	.lsm_stripe_by_index	= lsm_stripe_by_index_plain,
	.lsm_stripe_by_offset	= lsm_stripe_by_offset_plain,
	.lsm_unpackmd		= lsm_unpackmd_v3,
};

const struct lsm_operations *lsm_op_find(int magic)
{
	switch (magic) {
	case LOV_MAGIC_V1:
		return &lsm_v1_ops;
	case LOV_MAGIC_V3:
		return &lsm_v3_ops;
	default:
		CERROR("unrecognized lsm_magic %08x\n", magic);
		return NULL;
	}
}

void dump_lsm(unsigned int level, const struct lov_stripe_md *lsm)
{
	CDEBUG(level, "lsm %p, objid " DOSTID ", maxbytes %#llx, magic 0x%08X, stripe_size %u, stripe_count %u, refc: %d, layout_gen %u, pool [" LOV_POOLNAMEF "]\n",
	       lsm, POSTID(&lsm->lsm_oi), lsm->lsm_maxbytes, lsm->lsm_magic,
	       lsm->lsm_entries[0]->lsme_stripe_size,
	       lsm->lsm_entries[0]->lsme_stripe_count,
	       atomic_read(&lsm->lsm_refc), lsm->lsm_layout_gen,
	       lsm->lsm_entries[0]->lsme_pool_name);
}

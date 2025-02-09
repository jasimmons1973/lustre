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
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * lustre/include/lustre_lmv.h
 *
 * Lustre LMV structures and functions.
 *
 * Author: Di Wang <di.wang@intel.com>
 */

#ifndef _LUSTRE_LMV_H
#define _LUSTRE_LMV_H
#include <uapi/linux/lustre/lustre_idl.h>

struct lmv_oinfo {
	struct lu_fid	lmo_fid;
	u32		lmo_mds;
	struct inode	*lmo_root;
};

struct lmv_stripe_md {
	u32	lsm_md_magic;
	u32	lsm_md_stripe_count;
	u32	lsm_md_master_mdt_index;
	u32	lsm_md_hash_type;
	u8	lsm_md_max_inherit;
	u8	lsm_md_max_inherit_rr;
	u32	lsm_md_layout_version;
	u32	lsm_md_migrate_offset;
	u32	lsm_md_migrate_hash;
	char	lsm_md_pool_name[LOV_MAXPOOLNAME + 1];
	struct lmv_oinfo lsm_md_oinfo[0];
};

static inline bool lmv_dir_striped(const struct lmv_stripe_md *lsm)
{
	return lsm && lsm->lsm_md_magic == LMV_MAGIC;
}

static inline bool lmv_dir_foreign(const struct lmv_stripe_md *lsm)
{
	return lsm && lsm->lsm_md_magic == LMV_MAGIC_FOREIGN;
}

static inline bool lmv_dir_layout_changing(const struct lmv_stripe_md *lsm)
{
	return lmv_dir_striped(lsm) &&
	       lmv_hash_is_layout_changing(lsm->lsm_md_hash_type);
}

static inline bool lmv_dir_bad_hash(const struct lmv_stripe_md *lsm)
{
	if (!lmv_dir_striped(lsm))
		return false;

	if (lsm->lsm_md_hash_type & LMV_HASH_FLAG_BAD_TYPE)
		return true;

	return !lmv_is_known_hash_type(lsm->lsm_md_hash_type);
}

static inline u8 lmv_inherit_next(u8 inherit)
{
	if (inherit == LMV_INHERIT_END || inherit == LMV_INHERIT_NONE)
		return LMV_INHERIT_NONE;

	if (inherit == LMV_INHERIT_UNLIMITED || inherit > LMV_INHERIT_MAX)
		return inherit;

	return inherit - 1;
}

static inline u8 lmv_inherit_rr_next(u8 inherit_rr)
{
	if (inherit_rr == LMV_INHERIT_RR_NONE ||
	    inherit_rr == LMV_INHERIT_RR_UNLIMITED ||
	    inherit_rr > LMV_INHERIT_RR_MAX)
		return inherit_rr;

	return inherit_rr - 1;
}

static inline bool lmv_is_inheritable(u8 inherit)
{
	return inherit == LMV_INHERIT_UNLIMITED ||
	       (inherit > LMV_INHERIT_END && inherit <= LMV_INHERIT_MAX);
}

static inline bool
lsm_md_eq(const struct lmv_stripe_md *lsm1, const struct lmv_stripe_md *lsm2)
{
	u32 idx;

	if (lsm1->lsm_md_magic != lsm2->lsm_md_magic ||
	    lsm1->lsm_md_stripe_count != lsm2->lsm_md_stripe_count ||
	    lsm1->lsm_md_master_mdt_index != lsm2->lsm_md_master_mdt_index ||
	    lsm1->lsm_md_hash_type != lsm2->lsm_md_hash_type ||
	    lsm1->lsm_md_max_inherit != lsm2->lsm_md_max_inherit ||
	    lsm1->lsm_md_max_inherit_rr != lsm2->lsm_md_max_inherit_rr ||
	    lsm1->lsm_md_layout_version != lsm2->lsm_md_layout_version ||
	    lsm1->lsm_md_migrate_offset !=
				lsm2->lsm_md_migrate_offset ||
	    lsm1->lsm_md_migrate_hash !=
				lsm2->lsm_md_migrate_hash ||
	    strncmp(lsm1->lsm_md_pool_name, lsm2->lsm_md_pool_name,
		    sizeof(lsm1->lsm_md_pool_name)) != 0)
		return false;

	if (lmv_dir_striped(lsm1)) {
		for (idx = 0; idx < lsm1->lsm_md_stripe_count; idx++) {
			if (!lu_fid_eq(&lsm1->lsm_md_oinfo[idx].lmo_fid,
				       &lsm2->lsm_md_oinfo[idx].lmo_fid))
				return false;
		}
	} else if (lsm1->lsm_md_magic == LMV_USER_MAGIC_SPECIFIC) {
		for (idx = 0; idx < lsm1->lsm_md_stripe_count; idx++) {
			if (lsm1->lsm_md_oinfo[idx].lmo_mds !=
			    lsm2->lsm_md_oinfo[idx].lmo_mds)
				return false;
		}
	}

	return true;
}

static inline void lsm_md_dump(int mask, const struct lmv_stripe_md *lsm)
{
	int i;

	CDEBUG_LIMIT(mask,
	       "dump LMV: magic=%#x count=%u index=%u hash=%s:%#x max_inherit=%hhu max_inherit_rr=%hhu version=%u migrate_offset=%u migrate_hash=%s:%x pool=%.*s\n",
	       lsm->lsm_md_magic, lsm->lsm_md_stripe_count,
	       lsm->lsm_md_master_mdt_index,
	       lmv_is_known_hash_type(lsm->lsm_md_hash_type) ?
		mdt_hash_name[lsm->lsm_md_hash_type & LMV_HASH_TYPE_MASK] :
		"invalid", lsm->lsm_md_hash_type,
	       lsm->lsm_md_max_inherit, lsm->lsm_md_max_inherit_rr,
	       lsm->lsm_md_layout_version, lsm->lsm_md_migrate_offset,
	       lmv_is_known_hash_type(lsm->lsm_md_migrate_hash) ?
		mdt_hash_name[lsm->lsm_md_migrate_hash & LMV_HASH_TYPE_MASK] :
		"invalid", lsm->lsm_md_migrate_hash,
	       LOV_MAXPOOLNAME, lsm->lsm_md_pool_name);

	if (!lmv_dir_striped(lsm))
		return;

	for (i = 0; i < lsm->lsm_md_stripe_count; i++)
		CDEBUG(mask, "stripe[%d] "DFID"\n",
		       i, PFID(&lsm->lsm_md_oinfo[i].lmo_fid));
}

static inline bool
lsm_md_inherited(const struct lmv_stripe_md *plsm,
		 const struct lmv_stripe_md *clsm)
{
	return plsm && clsm &&
	       plsm->lsm_md_magic == clsm->lsm_md_magic &&
	       plsm->lsm_md_stripe_count == clsm->lsm_md_stripe_count &&
	       plsm->lsm_md_master_mdt_index ==
			clsm->lsm_md_master_mdt_index &&
	       plsm->lsm_md_hash_type == clsm->lsm_md_hash_type &&
	       lmv_inherit_next(plsm->lsm_md_max_inherit) ==
			clsm->lsm_md_max_inherit &&
	       lmv_inherit_rr_next(plsm->lsm_md_max_inherit_rr) ==
			clsm->lsm_md_max_inherit_rr;
}

union lmv_mds_md;

void lmv_free_memmd(struct lmv_stripe_md *lsm);

static inline void lmv1_le_to_cpu(struct lmv_mds_md_v1 *lmv_dst,
				  const struct lmv_mds_md_v1 *lmv_src)
{
	u32 i;

	lmv_dst->lmv_magic = le32_to_cpu(lmv_src->lmv_magic);
	lmv_dst->lmv_stripe_count = le32_to_cpu(lmv_src->lmv_stripe_count);
	lmv_dst->lmv_master_mdt_index =
		le32_to_cpu(lmv_src->lmv_master_mdt_index);
	lmv_dst->lmv_hash_type = le32_to_cpu(lmv_src->lmv_hash_type);
	lmv_dst->lmv_layout_version = le32_to_cpu(lmv_src->lmv_layout_version);
	if (lmv_src->lmv_stripe_count > LMV_MAX_STRIPE_COUNT)
		return;
	for (i = 0; i < lmv_src->lmv_stripe_count; i++)
		fid_le_to_cpu(&lmv_dst->lmv_stripe_fids[i],
			      &lmv_src->lmv_stripe_fids[i]);
}

static inline void lmv_le_to_cpu(union lmv_mds_md *lmv_dst,
				 const union lmv_mds_md *lmv_src)
{
	switch (le32_to_cpu(lmv_src->lmv_magic)) {
	case LMV_MAGIC_V1:
		lmv1_le_to_cpu(&lmv_dst->lmv_md_v1, &lmv_src->lmv_md_v1);
		break;
	default:
		break;
	}
}

/* This hash is only for testing purpose */
static inline unsigned int
lmv_hash_all_chars(unsigned int count, const char *name, int namelen)
{
	const unsigned char *p = (const unsigned char *)name;
	unsigned int c = 0;

	while (--namelen >= 0)
		c += p[namelen];

	c = c % count;

	return c;
}

static inline unsigned int
lmv_hash_fnv1a(unsigned int count, const char *name, int namelen)
{
	u64 hash;

	hash = lustre_hash_fnv_1a_64(name, namelen);

	return do_div(hash, count);
}

/*
 * Robert Jenkins' function for mixing 32-bit values
 * http://burtleburtle.net/bob/hash/evahash.html
 * a, b = random bits, c = input and output
 *
 * Mixing inputs to generate an evenly distributed hash.
 */
#define crush_hashmix(a, b, c)				\
do {							\
	a = a - b;  a = a - c;  a = a ^ (c >> 13);	\
	b = b - c;  b = b - a;  b = b ^ (a << 8);	\
	c = c - a;  c = c - b;  c = c ^ (b >> 13);	\
	a = a - b;  a = a - c;  a = a ^ (c >> 12);	\
	b = b - c;  b = b - a;  b = b ^ (a << 16);	\
	c = c - a;  c = c - b;  c = c ^ (b >> 5);	\
	a = a - b;  a = a - c;  a = a ^ (c >> 3);	\
	b = b - c;  b = b - a;  b = b ^ (a << 10);	\
	c = c - a;  c = c - b;  c = c ^ (b >> 15);	\
} while (0)

#define crush_hash_seed 1315423911

static inline u32 crush_hash(u32 a, u32 b)
{
	u32 hash = crush_hash_seed ^ a ^ b;
	u32 x = 231232;
	u32 y = 1232;

	crush_hashmix(a, b, hash);
	crush_hashmix(x, a, hash);
	crush_hashmix(b, y, hash);

	return hash;
}

/* refer to https://github.com/ceph/ceph/blob/master/src/crush/hash.c and
 * https://www.ssrc.ucsc.edu/Papers/weil-sc06.pdf for details of CRUSH
 * algorithm.
 */
static inline unsigned int
lmv_hash_crush(unsigned int count, const char *name, int namelen, bool crush2)
{
	unsigned long long straw;
	unsigned long long highest_straw = 0;
	unsigned int pg_id;
	unsigned int idx = 0;
	int i;

	/* put temp and backup file on the same MDT where target is located.
	 * temporary file naming rule:
	 * 1. rsync: .<target>.XXXXXX
	 * 2. dstripe: <target>.XXXXXXXX
	 */
	if (lu_name_is_temp_file(name, namelen, true, 6, crush2)) {
		name++;
		namelen -= 8;
	} else if (lu_name_is_temp_file(name, namelen, false, 8, crush2)) {
		namelen -= 9;
	} else if (lu_name_is_backup_file(name, namelen, &i)) {
		LASSERT(i < namelen);
		namelen -= i;
	}

	pg_id = lmv_hash_fnv1a(LMV_CRUSH_PG_COUNT, name, namelen);

	/* distribute PG among all stripes pseudo-randomly, so they are almost
	 * evenly distributed, and when stripe count changes, only (delta /
	 * total) sub files need to be moved, herein 'delta' is added or removed
	 * stripe count, 'total' is total stripe count before change for
	 * removal, or count after change for addition.
	 */
	for (i = 0; i < count; i++) {
		straw = crush_hash(pg_id, i);
		if (straw > highest_straw) {
			highest_straw = straw;
			idx = i;
		}
	}
	LASSERT(idx < count);

	return idx;
}

/* directory layout may change in three ways:
 * 1. directory migration, in its LMV source stripes are appended after
 *    target stripes, @migrate_hash is source hash type, @migrate_offset is
 *    target stripe count,
 * 2. directory split, @migrate_hash is hash type before split,
 *    @migrate_offset is stripe count before split.
 * 3. directory merge, @migrate_hash is hash type after merge,
 *    @migrate_offset is stripe count after merge.
 */
static inline int
__lmv_name_to_stripe_index(u32 hash_type, u32 stripe_count,
			   u32 migrate_hash, u32 migrate_offset,
			   const char *name, int namelen, bool new_layout)
{
	u32 saved_hash = hash_type;
	u32 saved_count = stripe_count;
	int stripe_index = 0;

	LASSERT(namelen > 0);
	LASSERT(stripe_count > 0);

	if (lmv_hash_is_splitting(hash_type)) {
		if (!new_layout) {
			hash_type = migrate_hash;
			stripe_count = migrate_offset;
		}
	} else if (lmv_hash_is_merging(hash_type)) {
		if (new_layout) {
			hash_type = migrate_hash;
			stripe_count = migrate_offset;
		}
	} else if (lmv_hash_is_migrating(hash_type)) {
		if (new_layout) {
			stripe_count = migrate_offset;
		} else {
			hash_type = migrate_hash;
			stripe_count -= migrate_offset;
		}
	}

	if (stripe_count > 1) {
		switch (hash_type & LMV_HASH_TYPE_MASK) {
		case LMV_HASH_TYPE_ALL_CHARS:
			stripe_index = lmv_hash_all_chars(stripe_count, name,
							  namelen);
			break;
		case LMV_HASH_TYPE_FNV_1A_64:
			stripe_index = lmv_hash_fnv1a(stripe_count, name,
						      namelen);
			break;
		case LMV_HASH_TYPE_CRUSH:
			stripe_index = lmv_hash_crush(stripe_count, name,
						      namelen, false);
			break;
		case LMV_HASH_TYPE_CRUSH2:
			stripe_index = lmv_hash_crush(stripe_count, name,
						      namelen, true);
			break;
		default:
			return -EBADFD;
		}
	}

	LASSERT(stripe_index < stripe_count);

	if (!new_layout && lmv_hash_is_migrating(saved_hash))
		stripe_index += migrate_offset;

	LASSERT(stripe_index < saved_count);

	CDEBUG(D_INFO, "name %.*s hash=%#x/%#x idx=%d/%u/%u under %s layout\n",
	       namelen, name, saved_hash, migrate_hash, stripe_index,
	       saved_count, migrate_offset, new_layout ? "new" : "old");

	return stripe_index;
}

static inline int lmv_name_to_stripe_index(struct lmv_mds_md_v1 *lmv,
					   const char *name, int namelen)
{
	if (lmv->lmv_magic == LMV_MAGIC_V1 ||
	    lmv->lmv_magic == LMV_MAGIC_STRIPE)
		return __lmv_name_to_stripe_index(lmv->lmv_hash_type,
						  lmv->lmv_stripe_count,
						  lmv->lmv_migrate_hash,
						  lmv->lmv_migrate_offset,
						  name, namelen, true);

	if (lmv->lmv_magic == cpu_to_le32(LMV_MAGIC_V1) ||
	    lmv->lmv_magic == cpu_to_le32(LMV_MAGIC_STRIPE))
		return __lmv_name_to_stripe_index(
					le32_to_cpu(lmv->lmv_hash_type),
					le32_to_cpu(lmv->lmv_stripe_count),
					le32_to_cpu(lmv->lmv_migrate_hash),
					le32_to_cpu(lmv->lmv_migrate_offset),
					name, namelen, true);

	return -EINVAL;
}

static inline int lmv_name_to_stripe_index_old(struct lmv_mds_md_v1 *lmv,
					       const char *name, int namelen)
{
	if (lmv->lmv_magic == LMV_MAGIC_V1 ||
	    lmv->lmv_magic == LMV_MAGIC_STRIPE)
		return __lmv_name_to_stripe_index(lmv->lmv_hash_type,
						  lmv->lmv_stripe_count,
						  lmv->lmv_migrate_hash,
						  lmv->lmv_migrate_offset,
						  name, namelen, false);

	if (lmv->lmv_magic == cpu_to_le32(LMV_MAGIC_V1) ||
	    lmv->lmv_magic == cpu_to_le32(LMV_MAGIC_STRIPE))
		return __lmv_name_to_stripe_index(
					le32_to_cpu(lmv->lmv_hash_type),
					le32_to_cpu(lmv->lmv_stripe_count),
					le32_to_cpu(lmv->lmv_migrate_hash),
					le32_to_cpu(lmv->lmv_migrate_offset),
					name, namelen, false);

	return -EINVAL;
}

static inline bool lmv_user_magic_supported(u32 lum_magic)
{
	return lum_magic == LMV_USER_MAGIC ||
	       lum_magic == LMV_USER_MAGIC_SPECIFIC ||
	       lum_magic == LMV_MAGIC_FOREIGN;
}

#define LMV_DEBUG(mask, lmv, msg)						   \
	CDEBUG_LIMIT(mask,							   \
		     "%s LMV: magic=%#x count=%u index=%u hash=%s:%#x version=%u migrate_offset=%u migrate_hash=%s:%x pool=%.*s\n",\
		     msg, (lmv)->lmv_magic, (lmv)->lmv_stripe_count,		   \
		     (lmv)->lmv_master_mdt_index,				   \
		     lmv_is_known_hash_type((lmv)->lmv_hash_type) ?		   \
		     mdt_hash_name[(lmv)->lmv_hash_type & LMV_HASH_TYPE_MASK] :	   \
		     "invalid", (lmv)->lmv_hash_type,				   \
		     (lmv)->lmv_layout_version, (lmv)->lmv_migrate_offset,	   \
		     lmv_is_known_hash_type((lmv)->lmv_migrate_hash) ?		   \
		     mdt_hash_name[(lmv)->lmv_migrate_hash & LMV_HASH_TYPE_MASK] : \
		     "invalid", (lmv)->lmv_migrate_hash,			   \
		     LOV_MAXPOOLNAME, lmv->lmv_pool_name)

/* master LMV is sane */
static inline bool lmv_is_sane(const struct lmv_mds_md_v1 *lmv)
{
	if (!lmv)
		return false;

	if (le32_to_cpu(lmv->lmv_magic) != LMV_MAGIC_V1)
		goto insane;

	if (le32_to_cpu(lmv->lmv_stripe_count) == 0)
		goto insane;

	if (!lmv_is_sane_hash_type(le32_to_cpu(lmv->lmv_hash_type)))
		goto insane;

	return true;
insane:
	LMV_DEBUG(D_ERROR, lmv, "unknown layout");
	return false;
}

/* LMV can be either master or stripe LMV */
static inline bool lmv_is_sane2(const struct lmv_mds_md_v1 *lmv)
{
	if (!lmv)
		return false;

	if (le32_to_cpu(lmv->lmv_magic) != LMV_MAGIC_V1 &&
	    le32_to_cpu(lmv->lmv_magic) != LMV_MAGIC_STRIPE)
		goto insane;

	if (le32_to_cpu(lmv->lmv_stripe_count) == 0)
		goto insane;

	if (!lmv_is_sane_hash_type(le32_to_cpu(lmv->lmv_hash_type)))
		goto insane;

	return true;
insane:
	LMV_DEBUG(D_ERROR, lmv, "unknown layout");
	return false;
}

static inline bool lmv_is_splitting(const struct lmv_mds_md_v1 *lmv)
{
	if (!lmv_is_sane2(lmv))
		return false;

	return lmv_hash_is_splitting(cpu_to_le32(lmv->lmv_hash_type));
}

static inline bool lmv_is_merging(const struct lmv_mds_md_v1 *lmv)
{
	if (!lmv_is_sane2(lmv))
		return false;

	return lmv_hash_is_merging(cpu_to_le32(lmv->lmv_hash_type));
}

static inline bool lmv_is_migrating(const struct lmv_mds_md_v1 *lmv)
{
	if (!lmv_is_sane(lmv))
		return false;

	return lmv_hash_is_migrating(cpu_to_le32(lmv->lmv_hash_type));
}

static inline bool lmv_is_restriping(const struct lmv_mds_md_v1 *lmv)
{
	if (!lmv_is_sane2(lmv))
		return false;

	return lmv_hash_is_splitting(cpu_to_le32(lmv->lmv_hash_type)) ||
	       lmv_hash_is_merging(cpu_to_le32(lmv->lmv_hash_type));
}

static inline bool lmv_is_layout_changing(const struct lmv_mds_md_v1 *lmv)
{
	if (!lmv_is_sane2(lmv))
		return false;

	return lmv_hash_is_splitting(cpu_to_le32(lmv->lmv_hash_type)) ||
	       lmv_hash_is_merging(cpu_to_le32(lmv->lmv_hash_type)) ||
	       lmv_hash_is_migrating(cpu_to_le32(lmv->lmv_hash_type));
}

#endif

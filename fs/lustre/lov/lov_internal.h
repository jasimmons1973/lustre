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
 */

#ifndef LOV_INTERNAL_H
#define LOV_INTERNAL_H

#include <obd_class.h>
#include <uapi/linux/lustre/lustre_idl.h>

/*
 * If we are unable to get the maximum object size from the OST in
 * ocd_maxbytes using OBD_CONNECT_MAXBYTES, then we fall back to using
 * the old maximum object size from ext3.
 */
#define LUSTRE_EXT3_STRIPE_MAXBYTES 0x1fffffff000ULL

struct lov_stripe_md_entry {
	struct lu_extent	lsme_extent;
	u32			lsme_id;
	u32			lsme_magic;
	u32			lsme_flags;
	u32			lsme_pattern;
	u64			lsme_timestamp;
	u32			lsme_stripe_size;
	u16			lsme_stripe_count;
	u16			lsme_layout_gen;
	char			lsme_pool_name[LOV_MAXPOOLNAME + 1];
	struct lov_oinfo       *lsme_oinfo[];
};

static inline bool lsme_is_dom(struct lov_stripe_md_entry *lsme)
{
	return (lov_pattern(lsme->lsme_pattern) == LOV_PATTERN_MDT);
}

static inline void copy_lsm_entry(struct lov_stripe_md_entry *dst,
				  struct lov_stripe_md_entry *src)
{
	unsigned int i;

	for (i = 0; i < src->lsme_stripe_count; i++)
		*dst->lsme_oinfo[i] = *src->lsme_oinfo[i];

	memcpy(dst, src, offsetof(typeof(*src), lsme_oinfo));
}

struct lov_stripe_md {
	atomic_t	lsm_refc;
	spinlock_t	lsm_lock;
	pid_t		lsm_lock_owner; /* debugging */

	union {
		/*
		 * maximum possible file size, might change as OSTs status
		 * changes, e.g. disconnected, deactivated
		 */
		loff_t          lsm_maxbytes;
		/* size of full foreign LOV */
		size_t          lsm_foreign_size;
	};
	struct ost_id	lsm_oi;
	u32		lsm_magic;
	u32		lsm_layout_gen;
	u16		lsm_flags;
	bool		lsm_is_released;
	u16		lsm_mirror_count;
	u16		lsm_entry_count;
	struct lov_stripe_md_entry *lsm_entries[];
};

#define lsm_foreign(lsm) (lsm->lsm_entries[0])

static inline bool lsme_is_foreign(const struct lov_stripe_md_entry *lsme)
{
	return lsme->lsme_magic == LOV_MAGIC_FOREIGN;
}

static inline bool lsm_entry_is_foreign(const struct lov_stripe_md *lsm,
					int index)
{
	return lsme_is_foreign(lsm->lsm_entries[index]);
}

static inline bool lsme_inited(const struct lov_stripe_md_entry *lsme)
{
	return lsme->lsme_flags & LCME_FL_INIT;
}

static inline bool lsm_entry_inited(const struct lov_stripe_md *lsm, int index)
{
	return lsme_inited(lsm->lsm_entries[index]);
}

static inline bool lsm_is_composite(u32 magic)
{
	return magic == LOV_MAGIC_COMP_V1;
}

static inline size_t lov_comp_md_size(const struct lov_stripe_md *lsm)
{
	struct lov_stripe_md_entry *lsme;
	size_t size;
	int entry;

	if (lsm->lsm_magic == LOV_MAGIC_V1 || lsm->lsm_magic == LOV_MAGIC_V3)
		return lov_mds_md_size(lsm->lsm_entries[0]->lsme_stripe_count,
				       lsm->lsm_entries[0]->lsme_magic);

	if (lsm->lsm_magic == LOV_MAGIC_FOREIGN)
		return lsm->lsm_foreign_size;

	LASSERT(lsm->lsm_magic == LOV_MAGIC_COMP_V1);

	size = sizeof(struct lov_comp_md_v1) +
	       sizeof(struct lov_comp_md_entry_v1) * lsm->lsm_entry_count;
	for (entry = 0; entry < lsm->lsm_entry_count; entry++) {
		u16 stripe_count;

		lsme = lsm->lsm_entries[entry];

		if (lsme_inited(lsme))
			stripe_count = lsme->lsme_stripe_count;
		else
			stripe_count = 0;

		size += lov_mds_md_size(stripe_count,
					lsme->lsme_magic);
	}

	return size;
}

static inline bool lsm_has_objects(struct lov_stripe_md *lsm)
{
	return lsm && !lsm->lsm_is_released;
}

static inline unsigned int lov_comp_index(int entry, int stripe)
{
	LASSERT(entry >= 0 && entry <= SHRT_MAX);
	LASSERT(stripe >= 0 && stripe < USHRT_MAX);

	return entry << 16 | stripe;
}

static inline int lov_comp_stripe(int index)
{
	return index & 0xffff;
}

static inline int lov_comp_entry(int index)
{
	return index >> 16;
}

struct lsm_operations {
	struct lov_stripe_md *(*lsm_unpackmd)(struct lov_obd *obd, void *buf,
					      size_t buf_len);
};

const struct lsm_operations *lsm_op_find(int magic);
void lsm_free(struct lov_stripe_md *lsm);

/* lov_do_div64(a, b) returns a % b, and a = a / b.
 * The 32-bit code is LOV-specific due to knowing about stripe limits in
 * order to reduce the divisor to a 32-bit number.  If the divisor is
 * already a 32-bit value the compiler handles this directly.
 */
#if BITS_PER_LONG == 64
# define lov_do_div64(n, base) ({		\
	u64 __base = (base);			\
	u64 __rem;				\
	__rem = ((u64)(n)) % __base;		\
	(n) = ((u64)(n)) / __base;		\
	__rem;					\
})
#elif BITS_PER_LONG == 32
# define lov_do_div64(n, base) ({					      \
	u64 __num = (n);						      \
	u64 __rem;							      \
	if ((sizeof(base) > 4) && (((base) & 0xffffffff00000000ULL) != 0)) {  \
		int __remainder;					      \
		LASSERTF(!((base) & (LOV_MIN_STRIPE_SIZE - 1)),		      \
			 "64 bit lov division %llu / %llu\n",		      \
			 __num, (u64)(base));				      \
		__remainder = __num & (LOV_MIN_STRIPE_SIZE - 1);	      \
		__num >>= LOV_MIN_STRIPE_BITS;				      \
		__rem = do_div(__num, (base) >> LOV_MIN_STRIPE_BITS);	      \
		__rem <<= LOV_MIN_STRIPE_BITS;				      \
		__rem += __remainder;					      \
	} else {							      \
		__rem = do_div(__num, base);				      \
	}								      \
	(n) = __num;							      \
	__rem;								      \
})
#endif

#define pool_tgt_count(p)	((p)->pool_obds.op_count)
#define pool_tgt_array(p)	((p)->pool_obds.op_array)
#define pool_tgt_rw_sem(p)	((p)->pool_obds.op_rw_sem)

struct pool_desc {
	char			 pool_name[LOV_MAXPOOLNAME + 1];
	struct lu_tgt_pool	 pool_obds;
	atomic_t		 pool_refcount;
	struct rhash_head	 pool_hash;		/* access by poolname */
	union {
		struct list_head	pool_list;	/* serial access */
		struct rcu_head		rcu;		/* delayed free */
	};
	struct dentry		*pool_debugfs_entry;	/* file in debugfs */
	struct obd_device	*pool_lobd;		/* owner */
};
int lov_pool_hash_init(struct rhashtable *tbl);
void lov_pool_hash_destroy(struct rhashtable *tbl);

struct lov_request {
	struct obd_info		rq_oi;
	struct lov_request_set *rq_rqset;

	struct list_head	rq_link;

	int			rq_idx;	/* index in lov->tgts array */
};

struct lov_request_set {
	struct obd_info		*set_oi;
	struct obd_device	*set_obd;
	int			set_count;
	atomic_t		set_completes;
	atomic_t		set_success;
	struct list_head	set_list;
};

extern struct kmem_cache *lov_oinfo_slab;

extern struct lu_kmem_descr lov_caches[];

#define lov_uuid2str(lv, index) \
	(char *)((lv)->lov_tgts[index]->ltd_uuid.uuid)

/* lov_merge.c */
int lov_merge_lvb_kms(struct lov_stripe_md *lsm, int index,
		      struct cl_attr *attr);

/* lov_offset.c */
u64 stripe_width(struct lov_stripe_md *lsm, unsigned int index);
u64 lov_stripe_size(struct lov_stripe_md *lsm, int index, u64 ost_size,
		    int stripeno);
int lov_stripe_offset(struct lov_stripe_md *lsm, int index, u64 lov_off,
		      int stripeno, u64 *obd_off);
u64 lov_size_to_stripe(struct lov_stripe_md *lsm, int index, u64 file_size,
		       int stripeno);
int lov_stripe_intersects(struct lov_stripe_md *lsm, int index, int stripeno,
			  struct lu_extent *ext, u64 *obd_start, u64 *obd_end);
int lov_stripe_number(struct lov_stripe_md *lsm, int index, u64 lov_off);
pgoff_t lov_stripe_pgoff(struct lov_stripe_md *lsm, int index,
			 pgoff_t stripe_index, int stripe);

/* lov_request.c */
int lov_prep_statfs_set(struct obd_device *obd, struct obd_info *oinfo,
			struct lov_request_set **reqset);
int lov_fini_statfs_set(struct lov_request_set *set);

/* lov_obd.c */
void lov_tgts_getref(struct obd_device *obd);
void lov_tgts_putref(struct obd_device *obd);
void lov_stripe_lock(struct lov_stripe_md *md);
void lov_stripe_unlock(struct lov_stripe_md *md);
void lov_fix_desc(struct lov_desc *desc);
void lov_fix_desc_stripe_size(u64 *val);
void lov_fix_desc_stripe_count(u32 *val);
void lov_fix_desc_pattern(u32 *val);
void lov_fix_desc_qos_maxage(u32 *val);
u16 lov_get_stripe_count(struct lov_obd *lov, u32 magic, u16 stripe_count);
int lov_connect_obd(struct obd_device *obd, u32 index, int activate,
		    struct obd_connect_data *data);
int lov_setup(struct obd_device *obd, struct lustre_cfg *lcfg);
int lov_process_config_base(struct obd_device *obd, struct lustre_cfg *lcfg,
			    u32 *indexp, int *genp);
int lov_del_target(struct obd_device *obd, u32 index,
		   struct obd_uuid *uuidp, int gen);

/* lov_pack.c */
ssize_t lov_lsm_pack(const struct lov_stripe_md *lsm, void *buf,
		     size_t buf_size);
struct lov_stripe_md *lov_unpackmd(struct lov_obd *lov, void *buf,
				   size_t buf_size);
int lov_free_memmd(struct lov_stripe_md **lsmp);

void lov_dump_lmm_v1(int level, struct lov_mds_md_v1 *lmm);
void lov_dump_lmm_common(int level, void *lmmp);

/* lov_ea.c */
void dump_lsm(unsigned int level, const struct lov_stripe_md *lsm);

/* lproc_lov.c */
int lov_tunables_init(struct obd_device *obd);

/* lov_cl.c */
extern struct lu_device_type lov_device_type;

#define LOV_MDC_TGT_MAX 256

/* high level pool methods */
int lov_pool_new(struct obd_device *obd, char *poolname);
int lov_pool_del(struct obd_device *obd, char *poolname);
int lov_pool_add(struct obd_device *obd, char *poolname, char *ostname);
int lov_pool_remove(struct obd_device *obd, char *poolname, char *ostname);
void lov_pool_putref(struct pool_desc *pool);

static inline struct lov_stripe_md *lsm_addref(struct lov_stripe_md *lsm)
{
	LASSERT(atomic_read(&lsm->lsm_refc) > 0);
	atomic_inc(&lsm->lsm_refc);
	return lsm;
}

static inline bool lov_oinfo_is_dummy(const struct lov_oinfo *loi)
{
	if (unlikely(loi->loi_oi.oi.oi_id == 0 &&
		     loi->loi_oi.oi.oi_seq == 0 &&
		     loi->loi_ost_idx == 0 &&
		     loi->loi_ost_gen == 0))
		return true;

	return false;
}

static inline struct obd_device *lov2obd(const struct lov_obd *lov)
{
	return container_of_safe(lov, struct obd_device, u.lov);
}

static inline void lov_lsm2layout(struct lov_stripe_md *lsm,
				  struct lov_stripe_md_entry *lsme,
				  struct ost_layout *ol)
{
	ol->ol_stripe_size = lsme->lsme_stripe_size;
	ol->ol_stripe_count = lsme->lsme_stripe_count;
	if (lsm->lsm_magic == LOV_MAGIC_COMP_V1) {
		ol->ol_comp_start = lsme->lsme_extent.e_start;
		ol->ol_comp_end = lsme->lsme_extent.e_end;
		ol->ol_comp_id = lsme->lsme_id;
	} else {
		ol->ol_comp_start = 0;
		ol->ol_comp_end = 0;
		ol->ol_comp_id = 0;
	}
}

struct pool_desc *lov_pool_find(struct obd_device *obd, char *poolname);
void lov_pool_putref(struct pool_desc *pool);
#endif

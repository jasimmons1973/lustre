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
 * Copyright (c) 2010, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/include/lustre/lustre_user.h
 *
 * Lustre public user-space interface definitions.
 */

#ifndef _LUSTRE_USER_H
#define _LUSTRE_USER_H

/** \defgroup lustreuser lustreuser
 *
 * @{
 */
#include <linux/string.h>
#ifndef __KERNEL__
# define __USE_ISOC99  1
# include <stdbool.h>
# include <stdio.h> /* snprintf() */
# include <sys/stat.h>

# define __USE_GNU	1
# define FILEID_LUSTRE 0x97 /* for name_to_handle_at() (and llapi_fd2fid()) */
#endif /* !__KERNEL__ */

#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/kernel.h>
#include <linux/stat.h>
#include <linux/quota.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/lustre/lustre_fiemap.h>
#include <linux/lustre/lustre_ver.h>

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef __STRICT_ANSI__
#define typeof  __typeof__
#endif

/*
 * We need to always use 64bit version because the structure
 * is shared across entire cluster where 32bit and 64bit machines
 * are co-existing.
 */
#if __BITS_PER_LONG != 64 || defined(__ARCH_WANT_STAT64)
typedef struct stat64	lstat_t;
#define lstat_f		lstat64
#define fstat_f		fstat64
#define fstatat_f	fstatat64
#else
typedef struct stat	lstat_t;
#define lstat_f		lstat
#define fstat_f		fstat
#define fstatat_f	fstatat
#endif

#define LUSTRE_EOF 0xffffffffffffffffULL

/* for statfs() */
#define LL_SUPER_MAGIC 0x0BD00BD0

#define LL_IOC_GETVERSION		_IOR('f', 3, long)
#define FSFILT_IOC_GETVERSION		LL_IOC_GETVERSION /* backward compat */

/* FIEMAP flags supported by Lustre */
#define LUSTRE_FIEMAP_FLAGS_COMPAT (FIEMAP_FLAG_SYNC | FIEMAP_FLAG_DEVICE_ORDER)

enum obd_statfs_state {
	OS_STATFS_DEGRADED	= 0x00000001, /**< RAID degraded/rebuilding */
	OS_STATFS_READONLY	= 0x00000002, /**< filesystem is read-only */
	OS_STATFS_NOPRECREATE	= 0x00000004, /**< no object precreation */
	OS_STATFS_UNUSED1	= 0x00000008, /**< obsolete 1.6, was EROFS=30 */
	OS_STATFS_UNUSED2	= 0x00000010, /**< obsolete 1.6, was EROFS=30 */
	OS_STATFS_ENOSPC	= 0x00000020, /**< not enough free space */
	OS_STATFS_ENOINO	= 0x00000040, /**< not enough inodes */
	OS_STATFS_SUM		= 0x00000100, /**< aggregated for all tagrets */
	OS_STATFS_NONROT	= 0x00000200, /**< non-rotational device */
};

struct obd_statfs {
	__u64	os_type;	/* EXT4_SUPER_MAGIC, UBERBLOCK_MAGIC */
	__u64	os_blocks;	/* total size in #os_bsize blocks */
	__u64	os_bfree;	/* number of unused blocks */
	__u64	os_bavail;	/* blocks available for allocation */
	__u64	os_files;	/* total number of objects */
	__u64	os_ffree;	/* # objects that could be created */
	__u8	os_fsid[40];	/* identifier for filesystem */
	__u32	os_bsize;	/* block size in bytes for os_blocks */
	__u32	os_namelen;	/* maximum length of filename in bytes*/
	__u64	os_maxbytes;	/* maximum object size in bytes */
	__u32	os_state;	/**< obd_statfs_state OS_STATFS_* flag */
	__u32	os_fprecreated;	/* objs available now to the caller
				 * used in QoS code to find preferred OSTs
				 */
	__u32	os_granted;	/* space granted for MDS */
	__u32	os_spare3;	/* Unused padding fields.  Remember */
	__u32	os_spare4;	/* to fix lustre_swab_obd_statfs() */
	__u32	os_spare5;
	__u32	os_spare6;
	__u32	os_spare7;
	__u32	os_spare8;
	__u32	os_spare9;
};

/**
 * File IDentifier.
 *
 * FID is a cluster-wide unique identifier of a file or an object (stripe).
 * FIDs are never reused.
 **/
struct lu_fid {
	/**
	 * FID sequence. Sequence is a unit of migration: all files (objects)
	 * with FIDs from a given sequence are stored on the same server.
	 * Lustre should support 2^64 objects, so even if each sequence
	 * has only a single object we can still enumerate 2^64 objects.
	 **/
	__u64 f_seq;
	/* FID number within sequence. */
	__u32 f_oid;
	/**
	 * FID version, used to distinguish different versions (in the sense
	 * of snapshots, etc.) of the same file system object. Not currently
	 * used.
	 **/
	__u32 f_ver;
} __attribute__((packed));

static inline bool fid_is_zero(const struct lu_fid *fid)
{
	return !fid->f_seq && !fid->f_oid;
}

/* The data name_to_handle_at() places in a struct file_handle (at f_handle) */
struct lustre_file_handle {
	struct lu_fid lfh_child;
	struct lu_fid lfh_parent;
};

struct ost_layout {
	__u32	ol_stripe_size;
	__u32	ol_stripe_count;
	__u64	ol_comp_start;
	__u64	ol_comp_end;
	__u32	ol_comp_id;
} __attribute__((packed));

/* Userspace should treat lu_fid as opaque, and only use the following methods
 * to print or parse them.  Other functions (e.g. compare, swab) could be moved
 * here from lustre_idl.h if needed.
 */
struct lu_fid;

/**
 * Following struct for object attributes, that will be kept inode's EA.
 * Introduced in 2.0 release (please see b15993, for details)
 * Added to all objects since Lustre 2.4 as contains self FID
 */
struct lustre_mdt_attrs {
	/**
	 * Bitfield for supported data in this structure. From enum lma_compat.
	 * lma_self_fid and lma_flags are always available.
	 */
	__u32   lma_compat;
	/**
	 * Per-file incompat feature list. Lustre version should support all
	 * flags set in this field. The supported feature mask is available in
	 * LMA_INCOMPAT_SUPP.
	 */
	__u32   lma_incompat;
	/** FID of this inode */
	struct lu_fid  lma_self_fid;
};

/**
 * Prior to 2.4, the LMA structure also included SOM attributes which has since
 * been moved to a dedicated xattr
 * lma_flags was also removed because of lma_compat/incompat fields.
 */
#define LMA_OLD_SIZE (sizeof(struct lustre_mdt_attrs) + 5 * sizeof(__u64))

enum lustre_som_flags {
	/* Unknown or no SoM data, must get size from OSTs. */
	SOM_FL_UNKNOWN	= 0x0000,
	/* Known strictly correct, FLR or DoM file (SoM guaranteed). */
	SOM_FL_STRICT	= 0x0001,
	/* Known stale - was right at some point in the past, but it is
	 * known (or likely) to be incorrect now (e.g. opened for write).
	 */
	SOM_FL_STALE	= 0x0002,
	/* Approximate, may never have been strictly correct,
	 * need to sync SOM data to achieve eventual consistency.
	 */
	SOM_FL_LAZY	= 0x0004,
};

struct lustre_som_attrs {
	__u16	lsa_valid;
	__u16	lsa_reserved[3];
	__u64	lsa_size;
	__u64	lsa_blocks;
};

/**
 * OST object IDentifier.
 */
struct ost_id {
	union {
		struct {
			__u64	oi_id;
			__u64	oi_seq;
		} oi;
		struct lu_fid oi_fid;
	};
} __attribute__((packed));

#define DOSTID "%#llx:%llu"
#define POSTID(oi) ostid_seq(oi), ostid_id(oi)

struct ll_futimes_3 {
	__u64 lfu_atime_sec;
	__u64 lfu_atime_nsec;
	__u64 lfu_mtime_sec;
	__u64 lfu_mtime_nsec;
	__u64 lfu_ctime_sec;
	__u64 lfu_ctime_nsec;
};

/*
 * Maximum number of mirrors currently implemented.
 */
#define LUSTRE_MIRROR_COUNT_MAX		16

/* Lease types for use as arg and return of LL_IOC_{GET,SET}_LEASE ioctl. */
enum ll_lease_mode {
	LL_LEASE_RDLCK	= 0x01,
	LL_LEASE_WRLCK	= 0x02,
	LL_LEASE_UNLCK	= 0x04,
};

enum ll_lease_flags {
	LL_LEASE_RESYNC		= 0x1,
	LL_LEASE_RESYNC_DONE	= 0x2,
	LL_LEASE_LAYOUT_MERGE	= 0x4,
	LL_LEASE_LAYOUT_SPLIT	= 0x8,
	LL_LEASE_PCC_ATTACH	= 0x10,
};

#define IOC_IDS_MAX	4096
struct ll_ioc_lease {
	__u32		lil_mode;
	__u32		lil_flags;
	__u32		lil_count;
	__u32		lil_ids[0];
};

struct ll_ioc_lease_id {
	__u32		lil_mode;
	__u32		lil_flags;
	__u32		lil_count;
	__u16		lil_mirror_id;
	__u16		lil_padding1;
	__u64		lil_padding2;
	__u32		lil_ids[0];
};

/*
 * The ioctl naming rules:
 * LL_*     - works on the currently opened filehandle instead of parent dir
 * *_OBD_*  - gets data for both OSC or MDC (LOV, LMV indirectly)
 * *_MDC_*  - gets/sets data related to MDC
 * *_LOV_*  - gets/sets data related to OSC/LOV
 * *FILE*   - called on parent dir and passes in a filename
 * *STRIPE* - set/get lov_user_md
 * *INFO    - set/get lov_user_mds_data
 */
/*	lustre_ioctl.h			101-150 */
/* ioctl codes 128-143 are reserved for fsverity */
#define LL_IOC_GETFLAGS			_IOR('f', 151, long)
#define LL_IOC_SETFLAGS			_IOW('f', 152, long)
#define LL_IOC_CLRFLAGS			_IOW('f', 153, long)
#define LL_IOC_LOV_SETSTRIPE		_IOW('f', 154, long)
#define LL_IOC_LOV_SETSTRIPE_NEW	_IOWR('f', 154, struct lov_user_md)
#define LL_IOC_LOV_GETSTRIPE		_IOW('f', 155, long)
#define LL_IOC_LOV_GETSTRIPE_NEW	_IOR('f', 155, struct lov_user_md)
#define LL_IOC_LOV_SETEA		_IOW('f', 156, long)
#define LL_IOC_GROUP_LOCK		_IOW('f', 158, long)
#define LL_IOC_GROUP_UNLOCK		_IOW('f', 159, long)
#define IOC_OBD_STATFS			_IOWR('f', 164, struct obd_statfs *)
#define LL_IOC_FLUSHCTX			_IOW('f', 166, long)
#define LL_IOC_GETOBDCOUNT		_IOR('f', 168, long)
#define LL_IOC_LLOOP_ATTACH		_IOWR('f', 169, long)
#define LL_IOC_LLOOP_DETACH		_IOWR('f', 170, long)
#define LL_IOC_LLOOP_INFO		_IOWR('f', 171, struct lu_fid)
#define LL_IOC_LLOOP_DETACH_BYDEV	_IOWR('f', 172, long)
#define LL_IOC_PATH2FID			_IOR('f', 173, long)
#define LL_IOC_GET_CONNECT_FLAGS	_IOWR('f', 174, __u64 *)
#define LL_IOC_GET_MDTIDX		_IOR('f', 175, int)
#define LL_IOC_FUTIMES_3		_IOWR('f', 176, struct ll_futimes_3)
#define LL_IOC_FLR_SET_MIRROR		_IOW('f', 177, long)
/*	lustre_ioctl.h			177-210 */
#define LL_IOC_HSM_STATE_GET		_IOR('f', 211, struct hsm_user_state)
#define LL_IOC_HSM_STATE_SET		_IOW('f', 212, struct hsm_state_set)
#define LL_IOC_HSM_CT_START		_IOW('f', 213, struct lustre_kernelcomm)
#define LL_IOC_HSM_COPY_START		_IOW('f', 214, struct hsm_copy *)
#define LL_IOC_HSM_COPY_END		_IOW('f', 215, struct hsm_copy *)
#define LL_IOC_HSM_PROGRESS		_IOW('f', 216, struct hsm_user_request)
#define LL_IOC_HSM_REQUEST		_IOW('f', 217, struct hsm_user_request)
#define LL_IOC_DATA_VERSION		_IOR('f', 218, struct ioc_data_version)
#define LL_IOC_LOV_SWAP_LAYOUTS		_IOW('f', 219, \
						struct lustre_swap_layouts)
#define LL_IOC_HSM_ACTION		_IOR('f', 220, \
						struct hsm_current_action)
/* see <lustre_lib.h> for ioctl numbers 221-233 */
#define LL_IOC_LMV_SETSTRIPE		_IOWR('f', 240, struct lmv_user_md)
#define LL_IOC_LMV_GETSTRIPE		_IOWR('f', 241, struct lmv_user_md)
#define LL_IOC_RMFID			_IOR('f', 242, struct fid_array)
#define LL_IOC_UNLOCK_FOREIGN		_IO('f', 242)
#define LL_IOC_SET_LEASE		_IOWR('f', 243, struct ll_ioc_lease)
#define LL_IOC_SET_LEASE_OLD		_IOWR('f', 243, long)
#define LL_IOC_GET_LEASE		_IO('f', 244)
#define LL_IOC_HSM_IMPORT		_IOWR('f', 245, struct hsm_user_import)
#define LL_IOC_LMV_SET_DEFAULT_STRIPE	_IOWR('f', 246, struct lmv_user_md)
#define LL_IOC_MIGRATE			_IOR('f', 247, int)
#define LL_IOC_FID2MDTIDX		_IOWR('f', 248, struct lu_fid)
#define LL_IOC_GETPARENT		_IOWR('f', 249, struct getparent)
#define LL_IOC_LADVISE			_IOR('f', 250, struct llapi_lu_ladvise)
#define LL_IOC_HEAT_GET			_IOWR('f', 251, struct lu_heat)
#define LL_IOC_HEAT_SET			_IOW('f', 251, __u64)
#define LL_IOC_PCC_ATTACH		_IOW('f', 252, struct lu_pcc_attach)
#define LL_IOC_PCC_DETACH		_IOW('f', 252, struct lu_pcc_detach)
#define LL_IOC_PCC_DETACH_BY_FID	_IOW('f', 252, struct lu_pcc_detach_fid)
#define LL_IOC_PCC_STATE		_IOR('f', 252, struct lu_pcc_state)
#define LL_IOC_PROJECT			_IOW('f', 253, struct lu_project)

#define LL_STATFS_LMV		1
#define LL_STATFS_LOV		2
#define LL_STATFS_NODELAY	4

#define IOC_MDC_TYPE		'i'
#define IOC_MDC_LOOKUP		_IOWR(IOC_MDC_TYPE, 20, struct obd_device *)
#define IOC_MDC_GETFILESTRIPE	_IOWR(IOC_MDC_TYPE, 21, struct lov_user_md *)
#define IOC_MDC_GETFILEINFO_V1	_IOWR(IOC_MDC_TYPE, 22, struct lov_user_mds_data_v1 *)
#define IOC_MDC_GETFILEINFO_V2	_IOWR(IOC_MDC_TYPE, 22, struct lov_user_mds_data)
#define LL_IOC_MDC_GETINFO_V1	_IOWR(IOC_MDC_TYPE, 23, struct lov_user_mds_data_v1 *)
#define LL_IOC_MDC_GETINFO_V2	_IOWR(IOC_MDC_TYPE, 23, struct lov_user_mds_data)
#define IOC_MDC_GETFILEINFO	IOC_MDC_GETFILEINFO_V1
#define LL_IOC_MDC_GETINFO	LL_IOC_MDC_GETINFO_V1

#define MAX_OBD_NAME 128 /* If this changes, a NEW ioctl must be added */

/* Define O_LOV_DELAY_CREATE to be a mask that is not useful for regular
 * files, but are unlikely to be used in practice and are not harmful if
 * used incorrectly.  O_NOCTTY and FASYNC are only meaningful for character
 * devices and are safe for use on new files (See LU-812, LU-4209).
 */
#define O_LOV_DELAY_CREATE	(O_NOCTTY | FASYNC)
/* O_FILE_ENC principle is similar to O_LOV_DELAY_CREATE above,
 * for access to encrypted files without the encryption key.
 */
#define O_FILE_ENC		(O_NOCTTY | O_NDELAY)

#define LL_FILE_IGNORE_LOCK	0x00000001
#define LL_FILE_GROUP_LOCKED	0x00000002
#define LL_FILE_READAHEA	0x00000004
#define LL_FILE_LOCKED_DIRECTIO 0x00000008 /* client-side locks with dio */
#define LL_FILE_FLOCK_WARNING	0x00000020 /* warned about disabled flock */

#define LOV_USER_MAGIC_V1	0x0BD10BD0
#define LOV_USER_MAGIC		LOV_USER_MAGIC_V1
#define LOV_USER_MAGIC_JOIN_V1	0x0BD20BD0
#define LOV_USER_MAGIC_V3	0x0BD30BD0
/* 0x0BD40BD0 is occupied by LOV_MAGIC_MIGRATE */
#define LOV_USER_MAGIC_SPECIFIC	0x0BD50BD0	/* for specific OSTs */
#define LOV_USER_MAGIC_COMP_V1	0x0BD60BD0
#define LOV_USER_MAGIC_FOREIGN	0x0BD70BD0

#define LMV_USER_MAGIC		0x0CD30CD0	/*default lmv magic*/
#define LMV_USER_MAGIC_SPECIFIC	0x0CD40CD0

#define LOV_PATTERN_NONE		0x000
#define LOV_PATTERN_RAID0		0x001

#define LOV_PATTERN_RAID1		0x002
#define LOV_PATTERN_MDT			0x100
#define LOV_PATTERN_OVERSTRIPING	0x200
#define LOV_PATTERN_FOREIGN		0x400
#define LOV_PATTERN_COMPRESS		0x800

#define LOV_PATTERN_F_MASK	0xffff0000
#define LOV_PATTERN_F_HOLE	0x40000000 /* there is hole in LOV EA */
#define LOV_PATTERN_F_RELEASED	0x80000000 /* HSM released file */

#define LOV_OFFSET_DEFAULT      ((__u16)-1)
#define LMV_OFFSET_DEFAULT      ((__u32)-1)

static inline bool lov_pattern_supported(__u32 pattern)
{
	return (pattern & ~LOV_PATTERN_F_RELEASED) == LOV_PATTERN_RAID0 ||
	       (pattern & ~LOV_PATTERN_F_RELEASED) ==
			(LOV_PATTERN_RAID0 | LOV_PATTERN_OVERSTRIPING) ||
	       (pattern & ~LOV_PATTERN_F_RELEASED) == LOV_PATTERN_MDT;
}

/* RELEASED and MDT patterns are not valid in many places, so rather than
 * having many extra checks on lov_pattern_supported, we have this separate
 * check for non-released, non-DOM components
 */
static inline bool lov_pattern_supported_normal_comp(__u32 pattern)
{
	return pattern == LOV_PATTERN_RAID0 ||
	       pattern == (LOV_PATTERN_RAID0 | LOV_PATTERN_OVERSTRIPING);

}

#define LOV_MAXPOOLNAME 15
#define LOV_POOLNAMEF "%.15s"
/* The poolname "ignore" is used to force a component creation without pool */
#define LOV_POOL_IGNORE "ignore"
/* The poolname "inherit" is used to force a component to inherit the pool from
 * parent or root directory
 */
#define LOV_POOL_INHERIT "inherit"
/* The poolname "none" is deprecated in 2.15 (same behavior as "inherit") */
#define LOV_POOL_NONE "none"

static inline bool lov_pool_is_ignored(const char *pool)
{
	return pool && strncmp(pool, LOV_POOL_IGNORE, LOV_MAXPOOLNAME) == 0;
}

static inline bool lov_pool_is_inherited(const char *pool)
{
	return pool && (strncmp(pool, LOV_POOL_INHERIT, LOV_MAXPOOLNAME) == 0 ||
			strncmp(pool, LOV_POOL_NONE, LOV_MAXPOOLNAME) == 0);
}

static inline bool lov_pool_is_reserved(const char *pool)
{
	return lov_pool_is_ignored(pool) || lov_pool_is_inherited(pool);
}

#define LOV_MIN_STRIPE_BITS	16	/* maximum PAGE_SIZE (ia64), power of 2 */
#define LOV_MIN_STRIPE_SIZE	(1 << LOV_MIN_STRIPE_BITS)
#define LOV_MAX_STRIPE_COUNT_OLD 160
/* This calculation is crafted so that input of 4096 will result in 160
 * which in turn is equal to old maximal stripe count.
 * XXX: In fact this is too simplified for now, what it also need is to get
 * ea_type argument to clearly know how much space each stripe consumes.
 *
 * The limit of 12 pages is somewhat arbitrary, but is a reasonably large
 * allocation that is sufficient for the current generation of systems.
 *
 * (max buffer size - lov+rpc header) / sizeof(struct lov_ost_data_v1)
 */
#define LOV_MAX_STRIPE_COUNT	2000  /* ~((12 * 4096 - 256) / 24) */
#define LOV_ALL_STRIPES		0xffff /* only valid for directories */
#define LOV_V1_INSANE_STRIPE_COUNT 65532 /* maximum stripe count bz13933 */

#define XATTR_LUSTRE_PREFIX	"lustre."
#define XATTR_LUSTRE_LOV	"lustre.lov"

#define lov_user_ost_data lov_user_ost_data_v1
struct lov_user_ost_data_v1 {	/* per-stripe data structure */
	struct ost_id l_ost_oi;	/* OST object ID */
	__u32 l_ost_gen;	/* generation of this OST index */
	__u32 l_ost_idx;	/* OST index in LOV */
} __attribute__((packed));

#define lov_user_md lov_user_md_v1
struct lov_user_md_v1 {		/* LOV EA user data (host-endian) */
	__u32 lmm_magic;	/* magic number = LOV_USER_MAGIC_V1 */
	__u32 lmm_pattern;	/* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
	struct ost_id lmm_oi;	/* LOV object ID */
	__u32 lmm_stripe_size;	/* size of stripe in bytes */
	__u16 lmm_stripe_count;	/* num stripes in use for this object */
	union {
		__u16 lmm_stripe_offset;	/* starting stripe offset in
						 * lmm_objects, use when writing
						 */
		__u16 lmm_layout_gen;		/* layout generation number
						 * used when reading
						 */
	};
	struct lov_user_ost_data_v1 lmm_objects[0]; /* per-stripe data */
} __attribute__((packed, __may_alias__));

struct lov_user_md_v3 {		/* LOV EA user data (host-endian) */
	__u32 lmm_magic;	/* magic number = LOV_USER_MAGIC_V3 */
	__u32 lmm_pattern;	/* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
	struct ost_id lmm_oi;	/* LOV object ID */
	__u32 lmm_stripe_size;	/* size of stripe in bytes */
	__u16 lmm_stripe_count;	/* num stripes in use for this object */
	union {
		__u16 lmm_stripe_offset;	/* starting stripe offset in
						 * lmm_objects, use when writing
						 */
		__u16 lmm_layout_gen;		/* layout generation number
						 * used when reading
						 */
	};
	char  lmm_pool_name[LOV_MAXPOOLNAME + 1];   /* pool name */
	struct lov_user_ost_data_v1 lmm_objects[0]; /* per-stripe data */
} __attribute__((packed, __may_alias__));

struct lov_foreign_md {
	__u32 lfm_magic;	/* magic number = LOV_MAGIC_FOREIGN */
	__u32 lfm_length;	/* length of lfm_value */
	__u32 lfm_type;		/* type, see LU_FOREIGN_TYPE_ */
	__u32 lfm_flags;	/* flags, type specific */
	char lfm_value[];
} __attribute__((packed));

#define foreign_size(lfm) (((struct lov_foreign_md *)lfm)->lfm_length + \
			   offsetof(struct lov_foreign_md, lfm_value))

#define foreign_size_le(lfm) \
	(le32_to_cpu(((struct lov_foreign_md *)lfm)->lfm_length) + \
	offsetof(struct lov_foreign_md, lfm_value))

struct lu_extent {
	__u64	e_start;
	__u64	e_end;
} __attribute__((packed));

#define DEXT "[%#llx, %#llx)"
#define PEXT(ext) (unsigned long long)(ext)->e_start, (unsigned long long)(ext)->e_end

static inline bool lu_extent_is_overlapped(struct lu_extent *e1,
					    struct lu_extent *e2)
{
	return e1->e_start < e2->e_end && e2->e_start < e1->e_end;
}

static inline bool lu_extent_is_whole(struct lu_extent *e)
{
	return e->e_start == 0 && e->e_end == LUSTRE_EOF;
}

enum lov_comp_md_entry_flags {
	LCME_FL_STALE		= 0x00000001,	/* FLR: stale data */
	LCME_FL_PREF_RD		= 0x00000002,	/* FLR: preferred for reading */
	LCME_FL_PREF_WR		= 0x00000004,	/* FLR: preferred for writing */
	LCME_FL_PREF_RW		= LCME_FL_PREF_RD | LCME_FL_PREF_WR,
	LCME_FL_OFFLINE		= 0x00000008,	/* Not used */
	LCME_FL_INIT		= 0x00000010,	/* instantiated */
	LCME_FL_NOSYNC		= 0x00000020,	/* FLR: no sync for the mirror */
	LCME_FL_EXTENSION	= 0x00000040,	/* extension comp, never init */
	LCME_FL_PARITY		= 0x00000080,	/* EC: a parity code component */
	LCME_FL_COMPRESS	= 0x00000100,	/* the component should be
						 * compressed
						 */
	LCME_FL_PARTIAL		= 0x00000200,	/* some chunks in the component
						 * are uncompressed
						 */
	LCME_FL_NOCOMPR		= 0x00000400,	/* the component should not be
						 * compressed
						 */
	LCME_FL_NEG		= 0x80000000,	/* used to indicate a negative
						 * flag, won't be stored on disk
						 */
};

#define LCME_KNOWN_FLAGS	(LCME_FL_NEG | LCME_FL_INIT | LCME_FL_STALE | \
				 LCME_FL_PREF_RW | LCME_FL_NOSYNC | \
				 LCME_FL_EXTENSION)

/* The mirror flags sent by client */
#define LCME_MIRROR_FLAGS	(LCME_FL_NOSYNC)

/* lcme_id can be specified as certain flags, and the first
 * bit of lcme_id is used to indicate that the ID is representing
 * certain LCME_FL_* but not a real ID. Which implies we can have
 * at most 31 flags (see LCME_FL_XXX).
 */
enum lcme_id {
	LCME_ID_INVAL	= 0x0,
	LCME_ID_MAX	= 0x7FFFFFFF,
	LCME_ID_ALL	= 0xFFFFFFFF,
	LCME_ID_NOT_ID	= LCME_FL_NEG
};

/* layout version equals to lcme_id, except some bits have special meanings */
enum layout_version_flags {
	/* layout version reaches the high water mark to be increased to
	 * circularly reuse the smallest value
	 */
	LU_LAYOUT_HIGEN		= 0x40000000,
	/* the highest bit is used to mark if the file is being resynced */
	LU_LAYOUT_RESYNC	= 0x80000000,
};

struct lov_comp_md_entry_v1 {
	__u32			lcme_id;	/* unique id of component */
	__u32			lcme_flags;	/* LCME_FL_XXX */
	/* file extent for component. If it's an EC code component, its flags
	 * contains LCME_FL_PARITY, and its extent covers the same extent of
	 * its corresponding data component.
	 */
	struct lu_extent	lcme_extent;
	__u32			lcme_offset;	/* offset of component blob,
						 * start from lov_comp_md_v1
						 */
	__u32			lcme_size;	/* size of component blob */
	__u32			lcme_layout_gen;
	__u64			lcme_timestamp;	/* snapshot time if applicable*/
	__u8			lcme_dstripe_count;	/* data stripe count,
							 * k value in EC
							 */
	__u8			lcme_cstripe_count;	/* code stripe count,
							 * p value in EC
							 */
	__u8			lcme_compr_type;	/* compress type */
	__u8			lcme_compr_lvl:4;	/* compress level */
	__u8			lcme_compr_chunk_log_bits:4;
				     /* chunk_size = 2^(16+chunk_log_bits)
				      * i.e. power-of-two multiple of 64KiB
				      */
} __attribute__((packed));

#define SEQ_ID_MAX		0x0000FFFF
#define SEQ_ID_MASK		SEQ_ID_MAX
/* bit 30:16 of lcme_id is used to store mirror id */
#define MIRROR_ID_MASK		0x7FFF0000
#define MIRROR_ID_NEG		0x8000
#define MIRROR_ID_SHIFT		16

static inline __u32 pflr_id(__u16 mirror_id, __u16 seqid)
{
	return ((mirror_id << MIRROR_ID_SHIFT) & MIRROR_ID_MASK) | seqid;
}

static inline __u16 mirror_id_of(__u32 id)
{
	return (id & MIRROR_ID_MASK) >> MIRROR_ID_SHIFT;
}

/**
 * on-disk data for lcm_flags. Valid if lcm_magic is LOV_MAGIC_COMP_V1.
 */
enum lov_comp_md_flags {
	/* the least 4 bits are used by FLR to record file state */
	LCM_FL_NONE             = 0x0,
	LCM_FL_RDONLY           = 0x1,
	LCM_FL_WRITE_PENDING    = 0x2,
	LCM_FL_SYNC_PENDING     = 0x3,
	LCM_FL_PCC_RDONLY	= 0x8,
	LCM_FL_FLR_MASK         = 0xB,
};

struct lov_comp_md_v1 {
	__u32	lcm_magic;	/* LOV_USER_MAGIC_COMP_V1 */
	__u32	lcm_size;	/* overall size including this struct */
	__u32	lcm_layout_gen;
	__u16	lcm_flags;
	__u16	lcm_entry_count;
	/* lcm_mirror_count stores the number of actual mirrors minus 1,
	 * so that non-flr files will have value 0 meaning 1 mirror.
	 */
	__u16	lcm_mirror_count;
	/* code components count, non-EC file contains 0 ec_count */
	__u8	lcm_ec_count;
	__u8	lcm_padding3[1];
	__u16	lcm_padding1[2];
	__u64	lcm_padding2;
	struct lov_comp_md_entry_v1 lcm_entries[0];
} __attribute__((packed));

static inline __u32 lov_user_md_size(__u16 stripes, __u32 lmm_magic)
{
	if (stripes == (__u16)-1)
		stripes = 0;

	if (lmm_magic == LOV_USER_MAGIC_V1)
		return sizeof(struct lov_user_md_v1) +
				stripes * sizeof(struct lov_user_ost_data_v1);
	return sizeof(struct lov_user_md_v3) +
		stripes * sizeof(struct lov_user_ost_data_v1);
}

/* Compile with -D_LARGEFILE64_SOURCE or -D_GNU_SOURCE (or #define) to
 * use this.  It is unsafe to #define those values in this header as it
 * is possible the application has already #included <sys/stat.h>.
 */
#define lov_user_mds_data lov_user_mds_data_v2
struct lov_user_mds_data_v1 {
	lstat_t lmd_st;			/* MDS stat struct */
	struct lov_user_md_v1 lmd_lmm;	/* LOV EA V1 user data */
} __attribute__((packed));

struct lov_user_mds_data_v2 {
	struct lu_fid lmd_fid;		/* Lustre FID */
	struct statx lmd_stx;		/* MDS statx struct */
	__u64 lmd_flags;		/* MDS stat flags */
	__u32 lmd_lmmsize;		/* LOV EA size */
	__u32 lmd_padding;		/* unused */
	struct lov_user_md_v1 lmd_lmm;	/* LOV EA user data */
} __attribute__((packed));

struct lov_user_mds_data_v3 {
	lstat_t lmd_st;			/* MDS stat struct */
	struct lov_user_md_v3 lmd_lmm;	/* LOV EA V3 user data */
} __attribute__((packed));

struct lmv_user_mds_data {
	struct lu_fid	lum_fid;
	__u32		lum_padding;
	__u32		lum_mds;
} __attribute__((packed, __may_alias__));

enum lmv_hash_type {
	LMV_HASH_TYPE_UNKNOWN	= 0,	/* 0 is reserved for testing purpose */
	LMV_HASH_TYPE_ALL_CHARS = 1,	/* simple sum of characters */
	LMV_HASH_TYPE_FNV_1A_64 = 2,	/* reasonable non-cryptographic hash */
	LMV_HASH_TYPE_CRUSH	= 3,	/* double-hash to optimize migration */
	LMV_HASH_TYPE_CRUSH2	= 4,	/* CRUSH with small fixes, LU-15692 */
	LMV_HASH_TYPE_MAX,
	LMV_HASH_TYPE_DEFAULT	= LMV_HASH_TYPE_FNV_1A_64
};

static __attribute__((unused)) const char *mdt_hash_name[] = {
	"none",
	"all_char",
	"fnv_1a_64",
	"crush",
	"crush2",
};


/* Right now only the lower part(0-16bits) of lmv_hash_type is being used,
 * and the higher part will be the flag to indicate the status of object,
 * for example the object is being migrated. And the hash function
 * might be interpreted differently with different flags.
 */
#define LMV_HASH_TYPE_MASK		0x0000ffff

static inline bool lmv_is_known_hash_type(__u32 type)
{
	return (type & LMV_HASH_TYPE_MASK) > LMV_HASH_TYPE_UNKNOWN &&
	       (type & LMV_HASH_TYPE_MASK) < LMV_HASH_TYPE_MAX;
}

/* This flag indicates that overstriping (>1 stripe per MDT) is desired */
#define LMV_HASH_FLAG_OVERSTRIPED	0x01000000
/* fixed layout, such directories won't split automatically */
/* NB, update LMV_HASH_FLAG_KNOWN when adding new flag */
#define LMV_HASH_FLAG_FIXED		0x02000000
#define LMV_HASH_FLAG_MERGE		0x04000000
#define LMV_HASH_FLAG_SPLIT		0x08000000

/* The striped directory has ever lost its master LMV EA, then LFSCK
 * re-generated it. This flag is used to indicate such case. It is an
 * on-disk flag.
 */
#define LMV_HASH_FLAG_LOST_LMV		0x10000000

#define LMV_HASH_FLAG_BAD_TYPE		0x20000000
#define LMV_HASH_FLAG_MIGRATION		0x80000000

#define LMV_HASH_FLAG_LAYOUT_CHANGE	\
	(LMV_HASH_FLAG_MIGRATION | LMV_HASH_FLAG_SPLIT | LMV_HASH_FLAG_MERGE)

#define LMV_HASH_FLAG_KNOWN		0xbe000000

/* migration failure may leave hash type as
 * LMV_HASH_TYPE_UNKNOWN|LMV_HASH_FLAG_BAD_TYPE, which should be treated as
 * sane, so such directory can be accessed (resume migration or unlink).
 */
static inline bool lmv_is_sane_hash_type(__u32 type)
{
	return lmv_is_known_hash_type(type) ||
	       type == (LMV_HASH_TYPE_UNKNOWN | LMV_HASH_FLAG_BAD_TYPE);
}

/* both SPLIT and MIGRATION are set for directory split */
static inline bool lmv_hash_is_splitting(__u32 hash)
{
	return (hash & LMV_HASH_FLAG_LAYOUT_CHANGE) ==
		(LMV_HASH_FLAG_SPLIT | LMV_HASH_FLAG_MIGRATION);
}

/* both MERGE and MIGRATION are set for directory merge */
static inline bool lmv_hash_is_merging(__u32 hash)
{
	return (hash & LMV_HASH_FLAG_LAYOUT_CHANGE) ==
		(LMV_HASH_FLAG_MERGE | LMV_HASH_FLAG_MIGRATION);
}

/* only MIGRATION is set for directory migration */
static inline bool lmv_hash_is_migrating(__u32 hash)
{
	return (hash & LMV_HASH_FLAG_LAYOUT_CHANGE) == LMV_HASH_FLAG_MIGRATION;
}

static inline bool lmv_hash_is_restriping(__u32 hash)
{
	return lmv_hash_is_splitting(hash) || lmv_hash_is_merging(hash);
}

static inline bool lmv_hash_is_layout_changing(__u32 hash)
{
	return lmv_hash_is_splitting(hash) || lmv_hash_is_merging(hash) ||
	       lmv_hash_is_migrating(hash);
}

struct lustre_foreign_type {
	__u32		lft_type;
	const char	*lft_name;
};

/**
 * LOV/LMV foreign types
 **/
enum lustre_foreign_types {
	LU_FOREIGN_TYPE_NONE = 0,
	/* HSM copytool lhsm_posix */
	LU_FOREIGN_TYPE_POSIX	= 1,
	/* Used for PCC-RW. PCCRW components are local to a single archive. */
	LU_FOREIGN_TYPE_PCCRW	= 2,
	/* Used for PCC-RO. PCCRO components may be shared between archives. */
	LU_FOREIGN_TYPE_PCCRO	= 3,
	/* Used for S3 */
	LU_FOREIGN_TYPE_S3	= 4,
	/* Used for DAOS */
	LU_FOREIGN_TYPE_SYMLINK = 0xda05,
	/* must be the max/last one */
	LU_FOREIGN_TYPE_UNKNOWN	= 0xffffffff,
};

extern struct lustre_foreign_type lu_foreign_types[];

/*
 * Got this according to how get LOV_MAX_STRIPE_COUNT, see above,
 * (max buffer size - lmv+rpc header) / sizeof(struct lmv_user_mds_data)
 */
#define LMV_MAX_STRIPE_COUNT 2000  /* ((12 * 4096 - 256) / 24) */
#define lmv_user_md lmv_user_md_v1
struct lmv_user_md_v1 {
	__u32	lum_magic;		/* must be the first field */
	__u32	lum_stripe_count;	/* dirstripe count */
	__u32	lum_stripe_offset;	/* MDT idx for default dirstripe */
	__u32	lum_hash_type;		/* Dir stripe policy */
	__u32	lum_type;		/* LMV type: default */
	__u8	lum_max_inherit;	/* inherit depth of default LMV */
	__u8	lum_max_inherit_rr;	/* inherit depth of default LMV to
					 * round-robin mkdir
					 */
	__u16	lum_padding1;
	__u32	lum_padding2;
	__u32	lum_padding3;
	char	lum_pool_name[LOV_MAXPOOLNAME + 1];
	struct lmv_user_mds_data  lum_objects[0];
} __attribute__((packed));

static inline __u32 lmv_foreign_to_md_stripes(__u32 size)
{
	if (size <= sizeof(struct lmv_user_md))
		return 0;

	size -= sizeof(struct lmv_user_md);
	return (size + sizeof(struct lmv_user_mds_data) - 1) /
	       sizeof(struct lmv_user_mds_data);
}

/*
 * NB, historically default layout didn't set type, but use XATTR name to differ
 * from normal layout, for backward compatibility, define LMV_TYPE_DEFAULT 0x0,
 * and still use the same method.
 */
enum lmv_type {
	LMV_TYPE_DEFAULT = 0x0000,
	/* fetch raw default LMV set on directory inode */
	LMV_TYPE_RAW	 = 0x0001,
};

/* lum_max_inherit will be decreased by 1 after each inheritance if it's not
 * LMV_INHERIT_UNLIMITED or > LMV_INHERIT_MAX.
 */
enum {
	/* for historical reason, 0 means unlimited inheritance */
	LMV_INHERIT_UNLIMITED		= 0,
	/* unlimited lum_max_inherit by default for plain stripe (0 or 1) */
	LMV_INHERIT_DEFAULT_PLAIN	= LMV_INHERIT_UNLIMITED,
	/* not inherit any more */
	LMV_INHERIT_END			= 1,
	/* for multiple stripes, the default lum_max_inherit is 3 */
	LMV_INHERIT_DEFAULT_STRIPED	= 3,
	/* max inherit depth */
	LMV_INHERIT_MAX			= 250,
	/* [251, 254] are reserved */
	/* not set, or when inherit depth goes beyond end,  */
	LMV_INHERIT_NONE		= 255,
};

enum {
	/* not set, or when inherit_rr depth goes beyond end,  */
	LMV_INHERIT_RR_NONE		= 0,
	/* disable lum_max_inherit_rr by default */
	LMV_INHERIT_RR_DEFAULT		= LMV_INHERIT_RR_NONE,
	/* not inherit any more */
	LMV_INHERIT_RR_END		= 1,
	/* default inherit_rr of ROOT */
	LMV_INHERIT_RR_ROOT		= 3,
	/* max inherit depth */
	LMV_INHERIT_RR_MAX		= 250,
	/* [251, 254] are reserved */
	/* unlimited inheritance */
	LMV_INHERIT_RR_UNLIMITED	= 255,
};

static inline int lmv_user_md_size(int stripes, int lmm_magic)
{
	int size = sizeof(struct lmv_user_md);

	if (lmm_magic == LMV_USER_MAGIC_SPECIFIC)
		size += stripes * sizeof(struct lmv_user_mds_data);

	return size;
}

struct ll_recreate_obj {
	__u64 lrc_id;
	__u32 lrc_ost_idx;
};

struct ll_fid {
	__u64 id;		/* holds object id */
	__u32 generation;	/* holds object generation */
	__u32 f_type;		/* holds object type or stripe idx when
				 * passing it to OST for saving into EA.
				 */
};

#define UUID_MAX	40
struct obd_uuid {
	char uuid[UUID_MAX];
};

static inline bool obd_uuid_equals(const struct obd_uuid *u1,
				   const struct obd_uuid *u2)
{
	return strcmp((char *)u1->uuid, (char *)u2->uuid) == 0;
}

static inline int obd_uuid_empty(struct obd_uuid *uuid)
{
	return uuid->uuid[0] == '\0';
}

static inline void obd_str2uuid(struct obd_uuid *uuid, const char *tmp)
{
	strncpy((char *)uuid->uuid, tmp, sizeof(*uuid));
	uuid->uuid[sizeof(*uuid) - 1] = '\0';
}

/* For printf's only, make sure uuid is terminated */
static inline char *obd_uuid2str(const struct obd_uuid *uuid)
{
	if (!uuid)
		return NULL;

	if (uuid->uuid[sizeof(*uuid) - 1] != '\0') {
		/* Obviously not safe, but for printfs, no real harm done...
		 * we're always null-terminated, even in a race.
		 */
		static char temp[sizeof(*uuid->uuid)];

		memcpy(temp, uuid->uuid, sizeof(*uuid->uuid) - 1);
		temp[sizeof(*uuid->uuid) - 1] = '\0';

		return temp;
	}
	return (char *)(uuid->uuid);
}

#define LUSTRE_MAXFSNAME 8
#define LUSTRE_MAXINSTANCE 16

/* Extract fsname from uuid (or target name) of a target
 * e.g. (myfs-OST0007_UUID -> myfs)
 * see also deuuidify.
 */
static inline void obd_uuid2fsname(char *buf, char *uuid, int buflen)
{
	char *p;

	strncpy(buf, uuid, buflen - 1);
	buf[buflen - 1] = '\0';
	p = strrchr(buf, '-');
	if (p)
		*p = '\0';
}

/* printf display format
 * * usage: printf("file FID is "DFID"\n", PFID(fid));
 */
#define FID_NOBRACE_LEN 40
#define FID_LEN (FID_NOBRACE_LEN + 2)
#define DFID_NOBRACE "%#llx:0x%x:0x%x"
#define DFID "[" DFID_NOBRACE "]"
#define PFID(fid) (unsigned long long)(fid)->f_seq, (fid)->f_oid, (fid)->f_ver

/* scanf input parse format for fids in DFID_NOBRACE format
 * Need to strip '[' from DFID format first or use "["SFID"]" at caller.
 * usage: sscanf(fidstr, SFID, RFID(&fid));
 */
#define SFID "0x%llx:0x%x:0x%x"
#define RFID(fid) &((fid)->f_seq), &((fid)->f_oid), &((fid)->f_ver)
#define PLOGID(logid) (unsigned long long)(logid)->lgl_oi.oi.oi_seq, (__u32)(logid)->lgl_oi.oi.oi_id, 0

/********* Quotas **********/

#define Q_QUOTACHECK	0x800100 /* deprecated as of 2.4 */
#define Q_INITQUOTA	0x800101 /* deprecated as of 2.4  */
#define Q_GETOINFO	0x800102 /* get obd quota info */
#define Q_GETOQUOTA	0x800103 /* get obd quotas */
#define Q_FINVALIDATE	0x800104 /* deprecated as of 2.4 */

/* these must be explicitly translated into linux Q_* in ll_dir_ioctl */
#define LUSTRE_Q_QUOTAON	0x800002	/* deprecated as of 2.4 */
#define LUSTRE_Q_QUOTAOFF	0x800003	/* deprecated as of 2.4 */
#define LUSTRE_Q_GETINFO	0x800005	/* get information about quota files */
#define LUSTRE_Q_SETINFO	0x800006	/* set information about quota files */
#define LUSTRE_Q_GETQUOTA	0x800007	/* get user quota structure */
#define LUSTRE_Q_SETQUOTA	0x800008	/* set user quota structure */
/* lustre-specific control commands */
#define LUSTRE_Q_INVALIDATE	0x80000b	/* deprecated as of 2.4 */
#define LUSTRE_Q_FINVALIDATE	0x80000c	/* deprecated as of 2.4 */
#define LUSTRE_Q_GETDEFAULT	0x80000d	/* get default quota */
#define LUSTRE_Q_SETDEFAULT	0x80000e	/* set default quota */
#define LUSTRE_Q_GETQUOTAPOOL	0x80000f	/* get user pool quota */
#define LUSTRE_Q_SETQUOTAPOOL	0x800010	/* set user pool quota */
#define LUSTRE_Q_GETINFOPOOL	0x800011	/* get pool quota info */
#define LUSTRE_Q_SETINFOPOOL	0x800012	/* set pool quota info */
#define LUSTRE_Q_GETDEFAULT_POOL	0x800013 /* get default pool quota*/
#define LUSTRE_Q_SETDEFAULT_POOL	0x800014 /* set default pool quota */
#define LUSTRE_Q_DELETEQID	0x800015  /* delete quota ID */
#define LUSTRE_Q_RESETQID	0x800016  /* reset quota ID */
/* In the current Lustre implementation, the grace time is either the time
 * or the timestamp to be used after some quota ID exceeds the soft limt,
 * 48 bits should be enough, its high 16 bits can be used as quota flags.
 */
#define LQUOTA_GRACE_BITS	48
#define LQUOTA_GRACE_MASK	((1ULL << LQUOTA_GRACE_BITS) - 1)
#define LQUOTA_GRACE_MAX	LQUOTA_GRACE_MASK
#define LQUOTA_GRACE(t)		(t & LQUOTA_GRACE_MASK)
#define LQUOTA_FLAG(t)		(t >> LQUOTA_GRACE_BITS)
#define LQUOTA_GRACE_FLAG(t, f)	((__u64)t | (__u64)f << LQUOTA_GRACE_BITS)

/* different quota flags */

/* the default quota flag, the corresponding quota ID will use the default
 * quota setting, the hardlimit and softlimit of its quota record in the global
 * quota file will be set to 0, the low 48 bits of the grace will be set to 0
 * and high 16 bits will contain this flag (see above comment).
 */
#define LQUOTA_FLAG_DEFAULT	0x0001
#define LQUOTA_FLAG_DELETED	0x0002

#define LUSTRE_Q_CMD_IS_POOL(cmd)		\
	(cmd == LUSTRE_Q_GETQUOTAPOOL ||	\
	 cmd == LUSTRE_Q_SETQUOTAPOOL ||	\
	 cmd == LUSTRE_Q_SETINFOPOOL ||		\
	 cmd == LUSTRE_Q_GETINFOPOOL)

#define ALLQUOTA 255	/* set all quota */

static inline const char *qtype_name(int qtype)
{
	switch (qtype) {
	case USRQUOTA:
		return "usr";
	case GRPQUOTA:
		return "grp";
	case PRJQUOTA:
		return "prj";
	}
	return "unknown";
}

#define IDENTITY_DOWNCALL_MAGIC 0x6d6dd629

/* permission */
#define N_PERMS_MAX	64

struct perm_downcall_data {
	__u64 pdd_nid;
	__u32 pdd_perm;
	__u32 pdd_padding;
};

struct identity_downcall_data {
	__u32			    idd_magic;
	__u32			    idd_err;
	__u32			    idd_uid;
	__u32			    idd_gid;
	__u32			    idd_nperms;
	__u32			    idd_ngroups;
	struct perm_downcall_data idd_perms[N_PERMS_MAX];
	__u32			    idd_groups[0];
};

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 16, 53, 0)
/* old interface struct is deprecated in 2.14 */
#define SEPOL_DOWNCALL_MAGIC_OLD 0x8b8bb842
struct sepol_downcall_data_old {
	__u32		sdd_magic;
	__s64		sdd_sepol_mtime;
	__u16		sdd_sepol_len;
	char		sdd_sepol[0];
};
#endif

#define SEPOL_DOWNCALL_MAGIC 0x8b8bb843
struct sepol_downcall_data {
	__u32		sdd_magic;
	__u16		sdd_sepol_len;
	__u16		sdd_padding1;
	__s64		sdd_sepol_mtime;
	char		sdd_sepol[0];
};

/* lustre volatile file support
 * file name header: ".^L^S^T^R:volatile"
 */
#define LUSTRE_VOLATILE_HDR	".\x0c\x13\x14\x12:VOLATILE"
#define LUSTRE_VOLATILE_HDR_LEN	14
/* hdr + MDT index */
#define LUSTRE_VOLATILE_IDX	LUSTRE_VOLATILE_HDR":%.4X:"

enum lustre_quota_version {
	LUSTRE_QUOTA_V2 = 1
};

/* XXX: same as if_dqinfo struct in kernel */
struct obd_dqinfo {
	__u64 dqi_bgrace;
	__u64 dqi_igrace;
	__u32 dqi_flags;
	__u32 dqi_valid;
};

/* XXX: same as if_dqblk struct in kernel, plus one padding */
struct obd_dqblk {
	__u64 dqb_bhardlimit;	/* kbytes unit */
	__u64 dqb_bsoftlimit;	/* kbytes unit */
	__u64 dqb_curspace;	/* bytes unit */
	__u64 dqb_ihardlimit;
	__u64 dqb_isoftlimit;
	__u64 dqb_curinodes;
	__u64 dqb_btime;
	__u64 dqb_itime;
	__u32 dqb_valid;
	__u32 dqb_padding;
};

enum {
	QC_GENERAL	= 0,
	QC_MDTIDX	= 1,
	QC_OSTIDX	= 2,
	QC_UUID		= 3
};

struct if_quotactl {
	__u32		  qc_cmd;
	__u32		  qc_type;
	__u32		  qc_id;
	__u32		  qc_stat;
	__u32		  qc_valid;
	__u32		  qc_idx;
	struct obd_dqinfo qc_dqinfo;
	struct obd_dqblk  qc_dqblk;
	char		  obd_type[16];
	struct obd_uuid	  obd_uuid;
	char		  qc_poolname[0];
};

/* swap layout flags */
#define SWAP_LAYOUTS_CHECK_DV1		(1 << 0)
#define SWAP_LAYOUTS_CHECK_DV2		(1 << 1)
#define SWAP_LAYOUTS_KEEP_MTIME		(1 << 2)
#define SWAP_LAYOUTS_KEEP_ATIME		(1 << 3)
#define SWAP_LAYOUTS_CLOSE		(1 << 4)

/* Swap XATTR_NAME_HSM as well, only on the MDT so far */
#define SWAP_LAYOUTS_MDS_HSM		(1 << 31)
struct lustre_swap_layouts {
	__u64	sl_flags;
	__u32	sl_fd;
	__u32	sl_gid;
	__u64	sl_dv1;
	__u64	sl_dv2;
};

/** Bit-mask of valid attributes */
/* The LA_* flags are written to disk as part of the ChangeLog records
 * so they are part of the on-disk and network protocol, and cannot be changed.
 * Only the first 12 bits are currently saved.
 */
enum la_valid {
	LA_ATIME	= 1 << 0,
	LA_MTIME	= 1 << 1,
	LA_CTIME	= 1 << 2,
	LA_SIZE		= 1 << 3,
	LA_MODE		= 1 << 4,
	LA_UID		= 1 << 5,
	LA_GID		= 1 << 6,
	LA_BLOCKS	= 1 << 7,
	LA_TYPE		= 1 << 8,
	LA_FLAGS	= 1 << 9,
	LA_NLINK	= 1 << 10,
	LA_RDEV		= 1 << 11,
	LA_BLKSIZE	= 1 << 12,
	LA_KILL_SUID	= 1 << 13,
	LA_KILL_SGID	= 1 << 14,
	LA_PROJID	= 1 << 15,
	LA_LAYOUT_VERSION = 1 << 16,
	LA_LSIZE	= 1 << 17,
	LA_LBLOCKS	= 1 << 18,
	LA_BTIME	= 1 << 19,	/* 0x8000 */
	/**
	 * Attributes must be transmitted to OST objects
	 */
	LA_REMOTE_ATTR_SET = (LA_UID | LA_GID | LA_PROJID | LA_LAYOUT_VERSION)
};

#define MDS_FMODE_READ		00000001
#define MDS_FMODE_WRITE		00000002

#define MDS_FMODE_CLOSED	00000000
#define MDS_FMODE_EXEC		00000004
/*	MDS_FMODE_EPOCH		01000000 obsolete since 2.8.0 */
/*	MDS_FMODE_TRUNC		02000000 obsolete since 2.8.0 */
/*	MDS_FMODE_SOM		04000000 obsolete since 2.8.0 */

#define MDS_OPEN_CREATED	00000010
/*	MDS_OPEN_CROSS		00000020 obsolete in 2.12, internal use only */

#define MDS_OPEN_CREAT		00000100
#define MDS_OPEN_EXCL		00000200
#define MDS_OPEN_TRUNC		00001000
#define MDS_OPEN_APPEND		00002000
#define MDS_OPEN_SYNC		00010000
#define MDS_OPEN_DIRECTORY	00200000

#define MDS_OPEN_BY_FID		040000000 /* open_by_fid for known object */
#define MDS_OPEN_DELAY_CREATE  0100000000 /* delay initial object create */
#define MDS_OPEN_OWNEROVERRIDE 0200000000 /* NFSD rw-reopen ro file for owner */
#define MDS_OPEN_JOIN_FILE     0400000000 /* open for join file.
					   * We do not support JOIN FILE
					   * anymore, reserve this flags
					   * just for preventing such bit
					   * to be reused.
					   */

#define MDS_OPEN_LOCK	      04000000000    /* This open requires open lock */
#define MDS_OPEN_HAS_EA	     010000000000    /* specify object create pattern */
#define MDS_OPEN_HAS_OBJS    020000000000    /* Just set the EA the obj exist */
#define MDS_OPEN_NORESTORE  0100000000000ULL /* Do not restore file at open */
#define MDS_OPEN_NEWSTRIPE  0200000000000ULL /* New stripe needed (restripe or
					      * hsm restore)
					      */
#define MDS_OPEN_VOLATILE   0400000000000ULL /* File is volatile = created
					      * unlinked
					      */
#define MDS_OPEN_LEASE	   01000000000000ULL /* Open the file and grant lease
					      * delegation, succeed if it's not
					      * being opened with conflict mode.
					      */
#define MDS_OPEN_RELEASE   02000000000000ULL /* Open the file for HSM release */
#define MDS_OPEN_RESYNC    04000000000000ULL /* FLR: file resync */
#define MDS_OPEN_PCC      010000000000000ULL /* PCC: auto RW-PCC cache attach
					      * for newly created file
					      */
#define MDS_OP_WITH_FID	  020000000000000ULL /* operation carried out by FID */
#define MDS_OPEN_DEFAULT_LMV  040000000000000ULL /* open fetches default LMV,
						  * or mkdir with default LMV
						  */

/* lustre internal open flags, which should not be set from user space */
#define MDS_OPEN_FL_INTERNAL (MDS_OPEN_HAS_EA | MDS_OPEN_HAS_OBJS |	\
			      MDS_OPEN_OWNEROVERRIDE | MDS_OPEN_LOCK |	\
			      MDS_OPEN_BY_FID | MDS_OPEN_LEASE |	\
			      MDS_OPEN_RELEASE | MDS_OPEN_RESYNC |	\
			      MDS_OPEN_PCC | MDS_OP_WITH_FID |		\
			      MDS_OPEN_DEFAULT_LMV)

/********* Changelogs **********/
/** Changelog record types */
enum changelog_rec_type {
	CL_NONE		= -1,
	CL_MARK		= 0,
	CL_CREATE	= 1,  /* namespace */
	CL_MKDIR	= 2,  /* namespace */
	CL_HARDLINK	= 3,  /* namespace */
	CL_SOFTLINK	= 4,  /* namespace */
	CL_MKNOD	= 5,  /* namespace */
	CL_UNLINK	= 6,  /* namespace */
	CL_RMDIR	= 7,  /* namespace */
	CL_RENAME	= 8,  /* namespace */
	CL_EXT		= 9,  /* namespace extended record (2nd half of rename) */
	CL_OPEN		= 10, /* not currently used */
	CL_CLOSE	= 11, /* may be written to log only with mtime change */
	CL_LAYOUT	= 12, /* file layout/striping modified */
	CL_TRUNC	= 13,
	CL_SETATTR	= 14,
	CL_SETXATTR	= 15,
	CL_XATTR	= CL_SETXATTR, /* Deprecated name */
	CL_HSM		= 16, /* HSM specific events, see flags */
	CL_MTIME	= 17, /* Precedence: setattr > mtime > ctime > atime */
	CL_CTIME	= 18,
	CL_ATIME	= 19,
	CL_FLRW		= 21, /* FLR: file was firstly written */
	CL_RESYNC	= 22, /* FLR: file was resync-ed */
	CL_GETXATTR	= 23,
	CL_DN_OPEN	= 24, /* denied open */
	CL_LAST,
};

static inline const char *changelog_type2str(int type)
{
	static const char *const changelog_str[] = {
		"MARK",  "CREAT", "MKDIR", "HLINK", "SLINK", "MKNOD", "UNLNK",
		"RMDIR", "RENME", "RNMTO", "OPEN",  "CLOSE", "LYOUT", "TRUNC",
		"SATTR", "XATTR", "HSM",   "MTIME", "CTIME", "ATIME", "",
		"FLRW",  "RESYNC", "GXATTR", "NOPEN",
	};

	if (type >= 0 && type < CL_LAST)
		return changelog_str[type];
	return NULL;
}

/* 12 bits of per-record data can be stored in the bottom of the flags */
#define CLF_FLAGSHIFT   12
enum changelog_rec_flags {
	CLF_VERSION	= 0x1000,
	CLF_RENAME	= 0x2000,
	CLF_JOBID	= 0x4000,
	CLF_EXTRA_FLAGS = 0x8000,
	CLF_SUPPORTED	= CLF_VERSION | CLF_RENAME | CLF_JOBID |
			  CLF_EXTRA_FLAGS,
	CLF_FLAGMASK	= (1U << CLF_FLAGSHIFT) - 1,
	CLF_VERMASK	= ~CLF_FLAGMASK,
};

/* Anything under the flagmask may be per-type (if desired) */
/* Flags for unlink */
#define CLF_UNLINK_LAST		0x0001 /* Unlink of last hardlink */
#define CLF_UNLINK_HSM_EXISTS	0x0002 /* File has something in HSM
					* HSM cleaning needed */
/* Flags for rename */
#define CLF_RENAME_LAST		0x0001	/* rename unlink last hardlink of
					 * target
					 */
#define CLF_RENAME_LAST_EXISTS	0x0002	/* rename unlink last hardlink of target
					 * has an archive in backend
					 */

/* Flags for HSM */
/* 12b used (from high weight to low weight):
 * 2b for flags
 * 3b for event
 * 7b for error code
 */
#define CLF_HSM_ERR_L	0 /* HSM return code, 7 bits */
#define CLF_HSM_ERR_H	6
#define CLF_HSM_EVENT_L	7 /* HSM event, 3 bits, see enum hsm_event */
#define CLF_HSM_EVENT_H	9
#define CLF_HSM_FLAG_L	10 /* HSM flags, 2 bits, 1 used, 1 spare */
#define CLF_HSM_FLAG_H	11
#define CLF_HSM_SPARE_L	12 /* 4 spare bits */
#define CLF_HSM_SPARE_H	15
#define CLF_HSM_LAST	15

/* Remove bits higher than _h, then extract the value
 * between _h and _l by shifting lower weigth to bit 0.
 */
#define CLF_GET_BITS(_b, _h, _l) (((_b << (CLF_HSM_LAST - _h)) & 0xFFFF) \
				   >> (CLF_HSM_LAST - _h + _l))

#define CLF_HSM_SUCCESS		0x00
#define CLF_HSM_MAXERROR	0x7E
#define CLF_HSM_ERROVERFLOW	0x7F

#define CLF_HSM_DIRTY	1 /* file is dirty after HSM request end */

/* 3 bits field => 8 values allowed */
enum hsm_event {
	HE_ARCHIVE	= 0,
	HE_RESTORE	= 1,
	HE_CANCEL	= 2,
	HE_RELEASE	= 3,
	HE_REMOVE	= 4,
	HE_STATE	= 5,
	HE_SPARE1	= 6,
	HE_SPARE2	= 7,
};

static inline enum hsm_event hsm_get_cl_event(__u16 flags)
{
	return CLF_GET_BITS(flags, CLF_HSM_EVENT_H, CLF_HSM_EVENT_L);
}

static inline void hsm_set_cl_event(enum changelog_rec_flags *clf_flags,
				    enum hsm_event he)
{
	*clf_flags = (enum changelog_rec_flags)
		(*clf_flags | (he << CLF_HSM_EVENT_L));
}

static inline __u16 hsm_get_cl_flags(enum changelog_rec_flags clf_flags)
{
	return CLF_GET_BITS(clf_flags, CLF_HSM_FLAG_H, CLF_HSM_FLAG_L);
}

static inline void hsm_set_cl_flags(enum changelog_rec_flags *clf_flags,
				    unsigned int bits)
{
	*clf_flags = (enum changelog_rec_flags)
		(*clf_flags | (bits << CLF_HSM_FLAG_L));
}

static inline int hsm_get_cl_error(enum changelog_rec_flags clf_flags)
{
	return CLF_GET_BITS(clf_flags, CLF_HSM_ERR_H, CLF_HSM_ERR_L);
}

static inline void hsm_set_cl_error(enum changelog_rec_flags *clf_flags,
				    unsigned int error)
{
	*clf_flags = (enum changelog_rec_flags)
		(*clf_flags | (error << CLF_HSM_ERR_L));
}

enum changelog_rec_extra_flags {
	CLFE_INVALID	= 0,
	CLFE_UIDGID	= 0x0001,
	CLFE_NID	= 0x0002,
	CLFE_OPEN	= 0x0004,
	CLFE_XATTR	= 0x0008,
	CLFE_SUPPORTED	= CLFE_UIDGID | CLFE_NID | CLFE_OPEN | CLFE_XATTR
};

enum changelog_send_flag {
	/* Not yet implemented */
	CHANGELOG_FLAG_FOLLOW	= 0x01,
	/*
	 * Blocking IO makes sense in case of slow user parsing of the records,
	 * but it also prevents us from cleaning up if the records are not
	 * consumed.
	 */
	CHANGELOG_FLAG_BLOCK	= 0x02,
	/* Pack jobid into the changelog records if available. */
	CHANGELOG_FLAG_JOBID	= 0x04,
	/* Pack additional flag bits into the changelog record */
	CHANGELOG_FLAG_EXTRA_FLAGS	= 0x08,
};

enum changelog_send_extra_flag {
	/* Pack uid/gid into the changelog record */
	CHANGELOG_EXTRA_FLAG_UIDGID = 0x01,
	/* Pack nid into the changelog record */
	CHANGELOG_EXTRA_FLAG_NID	= 0x02,
	/* Pack open mode into the changelog record */
	CHANGELOG_EXTRA_FLAG_OMODE	= 0x04,
	/* Pack xattr name into the changelog record */
	CHANGELOG_EXTRA_FLAG_XATTR	= 0x08,
};

#define CR_MAXSIZE __ALIGN_KERNEL(2 * NAME_MAX + 2 + \
				  changelog_rec_offset(CLF_SUPPORTED, \
							CLFE_SUPPORTED), 8)

/* 31 usable bytes string + null terminator. */
#define LUSTRE_JOBID_SIZE	32

/*
 * This is the minimal changelog record. It can contain extensions
 * such as rename fields or process jobid. Its exact content is described
 * by the cr_flags and cr_extra_flags.
 *
 * Extensions are packed in the same order as their corresponding flags,
 * then in the same order as their corresponding extra flags.
 */
struct changelog_rec {
	__u16		 cr_namelen;
	__u16		 cr_flags; /**< \a changelog_rec_flags */
	__u32		 cr_type;  /**< \a changelog_rec_type */
	__u64		 cr_index; /**< changelog record number */
	__u64		 cr_prev;  /**< last index for this target fid */
	__u64		 cr_time;
	union {
		struct lu_fid    cr_tfid;	/**< target fid */
		__u32	 cr_markerflags; /**< CL_MARK flags */
	};
	struct lu_fid	 cr_pfid;		/**< parent fid */
} __attribute__((packed));

/* Changelog extension for RENAME. */
struct changelog_ext_rename {
	struct lu_fid	cr_sfid;	/**< source fid, or zero */
	struct lu_fid	cr_spfid;	/**< source parent fid, or zero */
};

/* Changelog extension to include JOBID. */
struct changelog_ext_jobid {
	char	cr_jobid[LUSTRE_JOBID_SIZE];	/**< zero-terminated string. */
};

/* Changelog extra extension to include NID. */
struct changelog_ext_nid {
	/* have __u64 instead of lnet_nid_t type for use by client api */
	__u64 cr_nid;
	/* for use when IPv6 support is added */
	__u64 extra;
	__u32 padding;
};

/* Changelog extra extension to include low 32 bits of MDS_OPEN_* flags. */
struct changelog_ext_openmode {
	__u32 cr_openflags;
};

/* Changelog extra extension to include xattr */
struct changelog_ext_xattr {
	char cr_xattr[XATTR_NAME_MAX + 1]; /**< zero-terminated string. */
};

/* Changelog extension to include additional flags. */
struct changelog_ext_extra_flags {
	__u64 cr_extra_flags; /* Additional CLFE_* flags */
};

/* Changelog extra extension to include UID/GID. */
struct changelog_ext_uidgid {
	__u64	cr_uid;
	__u64	cr_gid;
};

static inline struct changelog_ext_extra_flags *changelog_rec_extra_flags(
	const struct changelog_rec *rec);

static inline __kernel_size_t changelog_rec_offset(enum changelog_rec_flags crf,
						   enum changelog_rec_extra_flags cref)
{
	__kernel_size_t size = sizeof(struct changelog_rec);

	if (crf & CLF_RENAME)
		size += sizeof(struct changelog_ext_rename);

	if (crf & CLF_JOBID)
		size += sizeof(struct changelog_ext_jobid);

	if (crf & CLF_EXTRA_FLAGS) {
		size += sizeof(struct changelog_ext_extra_flags);
		if (cref & CLFE_UIDGID)
			size += sizeof(struct changelog_ext_uidgid);
		if (cref & CLFE_NID)
			size += sizeof(struct changelog_ext_nid);
		if (cref & CLFE_OPEN)
			size += sizeof(struct changelog_ext_openmode);
		if (cref & CLFE_XATTR)
			size += sizeof(struct changelog_ext_xattr);
	}

	return size;
}

static inline __kernel_size_t changelog_rec_size(struct changelog_rec *rec)
{
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = (enum changelog_rec_extra_flags)
		       changelog_rec_extra_flags(rec)->cr_extra_flags;

	return changelog_rec_offset((enum changelog_rec_flags)rec->cr_flags,
				    cref);
}

static inline __kernel_size_t changelog_rec_varsize(struct changelog_rec *rec)
{
	return changelog_rec_size(rec) - sizeof(*rec) + rec->cr_namelen;
}

static inline
struct changelog_ext_rename *changelog_rec_rename(struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = (enum changelog_rec_flags)
				       (rec->cr_flags & CLF_VERSION);

	return (struct changelog_ext_rename *)((char *)rec +
					       changelog_rec_offset(crf,
								 CLFE_INVALID));
}

/* The jobid follows the rename extension, if present */
static inline
struct changelog_ext_jobid *changelog_rec_jobid(struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = (enum changelog_rec_flags)
				       (rec->cr_flags & (CLF_VERSION | CLF_RENAME));

	return (struct changelog_ext_jobid *)((char *)rec +
					      changelog_rec_offset(crf,
								 CLFE_INVALID));
}

/* The additional flags follow the rename and jobid extensions, if present */
static inline
struct changelog_ext_extra_flags *changelog_rec_extra_flags(
	const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = (enum changelog_rec_flags)
		(rec->cr_flags & (CLF_VERSION | CLF_RENAME | CLF_JOBID));

	return (struct changelog_ext_extra_flags *)((char *)rec +
						 changelog_rec_offset(crf,
								 CLFE_INVALID));
}

/* The uid/gid is the first extra extension */
static inline
struct changelog_ext_uidgid *changelog_rec_uidgid(
	const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = (enum changelog_rec_flags)
		(rec->cr_flags &
		 (CLF_VERSION | CLF_RENAME | CLF_JOBID | CLF_EXTRA_FLAGS));

	return (struct changelog_ext_uidgid *)((char *)rec +
					       changelog_rec_offset(crf,
								 CLFE_INVALID));
}

/* The nid is the second extra extension */
static inline
struct changelog_ext_nid *changelog_rec_nid(const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = (enum changelog_rec_flags)
		(rec->cr_flags &
		 (CLF_VERSION | CLF_RENAME | CLF_JOBID | CLF_EXTRA_FLAGS));
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = (enum changelog_rec_extra_flags)
			(changelog_rec_extra_flags(rec)->cr_extra_flags &
			 CLFE_UIDGID);

	return (struct changelog_ext_nid *)((char *)rec +
					    changelog_rec_offset(crf, cref));
}

/* The OPEN mode is the third extra extension */
static inline
struct changelog_ext_openmode *changelog_rec_openmode(
	const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = (enum changelog_rec_flags)
		(rec->cr_flags &
		 (CLF_VERSION | CLF_RENAME | CLF_JOBID | CLF_EXTRA_FLAGS));
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS) {
		cref = (enum changelog_rec_extra_flags)
			(changelog_rec_extra_flags(rec)->cr_extra_flags &
			 (CLFE_UIDGID | CLFE_NID));
	}

	return (struct changelog_ext_openmode *)((char *)rec +
						 changelog_rec_offset(crf, cref));
}

/* The xattr name is the fourth extra extension */
static inline
struct changelog_ext_xattr *changelog_rec_xattr(
	const struct changelog_rec *rec)
{
	enum changelog_rec_flags crf = (enum changelog_rec_flags)
		(rec->cr_flags &
		 (CLF_VERSION | CLF_RENAME | CLF_JOBID | CLF_EXTRA_FLAGS));
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = (enum changelog_rec_extra_flags)
			(changelog_rec_extra_flags(rec)->cr_extra_flags &
		         (CLFE_UIDGID | CLFE_NID | CLFE_OPEN));

	return (struct changelog_ext_xattr *)((char *)rec +
					      changelog_rec_offset(crf, cref));
}

/* The name follows the rename, jobid  and extra flags extns, if present */
static inline char *changelog_rec_name(struct changelog_rec *rec)
{
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		cref = (enum changelog_rec_extra_flags)
			changelog_rec_extra_flags(rec)->cr_extra_flags;

	return (char *)rec + changelog_rec_offset(
		(enum changelog_rec_flags)(rec->cr_flags & CLF_SUPPORTED),
		(enum changelog_rec_extra_flags)(cref & CLFE_SUPPORTED));
}

static inline __kernel_size_t changelog_rec_snamelen(struct changelog_rec *rec)
{
	return rec->cr_namelen - strlen(changelog_rec_name(rec)) - 1;
}

static inline char *changelog_rec_sname(struct changelog_rec *rec)
{
	char *str = changelog_rec_name(rec);

	while (*str != '\0')
		str++;
	return str + 1;
}

/**
 * Remap a record to the desired format as specified by the crf flags.
 * The record must be big enough to contain the final remapped version.
 * Superfluous extension fields are removed and missing ones are added
 * and zeroed. The flags of the record are updated accordingly.
 *
 * The jobid and rename extensions can be added to a record, to match the
 * format an application expects, typically. In this case, the newly added
 * fields will be zeroed.
 * The Jobid field can be removed, to guarantee compatibility with older
 * clients that don't expect this field in the records they process.
 *
 * The following assumptions are being made:
 *	- CLF_RENAME will not be removed
 *	- CLF_JOBID will not be added without CLF_RENAME being added too
 *	- CLF_EXTRA_FLAGS will not be added without CLF_JOBID being added too
 *
 * @rec			The record to remap.
 * @crf_wanted		Flags describing the desired extensions.
 * @cref_want		Flags describing the desired extra extensions.
 */
static inline void changelog_remap_rec(struct changelog_rec *rec,
				       enum changelog_rec_flags crf_wanted,
				       enum changelog_rec_extra_flags cref_want)
{
	char *xattr_mov = NULL;
	char *omd_mov = NULL;
	char *nid_mov = NULL;
	char *uidgid_mov = NULL;
	char *ef_mov;
	char *jid_mov, *rnm_mov;
	enum changelog_rec_extra_flags cref = CLFE_INVALID;

	crf_wanted = (enum changelog_rec_flags)
		      (crf_wanted & CLF_SUPPORTED);
	cref_want = (enum changelog_rec_extra_flags)
		     (cref_want & CLFE_SUPPORTED);

	if ((rec->cr_flags & CLF_SUPPORTED) == crf_wanted) {
		if (!(rec->cr_flags & CLF_EXTRA_FLAGS) ||
		    (rec->cr_flags & CLF_EXTRA_FLAGS &&
		    (changelog_rec_extra_flags(rec)->cr_extra_flags &
							CLFE_SUPPORTED) ==
								     cref_want))
			return;
	}

	/* First move the variable-length name field */
	memmove((char *)rec + changelog_rec_offset(crf_wanted, cref_want),
		changelog_rec_name(rec), rec->cr_namelen);

	/* Locations of extensions in the remapped record */
	if (rec->cr_flags & CLF_EXTRA_FLAGS) {
		xattr_mov = (char *)rec +
			    changelog_rec_offset((enum changelog_rec_flags)
						  (crf_wanted & CLF_SUPPORTED),
						 (enum changelog_rec_extra_flags)
						  (cref_want & ~CLFE_XATTR));
		omd_mov = (char *)rec +
			  changelog_rec_offset((enum changelog_rec_flags)
						(crf_wanted & CLF_SUPPORTED),
					       (enum changelog_rec_extra_flags)
					        (cref_want & ~(CLFE_OPEN |
							       CLFE_XATTR)));
		nid_mov = (char *)rec +
			  changelog_rec_offset((enum changelog_rec_flags)
						(crf_wanted & CLF_SUPPORTED),
					       (enum changelog_rec_extra_flags)
					        (cref_want & ~(CLFE_NID |
							       CLFE_OPEN |
							       CLFE_XATTR)));
		uidgid_mov = (char *)rec +
			     changelog_rec_offset((enum changelog_rec_flags)
						   (crf_wanted & CLF_SUPPORTED),
					          (enum changelog_rec_extra_flags)
					           (cref_want & ~(CLFE_UIDGID |
								  CLFE_NID |
								  CLFE_OPEN |
								  CLFE_XATTR)));
		cref = (enum changelog_rec_extra_flags)
		       changelog_rec_extra_flags(rec)->cr_extra_flags;
	}

	ef_mov  = (char *)rec +
		  changelog_rec_offset((enum changelog_rec_flags)
					(crf_wanted & ~CLF_EXTRA_FLAGS),
				        CLFE_INVALID);
	jid_mov = (char *)rec +
		  changelog_rec_offset((enum changelog_rec_flags)
					(crf_wanted & ~(CLF_EXTRA_FLAGS |
							CLF_JOBID)),
				       CLFE_INVALID);
	rnm_mov = (char *)rec +
		  changelog_rec_offset((enum changelog_rec_flags)
					(crf_wanted & ~(CLF_EXTRA_FLAGS |
							CLF_JOBID |
							CLF_RENAME)),
				       CLFE_INVALID);

	/* Move the extension fields to the desired positions */
	if ((crf_wanted & CLF_EXTRA_FLAGS) &&
	    (rec->cr_flags & CLF_EXTRA_FLAGS)) {
		if ((cref_want & CLFE_XATTR) && (cref & CLFE_XATTR))
			memmove(xattr_mov, changelog_rec_xattr(rec),
				sizeof(struct changelog_ext_xattr));

		if ((cref_want & CLFE_OPEN) && (cref & CLFE_OPEN))
			memmove(omd_mov, changelog_rec_openmode(rec),
				sizeof(struct changelog_ext_openmode));

		if ((cref_want & CLFE_NID) && (cref & CLFE_NID))
			memmove(nid_mov, changelog_rec_nid(rec),
				sizeof(struct changelog_ext_nid));

		if ((cref_want & CLFE_UIDGID) && (cref & CLFE_UIDGID))
			memmove(uidgid_mov, changelog_rec_uidgid(rec),
				sizeof(struct changelog_ext_uidgid));

		memmove(ef_mov, changelog_rec_extra_flags(rec),
			sizeof(struct changelog_ext_extra_flags));
	}

	if ((crf_wanted & CLF_JOBID) && (rec->cr_flags & CLF_JOBID))
		memmove(jid_mov, changelog_rec_jobid(rec),
			sizeof(struct changelog_ext_jobid));

	if ((crf_wanted & CLF_RENAME) && (rec->cr_flags & CLF_RENAME))
		memmove(rnm_mov, changelog_rec_rename(rec),
			sizeof(struct changelog_ext_rename));

	/* Clear newly added fields */
	if (xattr_mov && (cref_want & CLFE_XATTR) &&
	    !(cref & CLFE_XATTR))
		memset(xattr_mov, 0, sizeof(struct changelog_ext_xattr));

	if (omd_mov && (cref_want & CLFE_OPEN) &&
	    !(cref & CLFE_OPEN))
		memset(omd_mov, 0, sizeof(struct changelog_ext_openmode));

	if (nid_mov && (cref_want & CLFE_NID) &&
	    !(cref & CLFE_NID))
		memset(nid_mov, 0, sizeof(struct changelog_ext_nid));

	if (uidgid_mov && (cref_want & CLFE_UIDGID) &&
	    !(cref & CLFE_UIDGID))
		memset(uidgid_mov, 0, sizeof(struct changelog_ext_uidgid));

	if ((crf_wanted & CLF_EXTRA_FLAGS) &&
	    !(rec->cr_flags & CLF_EXTRA_FLAGS))
		memset(ef_mov, 0, sizeof(struct changelog_ext_extra_flags));

	if ((crf_wanted & CLF_JOBID) && !(rec->cr_flags & CLF_JOBID))
		memset(jid_mov, 0, sizeof(struct changelog_ext_jobid));

	if ((crf_wanted & CLF_RENAME) && !(rec->cr_flags & CLF_RENAME))
		memset(rnm_mov, 0, sizeof(struct changelog_ext_rename));

	/* Update the record's flags accordingly */
	rec->cr_flags = (rec->cr_flags & CLF_FLAGMASK) | crf_wanted;
	if (rec->cr_flags & CLF_EXTRA_FLAGS)
		changelog_rec_extra_flags(rec)->cr_extra_flags =
			changelog_rec_extra_flags(rec)->cr_extra_flags |
			cref_want;
}

enum changelog_message_type {
	CL_RECORD = 10, /* message is a changelog_rec */
	CL_EOF    = 11, /* at end of current changelog */
};

/********* Misc **********/

struct ioc_data_version {
	__u64	idv_version;
	__u32	idv_layout_version; /* FLR: layout version for OST objects */
	__u32	idv_flags;	    /* enum ioc_data_version_flags */
};

enum ioc_data_version_flags {
	LL_DV_RD_FLUSH	= (1 << 0), /* Flush dirty pages from clients */
	LL_DV_WR_FLUSH	= (1 << 1), /* Flush all caching pages from clients */
	LL_DV_SZ_UPDATE	= (1 << 2), /* Update the file size on the client */
};

#ifndef offsetof
# define offsetof(typ, memb)	((unsigned long)((char *)&(((typ *)0)->memb)))
#endif

#define dot_lustre_name ".lustre"
#define dot_fscrypt_name ".fscrypt"

/********* HSM **********/

/** HSM per-file state
 * See HSM_FLAGS below.
 */
enum hsm_states {
	HS_NONE		= 0x00000000,
	HS_EXISTS	= 0x00000001,
	HS_DIRTY	= 0x00000002,
	HS_RELEASED	= 0x00000004,
	HS_ARCHIVED	= 0x00000008,
	HS_NORELEASE	= 0x00000010,
	HS_NOARCHIVE	= 0x00000020,
	HS_LOST		= 0x00000040,
	HS_PCCRW	= 0x00000080,
	HS_PCCRO	= 0x00000100,
};

/* HSM user-setable flags. */
#define HSM_USER_MASK   (HS_NORELEASE | HS_NOARCHIVE | HS_DIRTY)

/* Other HSM flags. */
#define HSM_STATUS_MASK (HS_EXISTS | HS_LOST | HS_RELEASED | HS_ARCHIVED)

/*
 * All HSM-related possible flags that could be applied to a file.
 * This should be kept in sync with hsm_states.
 */
#define HSM_FLAGS_MASK  (HSM_USER_MASK | HSM_STATUS_MASK)

/**
 * HSM request progress state
 */
enum hsm_progress_states {
	HPS_NONE	= 0,
	HPS_WAITING	= 1,
	HPS_RUNNING	= 2,
	HPS_DONE	= 3,
};

static inline const char *hsm_progress_state2name(enum hsm_progress_states s)
{
	switch  (s) {
	case HPS_WAITING:	return "waiting";
	case HPS_RUNNING:	return "running";
	case HPS_DONE:		return "done";
	default:		return "unknown";
	}
}

struct hsm_extent {
	__u64 offset;
	__u64 length;
} __attribute__((packed));

/**
 * Current HSM states of a Lustre file.
 *
 * This structure purpose is to be sent to user-space mainly. It describes the
 * current HSM flags and in-progress action.
 */
struct hsm_user_state {
	/** Current HSM states, from enum hsm_states. */
	__u32			hus_states;
	__u32			hus_archive_id;
	/**  The current undergoing action, if there is one */
	__u32			hus_in_progress_state;
	__u32			hus_in_progress_action;
	struct hsm_extent	hus_in_progress_location;
	char			hus_extended_info[];
};

struct hsm_state_set_ioc {
	struct lu_fid	hssi_fid;
	__u64		hssi_setmask;
	__u64		hssi_clearmask;
};

/*
 * This structure describes the current in-progress action for a file.
 * it is returned to user space and send over the wire
 */
struct hsm_current_action {
	/**  The current undergoing action, if there is one */
	/* state is one of hsm_progress_states */
	__u32			hca_state;
	/* action is one of hsm_user_action */
	__u32			hca_action;
	struct hsm_extent	hca_location;
};

/***** HSM user requests ******/
/* User-generated (lfs/ioctl) request types */
enum hsm_user_action {
	HUA_NONE    =  1, /* no action (noop) */
	HUA_ARCHIVE = 10, /* copy to hsm */
	HUA_RESTORE = 11, /* prestage */
	HUA_RELEASE = 12, /* drop ost objects */
	HUA_REMOVE  = 13, /* remove from archive */
	HUA_CANCEL  = 14  /* cancel a request */
};

static inline const char *hsm_user_action2name(enum hsm_user_action  a)
{
	switch  (a) {
	case HUA_NONE:    return "NOOP";
	case HUA_ARCHIVE: return "ARCHIVE";
	case HUA_RESTORE: return "RESTORE";
	case HUA_RELEASE: return "RELEASE";
	case HUA_REMOVE:  return "REMOVE";
	case HUA_CANCEL:  return "CANCEL";
	default:	  return "UNKNOWN";
	}
}

/*
 * List of hr_flags (bit field)
 */
#define HSM_FORCE_ACTION 0x0001
/* used by CT, connot be set by user */
#define HSM_GHOST_COPY   0x0002

/**
 * Contains all the fixed part of struct hsm_user_request.
 *
 */
struct hsm_request {
	__u32 hr_action;	/* enum hsm_user_action */
	__u32 hr_archive_id;	/* archive id, used only with HUA_ARCHIVE */
	__u64 hr_flags;		/* request flags */
	__u32 hr_itemcount;	/* item count in hur_user_item vector */
	__u32 hr_data_len;
};

struct hsm_user_item {
	struct lu_fid	hui_fid;
	struct hsm_extent hui_extent;
} __attribute__((packed));

struct hsm_user_request {
	struct hsm_request	hur_request;
	struct hsm_user_item	hur_user_item[0];
	/* extra data blob at end of struct (after all
	 * hur_user_items), only use helpers to access it
	 */
} __attribute__((packed));

/** Return pointer to data field in a hsm user request */
static inline void *hur_data(struct hsm_user_request *hur)
{
	return &hur->hur_user_item[hur->hur_request.hr_itemcount];
}

/**
 * Compute the current length of the provided hsm_user_request.  This returns -1
 * instead of an errno because __kernel_size_t is defined to be only
 * [ -1, SSIZE_MAX ]
 *
 * return -1 on bounds check error.
 */
static inline __kernel_size_t hur_len(struct hsm_user_request *hur)
{
	__u64	size;

	/* can't overflow a __u64 since hr_itemcount is only __u32 */
	size = offsetof(struct hsm_user_request, hur_user_item[0]) +
		(__u64)hur->hur_request.hr_itemcount *
		sizeof(hur->hur_user_item[0]) + hur->hur_request.hr_data_len;

	if ((__kernel_ssize_t)size < 0)
		return -1;

	return size;
}

/****** HSM RPCs to copytool *****/
/* Message types the copytool may receive */
enum hsm_message_type {
	HMT_ACTION_LIST = 100, /* message is a hsm_action_list */
};

/* Actions the copytool may be instructed to take for a given action_item */
enum hsm_copytool_action {
	HSMA_NONE    = 10, /* no action */
	HSMA_ARCHIVE = 20, /* arbitrary offset */
	HSMA_RESTORE = 21,
	HSMA_REMOVE  = 22,
	HSMA_CANCEL  = 23
};

static inline const char *hsm_copytool_action2name(enum hsm_copytool_action  a)
{
	switch  (a) {
	case HSMA_NONE:    return "NOOP";
	case HSMA_ARCHIVE: return "ARCHIVE";
	case HSMA_RESTORE: return "RESTORE";
	case HSMA_REMOVE:  return "REMOVE";
	case HSMA_CANCEL:  return "CANCEL";
	default:	   return "UNKNOWN";
	}
}

/* Copytool item action description */
struct hsm_action_item {
	__u32		hai_len;     /* valid size of this struct */
	__u32		hai_action;  /* hsm_copytool_action, but use known size */
	struct lu_fid	hai_fid;     /* Lustre FID to operated on */
	struct lu_fid	hai_dfid;    /* fid used for data access */
	struct hsm_extent hai_extent;  /* byte range to operate on */
	__u64		hai_cookie;  /* action cookie from coordinator */
	__u64		hai_gid;     /* grouplock id */
	char		hai_data[0]; /* variable length */
} __attribute__((packed));

/*
 * helper function which print in hexa the first bytes of
 * hai opaque field
 *
 * @hai		record to print
 * @buffer	output buffer
 * @len		max buffer len
 * Return:	buffer
 */
static inline char *hai_dump_data_field(struct hsm_action_item *hai,
					char *buffer, __kernel_size_t len)
{
	int i, data_len;
	char *ptr;

	ptr = buffer;
	data_len = hai->hai_len - sizeof(*hai);
	for (i = 0; (i < data_len) && (len > 2); i++) {
		snprintf(ptr, 3, "%02X", (unsigned char)hai->hai_data[i]);
		ptr += 2;
		len -= 2;
	}

	*ptr = '\0';

	return buffer;
}

/* Copytool action list */
#define HAL_VERSION 1
#define HAL_MAXSIZE LNET_MTU /* bytes, used in userspace only */
struct hsm_action_list {
	__u32 hal_version;
	__u32 hal_count;	/* number of hai's to follow */
	__u64 hal_compound_id;	/* returned by coordinator, ignored */
	__u64 hal_flags;
	__u32 hal_archive_id;	/* which archive backend */
	__u32 padding1;
	char  hal_fsname[0];	/* null-terminated */
	/* struct hsm_action_item[hal_count] follows, aligned on 8-byte
	 * boundaries. See hai_first
	 */
} __attribute__((packed));

/* Return pointer to first hai in action list */
static inline struct hsm_action_item *hai_first(struct hsm_action_list *hal)
{
	__kernel_size_t offset = __ALIGN_KERNEL(strlen(hal->hal_fsname) + 1, 8);

	return (struct hsm_action_item *)(hal->hal_fsname + offset);
}

/* Return pointer to next hai */
static inline struct hsm_action_item *hai_next(struct hsm_action_item *hai)
{
	__kernel_size_t offset = __ALIGN_KERNEL(hai->hai_len, 8);

	return (struct hsm_action_item *)((char *)hai + offset);
}

/* Return size of an hsm_action_list */
static inline __kernel_size_t hal_size(struct hsm_action_list *hal)
{
	__u32 i;
	__kernel_size_t sz;
	struct hsm_action_item *hai;

	sz = sizeof(*hal) + __ALIGN_KERNEL(strlen(hal->hal_fsname) + 1, 8);
	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai))
		sz += __ALIGN_KERNEL(hai->hai_len, 8);

	return sz;
}

/* HSM file import
 * describe the attributes to be set on imported file
 */
struct hsm_user_import {
	__u64		hui_size;
	__u64		hui_atime;
	__u64		hui_mtime;
	__u32		hui_atime_ns;
	__u32		hui_mtime_ns;
	__u32		hui_uid;
	__u32		hui_gid;
	__u32		hui_mode;
	__u32		hui_archive_id;
};

/* Copytool progress reporting */
#define HP_FLAG_COMPLETED	0x01
#define HP_FLAG_RETRY		0x02

struct hsm_progress {
	struct lu_fid		hp_fid;
	__u64			hp_cookie;
	struct hsm_extent	hp_extent;
	__u16			hp_flags;
	__u16			hp_errval; /* positive val */
	__u32			padding;
};

struct hsm_copy {
	__u64			hc_data_version;
	__u16			hc_flags;
	__u16			hc_errval; /* positive val */
	__u32			padding;
	struct hsm_action_item	hc_hai;
};

enum lu_ladvise_type {
	LU_LADVISE_INVALID	= 0,
	LU_LADVISE_WILLREAD	= 1,
	LU_LADVISE_DONTNEED	= 2,
	LU_LADVISE_LOCKNOEXPAND	= 3,
	LU_LADVISE_LOCKAHEAD    = 4,
	LU_LADVISE_MAX
};

#define LU_LADVISE_NAMES {					\
	[LU_LADVISE_WILLREAD]		= "willread",		\
	[LU_LADVISE_DONTNEED]		= "dontneed",		\
	[LU_LADVISE_LOCKNOEXPAND]	= "locknoexpand",	\
	[LU_LADVISE_LOCKAHEAD]		= "lockahead",		\
}

/*
 * This is the userspace argument for ladvise. It is currently the same as
 * what goes on the wire (struct lu_ladvise), but is defined separately as we
 * may need info which is only used locally.
 */
struct llapi_lu_ladvise {
	__u16 lla_advice;	/* advice type */
	__u16 lla_value1;	/* values for different advice types */
	__u32 lla_value2;
	__u64 lla_start;	/* first byte of extent for advice */
	__u64 lla_end;		/* last byte of extent for advice */
	__u32 lla_value3;
	__u32 lla_value4;
};

enum ladvise_flag {
	LF_ASYNC	= 0x00000001,
	LF_UNSET	= 0x00000002,
};

#define LADVISE_MAGIC 0x1ADF1CE0
/* Masks of valid flags for each advice */
#define LF_LOCKNOEXPAND_MASK LF_UNSET
/* Flags valid for all advices not explicitly specified */
#define LF_DEFAULT_MASK LF_ASYNC
/* All flags */
#define LF_MASK (LF_ASYNC | LF_UNSET)

#define lla_lockahead_mode	lla_value1
#define lla_peradvice_flags	lla_value2
#define lla_lockahead_result	lla_value3

/*
 * This is the userspace argument for ladvise, corresponds to ladvise_hdr which
 * is used on the wire. It is defined separately as we may need info which is
 * only used locally.
 */
struct llapi_ladvise_hdr {
	__u32			lah_magic;	/* LADVISE_MAGIC */
	__u32			lah_count;	/* number of advices */
	__u64			lah_flags;	/* from enum ladvise_flag */
	__u32			lah_value1;	/* unused */
	__u32			lah_value2;	/* unused */
	__u64			lah_value3;	/* unused */
	struct llapi_lu_ladvise	lah_advise[0];	/* advices in this header */
};

#define LAH_COUNT_MAX		1024

enum lock_mode_user {
	MODE_READ_USER = 1,
	MODE_WRITE_USER,
	MODE_MAX_USER,
};

#define LOCK_MODE_NAMES {			\
	[MODE_READ_USER]	= "READ",	\
	[MODE_WRITE_USER]	= "WRITE"	\
}

enum lockahead_results {
	LLA_RESULT_SENT = 0,
	LLA_RESULT_DIFFERENT,
	LLA_RESULT_SAME,
};

enum lu_heat_flag_bit {
	LU_HEAT_FLAG_BIT_INVALID = 0,
	LU_HEAT_FLAG_BIT_OFF,
	LU_HEAT_FLAG_BIT_CLEAR,
};

enum lu_heat_flag {
	LU_HEAT_FLAG_OFF	= 1ULL << LU_HEAT_FLAG_BIT_OFF,
	LU_HEAT_FLAG_CLEAR	= 1ULL << LU_HEAT_FLAG_BIT_CLEAR,
};

enum obd_heat_type {
	OBD_HEAT_READSAMPLE	= 0,
	OBD_HEAT_WRITESAMPLE	= 1,
	OBD_HEAT_READBYTE	= 2,
	OBD_HEAT_WRITEBYTE	= 3,
	OBD_HEAT_COUNT
};

#define LU_HEAT_NAMES {					\
	[OBD_HEAT_READSAMPLE]	= "readsample",		\
	[OBD_HEAT_WRITESAMPLE]	= "writesample",	\
	[OBD_HEAT_READBYTE]	= "readbyte",		\
	[OBD_HEAT_WRITEBYTE]	= "writebyte",		\
}

struct lu_heat {
	__u32 lh_count;
	__u32 lh_flags;
	__u64 lh_heat[0];
};

enum lu_pcc_type {
	LU_PCC_NONE		= 0x0,
	LU_PCC_READWRITE	= 0x01,
	LU_PCC_READONLY		= 0x02,
	LU_PCC_TYPE_MASK	= LU_PCC_READWRITE | LU_PCC_READONLY,
	LU_PCC_FL_ASYNC		= 0x10,
	LU_PCC_MAX
};

static inline const char *pcc_type2string(enum lu_pcc_type type)
{
	switch (type & LU_PCC_TYPE_MASK) {
	case LU_PCC_NONE:
		return "none";
	case LU_PCC_READWRITE:
		return "readwrite";
	case LU_PCC_READONLY:
		return "readonly";
	default:
		return "fault";
	}
}

struct lu_pcc_attach {
	__u32 pcca_type; /* PCC type */
	__u32 pcca_id; /* archive ID for readwrite, group ID for readonly */
};

enum lu_pcc_detach_opts {
	PCC_DETACH_OPT_NONE = 0, /* Detach only, keep the PCC copy */
	PCC_DETACH_OPT_UNCACHE, /* Remove the cached file after detach */
};

struct lu_pcc_detach_fid {
	/* fid of the file to detach */
	struct lu_fid	pccd_fid;
	__u32		pccd_opt;
};

struct lu_pcc_detach {
	__u32		pccd_opt;
};

enum lu_pcc_state_flags {
	PCC_STATE_FL_NONE		= 0x0,
	/* The inode attr is cached locally */
	PCC_STATE_FL_ATTR_VALID		= 0x01,
	/* The file is being attached into PCC */
	PCC_STATE_FL_ATTACHING		= 0x02,
	/* The PCC copy is unlinked */
	PCC_STATE_FL_UNLINKED		= 0x04,
};

struct lu_pcc_state {
	__u32	pccs_type; /* enum lu_pcc_type */
	__u32	pccs_open_count;
	__u32	pccs_flags; /* enum lu_pcc_state_flags */
	__u32	pccs_padding;
	char	pccs_path[PATH_MAX];
};

enum lu_project_type {
	LU_PROJECT_NONE = 0,
	LU_PROJECT_SET,
	LU_PROJECT_GET,
	LU_PROJECT_MAX
};

struct lu_project {
	__u32	project_type; /* enum lu_project_type */
	__u32	project_id;
	__u32	project_xflags;
	__u32	project_reserved;
	char	project_name[NAME_MAX + 1];
};

struct fid_array {
	__u32 fa_nr;
	/* make header's size equal lu_fid */
	__u32 fa_padding0;
	__u64 fa_padding1;
	struct lu_fid fa_fids[0];
};
#define OBD_MAX_FIDS_IN_ARRAY	4096

/* more types could be defined upon need for more complex
 * format to be used in foreign symlink LOV/LMV EAs, like
 * one to describe a delimiter string and occurence number
 * of delimited sub-string, ...
 */
enum ll_foreign_symlink_upcall_item_type {
	EOB_TYPE = 1,
	STRING_TYPE = 2,
	POSLEN_TYPE = 3,
};

/* may need to be modified to allow for more format items to be defined, and
 * like for ll_foreign_symlink_upcall_item_type enum
 */
struct ll_foreign_symlink_upcall_item {
	__u32 type;
	union {
		struct {
			__u32 pos;
			__u32 len;
		};
		struct {
			size_t size;
			union {
				/* internal storage of constant string */
				char *string;
				/* upcall stores constant string in a raw */
				char bytestring[0];
			};
		};
	};
};

#define POSLEN_ITEM_SZ (offsetof(struct ll_foreign_symlink_upcall_item, len) + \
		sizeof(((struct ll_foreign_symlink_upcall_item *)0)->len))
#define STRING_ITEM_SZ(sz) ( \
	offsetof(struct ll_foreign_symlink_upcall_item, bytestring) + \
	(sz + sizeof(__u32) - 1) / sizeof(__u32) * sizeof(__u32))

/* presently limited to not cause max stack frame size to be reached
 * because of temporary automatic array of
 * "struct ll_foreign_symlink_upcall_item" presently used in
 * foreign_symlink_upcall_info_store()
 */
#define MAX_NB_UPCALL_ITEMS 32

#if defined(__cplusplus)
}
#endif

/** @} lustreuser */

#endif /* _LUSTRE_USER_H */

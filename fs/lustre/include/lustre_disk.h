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
 *
 * lustre/include/lustre_disk.h
 *
 * Lustre disk format definitions.
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#ifndef _LUSTRE_DISK_H
#define _LUSTRE_DISK_H

/** \defgroup disk disk
 *
 * @{
 */

#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/backing-dev.h>
#include <lustre_crypto.h>

/****************** persistent mount data *********************/

#define LDD_F_SV_TYPE_MDT	0x0001
#define LDD_F_SV_TYPE_OST	0x0002
#define LDD_F_SV_TYPE_MGS	0x0004
#define LDD_F_SV_TYPE_MASK	(LDD_F_SV_TYPE_MDT  | \
				 LDD_F_SV_TYPE_OST  | \
				 LDD_F_SV_TYPE_MGS)
#define LDD_F_SV_ALL		0x0008

/****************** mount command *********************/

/* The lmd is only used internally by Lustre; mount simply passes
 * everything as string options
 */

#define LMD_MAGIC		0xbdacbd03
#define LMD_PARAMS_MAXLEN	4096

enum lmd_flags {
	LMD_FLG_SERVER		= 0,	/* Mounting a server */
	LMD_FLG_CLIENT,			/* Mounting a client */
	LMD_FLG_SKIP_LFSCK,		/* NOT auto resume LFSCK when mount */
	LMD_FLG_ABORT_RECOV,		/* Abort recovery */
	LMD_FLG_NOSVC,			/* Only start MGS/MGC for servers,
					 * no other services
					 */
	LMD_FLG_NOMGS,			/* Only start target for servers,
					 * reusing existing MGS services
					 */
	LMD_FLG_WRITECONF,		/* Rewrite config log */
	LMD_FLG_NOIR,			/* NO imperative recovery */
	LMD_FLG_NOSCRUB,			/* Do not trigger scrub automatically */
	LMD_FLG_MGS,			/* Also start MGS along with server */
	LMD_FLG_IAM,			/* IAM dir */
	LMD_FLG_NO_PRIMNODE,		/* all nodes are service nodes */
	LMD_FLG_VIRGIN,			/* the service registers first time */
	LMD_FLG_UPDATE,			/* update parameters */
	LMD_FLG_HSM,			/* Start coordinator */
	LMD_FLG_DEV_RDONLY,		/* discard modification quitely */
	LMD_FLG_NO_PRECREATE,		/* do not allow OST object creation */
	LMD_FLG_LOCAL_RECOV,		/* force recovery for local clients */
	LMD_FLG_ABORT_RECOV_MDT,	/* Abort recovery between MDTs */
	LMD_FLG_NO_LOCAL_LOGS,		/* Use config logs from MGS */
	LMD_FLG_NUM_FLAGS
};

/* gleaned from the mount command - no persistent info here */
struct lustre_mount_data {
	u32	lmd_magic;
	DECLARE_BITMAP(lmd_flags, LMD_FLG_NUM_FLAGS); /* lustre mount flags */
	int	lmd_mgs_failnodes; /* mgs failover node count */
	int	lmd_exclude_count;
	int	lmd_recovery_time_soft;
	int	lmd_recovery_time_hard;
	char	*lmd_dev;	/* device name */
	char	*lmd_profile;	/* client only */
	char	*lmd_fileset;	/* mount fileset */
	char	*lmd_mgssec;	/* sptlrpc flavor to mgs */
	char	*lmd_opts;	/* lustre mount options (as opposed to
				 * _device_ mount options)
				 */
	char	*lmd_params;	/* lustre params */
	u32	*lmd_exclude;	/* array of OSTs to ignore */
	char	*lmd_mgs;	/* MGS nid */
	char	*lmd_osd_type;	/* OSD type */
	char    *lmd_nidnet;	/* network to restrict this client to */
};

#define lmd_is_client(x) (test_bit(LMD_FLG_CLIENT, (x)->lmd_flags))

/****************** superblock additional info *********************/

struct ll_sb_info;
struct kobject;

struct lustre_sb_info {
	int			  lsi_flags;
	struct obd_device	 *lsi_mgc;    /* mgc obd */
	struct lustre_mount_data *lsi_lmd;    /* mount command info */
	struct ll_sb_info	 *lsi_llsbi;  /* add'l client sbi info */
	struct dt_device	 *lsi_dt_dev; /* dt device to access disk fs */
	atomic_t		  lsi_mounts; /* references to the srv_mnt */
	struct kobject		 *lsi_kobj;
	char			  lsi_svname[MTI_NAME_MAXLEN];
	/* lsi_osd_obdname format = 'lsi->ls_svname'-osd */
	char			  lsi_osd_obdname[MTI_NAME_MAXLEN + 4];
	/* lsi_osd_uuid format = 'lsi->ls_osd_obdname'_UUID */
	char			  lsi_osd_uuid[MTI_NAME_MAXLEN + 9];
	struct obd_export	 *lsi_osd_exp;
	char			  lsi_osd_type[16];
	char			  lsi_fstype[16];
	/* Encryption context for '-o test_dummy_encryption' */
	struct fscrypt_dummy_context lsi_dummy_enc_ctx;
};

#define LSI_UMOUNT_FAILOVER		0x00200000
#define LSI_FILENAME_ENC_B64_OLD_CLI    0x01000000 /* use old style base64 */

#define     s2lsi(sb)	((struct lustre_sb_info *)((sb)->s_fs_info))
#define     s2lsi_nocast(sb) ((sb)->s_fs_info)

#define     get_profile_name(sb)   (s2lsi(sb)->lsi_lmd->lmd_profile)
#define     get_mount_fileset(sb)  (s2lsi(sb)->lsi_lmd->lmd_fileset)

/****************** prototypes *********************/

/* obd_mount.c */
int server_name2fsname(const char *svname, char *fsname, const char **endptr);

int lustre_start_mgc(struct super_block *sb);
int lustre_common_put_super(struct super_block *sb);

struct lustre_sb_info *lustre_init_lsi(struct super_block *sb);
int lustre_put_lsi(struct super_block *sb);
int lmd_parse(char *options, struct lustre_mount_data *lmd);

/* mgc_request.c */
int mgc_fsname2resid(char *fsname, struct ldlm_res_id *res_id,
		     enum mgs_cfg_type type);

/** @} disk */

#endif /* _LUSTRE_DISK_H */

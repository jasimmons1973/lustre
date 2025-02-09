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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 *
 * Kernel <-> userspace communication routines.
 * The definitions below are used in the kernel and userspace.
 */

#ifndef __UAPI_LUSTRE_KERNELCOMM_H__
#define __UAPI_LUSTRE_KERNELCOMM_H__

#include <linux/types.h>

#define LUSTRE_GENL_NAME		"lustre"
#define LUSTRE_GENL_VERSION		0x1

/*
 * enum lustre_commands		      - Supported Lustre Netlink commands
 *
 * @LUSTRE_CMD_UNSPEC:			unspecified command to catch errors
 * @LUSTRE_CMD_DEVICES:			command to manage the Lustre devices
 */
enum lustre_commands {
	LUSTRE_CMD_UNSPEC	= 0,
	LUSTRE_CMD_DEVICES	= 1,

	__LUSTRE_CMD_MAX_PLUS_ONE
};

#define LUSTRE_CMD_MAX	(__LUSTRE_CMD_MAX_PLUS_ONE - 1)

/* KUC message header.
 * All current and future KUC messages should use this header.
 * To avoid having to include Lustre headers from libcfs, define this here.
 */
struct kuc_hdr {
	__u16 kuc_magic;
	/* Each new Lustre feature should use a different transport */
	__u8  kuc_transport;
	__u8  kuc_flags;
	/* Message type or opcode, transport-specific */
	__u16 kuc_msgtype;
	/* Including header */
	__u16 kuc_msglen;
} __attribute__((aligned(sizeof(__u64))));

#define KUC_MAGIC		0x191C /*Lustre9etLinC */

/* kuc_msgtype values are defined in each transport */
enum kuc_transport_type {
	KUC_TRANSPORT_GENERIC	= 1,
	KUC_TRANSPORT_HSM	= 2,
};

enum kuc_generic_message_type {
	KUC_MSG_SHUTDOWN	= 1,
};

/* KUC Broadcast Groups. This determines which userspace process hears which
 * messages.  Mutliple transports may be used within a group, or multiple
 * groups may use the same transport.  Broadcast
 * groups need not be used if e.g. a UID is specified instead;
 * use group 0 to signify unicast.
 */
#define KUC_GRP_HSM	0x02
#define KUC_GRP_MAX	KUC_GRP_HSM

enum lk_flags {
	LK_FLG_STOP	= 0x0001,
	LK_FLG_DATANR	= 0x0002,
};
#define LK_NOFD -1U

/* kernelcomm control structure, passed from userspace to kernel.
 * For compatibility with old copytools, users who pass ARCHIVE_IDs
 * to kernel using lk_data_count and lk_data should fill lk_flags with
 * LK_FLG_DATANR. Otherwise kernel will take lk_data_count as bitmap of
 * ARCHIVE IDs.
 */
struct lustre_kernelcomm {
	__u32 lk_wfd;
	__u32 lk_rfd;
	__u32 lk_uid;
	__u32 lk_group;
	__u32 lk_data_count;
	__u32 lk_flags;
	__u32 lk_data[0];
} __packed;

#endif	/* __UAPI_LUSTRE_KERNELCOMM_H__ */

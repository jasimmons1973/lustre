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
 * Copyright (c) 2012 - 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Seagate, Inc.
 *
 * lnet/include/lnet/socklnd.h
 */
#ifndef __LNET_LNET_SOCKLND_H__
#define __LNET_LNET_SOCKLND_H__

#include <uapi/linux/lnet/lnet-types.h>
#include <uapi/linux/lnet/socklnd.h>

struct ksock_hello_msg {
	u32		kshm_magic;	/* magic number of socklnd message */
	u32		kshm_version;	/* version of socklnd message */
	lnet_nid_t	kshm_src_nid;	/* sender's nid */
	lnet_nid_t	kshm_dst_nid;	/* destination nid */
	lnet_pid_t	kshm_src_pid;	/* sender's pid */
	lnet_pid_t	kshm_dst_pid;	/* destination pid */
	u64		kshm_src_incarnation; /* sender's incarnation */
	u64		kshm_dst_incarnation; /* destination's incarnation */
	u32		kshm_ctype;	/* connection type */
	u32		kshm_nips;	/* # IP addrs */
	u32		kshm_ips[0];	/* IP addrs */
} __packed;

struct ksock_msg_hdr {
	u32		ksh_type;		/* type of socklnd message */
	u32		ksh_csum;		/* checksum if != 0 */
	u64		ksh_zc_cookies[2];	/* Zero-Copy request/ACK
						 * cookie
						 */
} __packed;

#define KSOCK_MSG_NOOP	0xC0	/* empty */
#define KSOCK_MSG_LNET	0xC1	/* lnet msg */

struct ksock_msg {
	struct ksock_msg_hdr	ksm_kh;
	union {
		/* case ksm_kh.ksh_type == KSOCK_MSG_NOOP */
		/* - nothing */
		/* case ksm_kh.ksh_type == KSOCK_MSG_LNET */
		struct lnet_hdr_nid4 lnetmsg_nid4;
	} __packed ksm_u;
} __packed;
#define ksm_type ksm_kh.ksh_type
#define ksm_csum ksm_kh.ksh_csum
#define ksm_zc_cookies ksm_kh.ksh_zc_cookies

/* We need to know this number to parse hello msg from ksocklnd in
 * other LND (usocklnd, for example)
 */
#define KSOCK_PROTO_V2	2
#define KSOCK_PROTO_V3	3

#endif

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
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __SELFTEST_RPC_H__
#define __SELFTEST_RPC_H__

#include <uapi/linux/lnet/lnetst.h>

/*
 * LST wired structures
 *
 * XXX: *REPLY == *REQST + 1
 */
enum srpc_msg_type {
	SRPC_MSG_MKSN_REQST	= 0,
	SRPC_MSG_MKSN_REPLY	= 1,
	SRPC_MSG_RMSN_REQST	= 2,
	SRPC_MSG_RMSN_REPLY	= 3,
	SRPC_MSG_BATCH_REQST	= 4,
	SRPC_MSG_BATCH_REPLY	= 5,
	SRPC_MSG_STAT_REQST	= 6,
	SRPC_MSG_STAT_REPLY	= 7,
	SRPC_MSG_TEST_REQST	= 8,
	SRPC_MSG_TEST_REPLY	= 9,
	SRPC_MSG_DEBUG_REQST	= 10,
	SRPC_MSG_DEBUG_REPLY	= 11,
	SRPC_MSG_BRW_REQST	= 12,
	SRPC_MSG_BRW_REPLY	= 13,
	SRPC_MSG_PING_REQST	= 14,
	SRPC_MSG_PING_REPLY	= 15,
	SRPC_MSG_JOIN_REQST	= 16,
	SRPC_MSG_JOIN_REPLY	= 17,
};

/* CAVEAT EMPTOR:
 * All srpc_*_reqst_t's 1st field must be matchbits of reply buffer,
 * and 2nd field matchbits of bulk buffer if any.
 *
 * All srpc_*_reply_t's 1st field must be a u32 status, and 2nd field
 * session id if needed.
 */
struct srpc_generic_reqst {
	u64			rpyid;		/* reply buffer matchbits */
	u64			bulkid;		/* bulk buffer matchbits */
} __packed;

struct srpc_generic_reply {
	u32			status;
	struct lst_sid		sid;
} __packed;

/* FRAMEWORK RPCs */
struct srpc_mksn_reqst {
	u64			mksn_rpyid;	/* reply buffer matchbits */
	struct lst_sid		mksn_sid;	/* session id */
	u32			mksn_force;	/* use brute force */
	char			mksn_name[LST_NAME_SIZE];
} __packed; /* make session request */

struct srpc_mksn_reply {
	u32			mksn_status;	/* session status */
	struct lst_sid		mksn_sid;	/* session id */
	u32			mksn_timeout;	/* session timeout */
	char			mksn_name[LST_NAME_SIZE];
} __packed; /* make session reply */

struct srpc_rmsn_reqst {
	u64			rmsn_rpyid;	/* reply buffer matchbits */
	struct lst_sid		rmsn_sid;	/* session id */
} __packed; /* remove session request */

struct srpc_rmsn_reply {
	u32			rmsn_status;
	struct lst_sid		rmsn_sid;	/* session id */
} __packed; /* remove session reply */

struct srpc_join_reqst {
	u64			join_rpyid;	/* reply buffer matchbits */
	struct lst_sid		join_sid;	/* session id to join */
	char			join_group[LST_NAME_SIZE]; /* group name */
} __packed;

struct srpc_join_reply {
	u32			join_status;	/* returned status */
	struct lst_sid		join_sid;	/* session id */
	u32			join_timeout;	/* # seconds' inactivity to
						 * expire
						 */
	char			join_session[LST_NAME_SIZE]; /* session name */
} __packed;

struct srpc_debug_reqst {
	u64			dbg_rpyid;	/* reply buffer matchbits */
	struct lst_sid		dbg_sid;	/* session id */
	u32			dbg_flags;	/* bitmap of debug */
} __packed;

struct srpc_debug_reply {
	u32			dbg_status;	/* returned code */
	struct lst_sid		dbg_sid;	/* session id */
	u32			dbg_timeout;	/* session timeout */
	u32			dbg_nbatch;	/* # of batches in the node */
	char			dbg_name[LST_NAME_SIZE]; /* session name */
} __packed;

#define SRPC_BATCH_OPC_RUN	1
#define SRPC_BATCH_OPC_STOP	2
#define SRPC_BATCH_OPC_QUERY	3

struct srpc_batch_reqst {
	u64		   bar_rpyid;	   /* reply buffer matchbits */
	struct lst_sid	   bar_sid;	   /* session id */
	struct lst_bid	   bar_bid;	   /* batch id */
	u32		   bar_opc;	   /* create/start/stop batch */
	u32		   bar_testidx;    /* index of test */
	u32		   bar_arg;	   /* parameters */
} __packed;

struct srpc_batch_reply {
	u32		   bar_status;	   /* status of request */
	struct lst_sid	   bar_sid;	   /* session id */
	u32		   bar_active;	   /* # of active tests in batch/test */
	u32		   bar_time;	   /* remained time */
} __packed;

struct srpc_stat_reqst {
	u64		   str_rpyid;	   /* reply buffer matchbits */
	struct lst_sid	   str_sid;	   /* session id */
	u32		   str_type;	   /* type of stat */
} __packed;

struct srpc_stat_reply {
	u32			    str_status;
	struct lst_sid		    str_sid;
	struct sfw_counters	    str_fw;
	struct srpc_counters	    str_rpc;
	struct lnet_counters_common str_lnet;
} __packed;

struct test_bulk_req {
	u32		   blk_opc;	   /* bulk operation code */
	u32		   blk_npg;	   /* # of pages */
	u32		   blk_flags;	   /* reserved flags */
} __packed;

struct test_bulk_req_v1 {
	u16		   blk_opc;	   /* bulk operation code */
	u16		   blk_flags;	   /* data check flags */
	u32		   blk_len;	   /* data length */
	u32		   blk_offset;	   /* offset */
} __packed;

struct test_ping_req {
	u32		   png_size;	   /* size of ping message */
	u32		   png_flags;	   /* reserved flags */
} __packed;

struct srpc_test_reqst {
	u64			tsr_rpyid;	/* reply buffer matchbits */
	u64			tsr_bulkid;	/* bulk buffer matchbits */
	struct lst_sid		tsr_sid;	/* session id */
	struct lst_bid		tsr_bid;	/* batch id */
	u32			tsr_service;	/* test type: bulk|ping|... */
	u32			tsr_loop;	/* test client loop count or
						 * # server buffers needed
						 */
	u32			tsr_concur;	/* concurrency of test */
	u8			tsr_is_client;	/* is test client or not */
	u8			tsr_stop_onerr; /* stop on error */
	u32			tsr_ndest;	/* # of dest nodes */

	union {
		struct test_ping_req	ping;
		struct test_bulk_req	bulk_v0;
		struct test_bulk_req_v1	bulk_v1;
	} tsr_u;
} __packed;

struct srpc_test_reply {
	u32			tsr_status;	/* returned code */
	struct lst_sid		tsr_sid;
} __packed;

/* TEST RPCs */
struct srpc_ping_reqst {
	u64	pnr_rpyid;
	u32	pnr_magic;
	u32	pnr_seq;
	u64	pnr_time_sec;
	u64	pnr_time_usec;
} __packed;

struct srpc_ping_reply {
	u32	pnr_status;
	u32	pnr_magic;
	u32	pnr_seq;
} __packed;

struct srpc_brw_reqst {
	u64	brw_rpyid;	/* reply buffer matchbits */
	u64	brw_bulkid;	/* bulk buffer matchbits */
	u32	brw_rw;		/* read or write */
	u32	brw_len;	/* bulk data len */
	u32	brw_flags;	/* bulk data patterns */
} __packed; /* bulk r/w request */

struct srpc_brw_reply {
	u32	brw_status;
} __packed; /* bulk r/w reply */

#define SRPC_MSG_MAGIC		0xeeb0f00d
#define SRPC_MSG_VERSION	1

struct srpc_msg {
	u32	msg_magic;     /* magic number */
	u32	msg_version;   /* message version number */
	u32	msg_type;      /* type of message body: srpc_msg_type */
	u32	msg_reserved0;
	u32	msg_reserved1;
	u32	msg_ses_feats; /* test session features */
	union {
		struct srpc_generic_reqst	reqst;
		struct srpc_generic_reply	reply;

		struct srpc_mksn_reqst		mksn_reqst;
		struct srpc_mksn_reply		mksn_reply;
		struct srpc_rmsn_reqst		rmsn_reqst;
		struct srpc_rmsn_reply		rmsn_reply;
		struct srpc_debug_reqst		dbg_reqst;
		struct srpc_debug_reply		dbg_reply;
		struct srpc_batch_reqst		bat_reqst;
		struct srpc_batch_reply		bat_reply;
		struct srpc_stat_reqst		stat_reqst;
		struct srpc_stat_reply		stat_reply;
		struct srpc_test_reqst		tes_reqst;
		struct srpc_test_reply		tes_reply;
		struct srpc_join_reqst		join_reqst;
		struct srpc_join_reply		join_reply;

		struct srpc_ping_reqst		ping_reqst;
		struct srpc_ping_reply		ping_reply;
		struct srpc_brw_reqst		brw_reqst;
		struct srpc_brw_reply		brw_reply;
	}     msg_body;
} __packed;

static inline void
srpc_unpack_msg_hdr(struct srpc_msg *msg)
{
	if (msg->msg_magic == SRPC_MSG_MAGIC)
		return; /* no flipping needed */

	/*
	 * We do not swap the magic number here as it is needed to
	 * determine whether the body needs to be swapped.
	 */
	/* __swab32s(&msg->msg_magic); */
	__swab32s(&msg->msg_type);
	__swab32s(&msg->msg_version);
	__swab32s(&msg->msg_ses_feats);
	__swab32s(&msg->msg_reserved0);
	__swab32s(&msg->msg_reserved1);
}

#endif /* __SELFTEST_RPC_H__ */

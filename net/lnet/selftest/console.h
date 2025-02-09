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
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/selftest/console.h
 *
 * kernel structure for LST console
 *
 * Author: Liang Zhen <liangzhen@clusterfs.com>
 */

#ifndef __LST_CONSOLE_H__
#define __LST_CONSOLE_H__

#include <linux/lnet/lib-types.h>
#include "selftest.h"
#include "conrpc.h"

/* node descriptor */
struct lstcon_node {
	struct lnet_process_id	nd_id;	/* id of the node */
	int		  nd_ref;     /* reference count */
	int		  nd_state;   /* state of the node */
	int		  nd_timeout; /* session timeout */
	ktime_t			nd_stamp;   /* timestamp of last replied RPC */
	struct lstcon_rpc nd_ping;    /* ping rpc */
};

/* node link descriptor */
struct lstcon_ndlink {
	struct list_head ndl_link;    /* chain on list */
	struct list_head ndl_hlink;   /* chain on hash */
	struct lstcon_node	*ndl_node;	/* pointer to node */
};

/* (alias of nodes) group descriptor */
struct lstcon_group {
	struct list_head grp_link;		  /* chain on global group list */
	int		 grp_ref;		  /* reference count */
	int		 grp_userland;		  /* has userland nodes */
	int		 grp_nnode;		  /* # of nodes */
	char		 grp_name[LST_NAME_SIZE]; /* group name */

	struct list_head grp_trans_list;	  /* transaction list */
	struct list_head grp_ndl_list;		  /* nodes list */
	struct list_head grp_ndl_hash[0];	  /* hash table for nodes */
};

#define LST_BATCH_IDLE		0xB0	/* idle batch */
#define LST_BATCH_RUNNING	0xB1	/* running batch */

struct lstcon_tsb_hdr {
	struct lst_bid	 tsb_id;	/* batch ID */
	int		 tsb_index;	/* test index */
};

/* (tests ) batch descriptor */
struct lstcon_batch {
	struct lstcon_tsb_hdr	bat_hdr;  /* test_batch header */
	struct list_head bat_link;	  /* chain on session's batches list */
	int		 bat_ntest;	  /* # of test */
	int		 bat_state;	  /* state of the batch */
	int		 bat_arg;	  /* parameter for run|stop, timeout
					   * for run, force for stop
					   */
	char		 bat_name[LST_NAME_SIZE];/* name of batch */

	struct list_head bat_test_list;	  /* list head of tests
					   *   (struct lstcon_test)
					   */
	struct list_head bat_trans_list;  /* list head of transaction */
	struct list_head bat_cli_list;	  /* list head of client nodes
					   * (struct lstcon_node)
					   */
	struct list_head *bat_cli_hash;	  /* hash table of client nodes */
	struct list_head bat_srv_list;	  /* list head of server nodes */
	struct list_head *bat_srv_hash;	  /* hash table of server nodes */
};

/* a single test descriptor */
struct lstcon_test {
	struct lstcon_tsb_hdr	tes_hdr;	/* test batch header */
	struct list_head	tes_link;	/* chain on batch's tests list */
	struct lstcon_batch	*tes_batch;	/* pointer to batch */

	int		 tes_type;	 /* type of the test, i.e: bulk, ping */
	int		 tes_stop_onerr; /* stop on error */
	int		 tes_oneside;	 /* one-sided test */
	int		 tes_concur;	 /* concurrency */
	int		 tes_loop;	 /* loop count */
	int		 tes_dist;	 /* nodes distribution of target group */
	int		 tes_span;	 /* nodes span of target group */
	int		 tes_cliidx;	 /* client index, used for RPC creating */

	struct list_head tes_trans_list; /* transaction list */
	struct lstcon_group	*tes_src_grp;	/* group run the test */
	struct lstcon_group	*tes_dst_grp;	/* target group */

	int		 tes_paramlen;	 /* test parameter length */
	char		 tes_param[0];	 /* test parameter */
};

#define LST_GLOBAL_HASHSIZE	503	/* global nodes hash table size */
#define LST_NODE_HASHSIZE	239	/* node hash table (for batch or group) */

#define LST_SESSION_NONE	0x0	/* no session */
#define LST_SESSION_ACTIVE	0x1	/* working session */

#define LST_CONSOLE_TIMEOUT	300	/* default console timeout */

struct lstcon_session {
	struct mutex		ses_mutex;	/* only 1 thread in session */
	struct lst_session_id	ses_id;		/* global session id */
	u32			ses_key;	/* local session key */
	int			ses_state;	/* state of session */
	int			ses_timeout;	/* timeout in seconds */
	time64_t		ses_laststamp;	/* last operation stamp (secs) */
	unsigned int		ses_features;	/* tests features of the session */
	unsigned int		ses_feats_updated:1; /* features are synced with
						      * remote test nodes
						      */
	unsigned int		ses_force:1;	/* force creating */
	unsigned int		ses_shutdown:1;	/* session is shutting down */
	unsigned int		ses_expired:1;	/* console is timedout */
	u64			ses_id_cookie;	/* batch id cookie */
	char			ses_name[LST_NAME_SIZE];/* session name */
	struct lstcon_rpc_trans *ses_ping;	/* session pinger */
	struct stt_timer	ses_ping_timer;	/* timer for pinger */
	struct lstcon_trans_stat ses_trans_stat;/* transaction stats */

	struct list_head	ses_trans_list;	/* global list of transaction */
	struct list_head	ses_grp_list;	/* global list of groups */
	struct list_head	ses_bat_list;	/* global list of batches */
	struct list_head	ses_ndl_list;	/* global list of nodes */
	struct list_head	*ses_ndl_hash;	/* hash table of nodes */

	spinlock_t		ses_rpc_lock;	/* serialize */
	atomic_t		ses_rpc_counter;/* # of initialized RPCs */
	struct list_head	ses_rpc_freelist;/* idle console rpc */
}; /* session descriptor */

extern struct lstcon_session	console_session;

static inline struct lstcon_trans_stat *
lstcon_trans_stat(void)
{
	return &console_session.ses_trans_stat;
}

static inline struct list_head *
lstcon_id2hash(struct lnet_process_id id, struct list_head *hash)
{
	unsigned int idx = LNET_NIDADDR(id.nid) % LST_NODE_HASHSIZE;

	return &hash[idx];
}

int lstcon_ioctl_entry(struct notifier_block *nb,
		       unsigned long cmd, void *vdata);

int lstcon_init_netlink(void);
void lstcon_fini_netlink(void);

int lstcon_console_init(void);
int lstcon_console_fini(void);

int lstcon_session_match(struct lst_sid sid);
int lstcon_session_new(char *name, int key, unsigned int version,
		       int timeout, int flags);
int lstcon_session_end(void);
int lstcon_session_debug(int timeout, struct list_head __user *result_up);
int lstcon_session_feats_check(unsigned int feats);
int lstcon_batch_debug(int timeout, char *name,
		       int client, struct list_head __user *result_up);
int lstcon_group_debug(int timeout, char *name,
		       struct list_head __user *result_up);
int lstcon_nodes_debug(int timeout, int nnd,
		       struct lnet_process_id __user *nds_up,
		       struct list_head __user *result_up);
int lstcon_group_add(char *name);
int lstcon_group_del(char *name);
void lstcon_group_addref(struct lstcon_group *grp);
void lstcon_group_decref(struct lstcon_group *grp);
int lstcon_group_find(const char *name, struct lstcon_group **grpp);
int lstcon_group_clean(char *name, int args);
int lstcon_group_refresh(char *name, struct list_head __user *result_up);
int lstcon_nodes_add(char *name, int nnd, struct lnet_process_id __user *nds_up,
		     unsigned int *featp, struct list_head __user *result_up);
int lstcon_nodes_remove(char *name, int nnd,
			struct lnet_process_id __user *nds_up,
			struct list_head __user *result_up);
int lstcon_group_info(char *name, struct lstcon_ndlist_ent __user *gent_up,
		      int *index_p, int *ndent_p,
		      struct lstcon_node_ent __user *ndents_up);
int lstcon_batch_add(char *name);
int lstcon_batch_run(char *name, int timeout,
		     struct list_head __user *result_up);
int lstcon_batch_stop(char *name, int force,
		      struct list_head __user *result_up);
int lstcon_test_batch_query(char *name, int testidx,
			    int client, int timeout,
			    struct list_head __user *result_up);
int lstcon_batch_del(char *name);
int lstcon_batch_list(int idx, int namelen, char __user *name_up);
int lstcon_batch_info(char *name, struct lstcon_test_batch_ent __user *ent_up,
		      int server, int testidx, int *index_p,
		      int *ndent_p, struct lstcon_node_ent __user *dents_up);
int lstcon_group_stat(char *grp_name, int timeout,
		      struct list_head __user *result_up);
int lstcon_nodes_stat(int count, struct lnet_process_id __user *ids_up,
		      int timeout, struct list_head __user *result_up);
int lstcon_test_add(char *batch_name, int type, int loop,
		    int concur, int dist, int span,
		    char *src_name, char *dst_name,
		    void *param, int paramlen, int *retp,
		    struct list_head __user *result_up);
#endif

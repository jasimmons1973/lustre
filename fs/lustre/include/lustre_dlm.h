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
 * Copyright (c) 2010, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

/** \defgroup LDLM Lustre Distributed Lock Manager
 *
 * Lustre DLM is based on VAX DLM.
 * Its two main roles are:
 *   - To provide locking assuring consistency of data on all Lustre nodes.
 *   - To allow clients to cache state protected by a lock by holding the
 *     lock until a conflicting lock is requested or it is expired by the LRU.
 *
 * @{
 */

#ifndef _LUSTRE_DLM_H__
#define _LUSTRE_DLM_H__

#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_handles.h>
#include <linux/interval_tree_generic.h>
#include <lu_ref.h>

#include "lustre_dlm_flags.h"

struct obd_ops;
struct obd_device;

#define OBD_LDLM_DEVICENAME  "ldlm"

#define LDLM_DEFAULT_LRU_SIZE (100 * num_online_cpus())
#define LDLM_DEFAULT_MAX_ALIVE (64 * 60)	/* 65 min */
/* if client lock is unused for that time it can be cancelled if any other
 * client shows interest in that lock, e.g. glimpse is occurred.
 */
#define LDLM_DIRTY_AGE_LIMIT (10)
#define LDLM_DEFAULT_PARALLEL_AST_LIMIT 1024
#define LDLM_DEFAULT_LRU_SHRINK_BATCH (16)
#define LDLM_DEFAULT_SLV_RECALC_PCT (10)

/**
 * LDLM non-error return states
 */
enum ldlm_error {
	ELDLM_OK		= 0,
	ELDLM_LOCK_MATCHED	= 1,

	ELDLM_LOCK_CHANGED	= 300,
	ELDLM_LOCK_ABORTED	= 301,
	ELDLM_LOCK_REPLACED	= 302,
	ELDLM_NO_LOCK_DATA	= 303,
	ELDLM_LOCK_WOULDBLOCK	= 304,

	ELDLM_NAMESPACE_EXISTS	= 400,
	ELDLM_BAD_NAMESPACE	= 401
};

/**
 * LDLM namespace type.
 * The "client" type is actually an indication that this is a narrow local view
 * into complete namespace on the server. Such namespaces cannot make any
 * decisions about lack of conflicts or do any autonomous lock granting without
 * first speaking to a server.
 */
enum ldlm_side {
	LDLM_NAMESPACE_SERVER = 0x01,
	LDLM_NAMESPACE_CLIENT = 0x02
};

/**
 * The blocking callback is overloaded to perform two functions.  These flags
 * indicate which operation should be performed.
 */
#define LDLM_CB_BLOCKING    1
#define LDLM_CB_CANCELING   2

/**
 * \name Lock Compatibility Matrix.
 *
 * A lock has both a type (extent, flock, inode bits, or plain) and a mode.
 * Lock types are described in their respective implementation files:
 * ldlm_{extent,flock,inodebits,plain}.c.
 *
 * There are six lock modes along with a compatibility matrix to indicate if
 * two locks are compatible.
 *
 * - EX: Exclusive mode. Before a new file is created, MDS requests EX lock
 *   on the parent.
 * - PW: Protective Write (normal write) mode. When a client requests a write
 *   lock from an OST, a lock with PW mode will be issued.
 * - PR: Protective Read (normal read) mode. When a client requests a read from
 *   an OST, a lock with PR mode will be issued. Also, if the client opens a
 *   file for execution, it is granted a lock with PR mode.
 * - CW: Concurrent Write mode. The type of lock that the MDS grants if a client
 *   requests a write lock during a file open operation.
 * - CR Concurrent Read mode. When a client performs a path lookup, MDS grants
 *   an inodebit lock with the CR mode on the intermediate path component.
 * - NL Null mode.
 *
 * <PRE>
 *       NL  CR  CW  PR  PW  EX
 *  NL    1   1   1   1   1   1
 *  CR    1   1   1   1   1   0
 *  CW    1   1   1   0   0   0
 *  PR    1   1   0   1   0   0
 *  PW    1   1   0   0   0   0
 *  EX    1   0   0   0   0   0
 * </PRE>
 */
/** @{ */
#define LCK_COMPAT_EX  LCK_NL
#define LCK_COMPAT_PW  (LCK_COMPAT_EX | LCK_CR)
#define LCK_COMPAT_PR  (LCK_COMPAT_PW | LCK_PR)
#define LCK_COMPAT_CW  (LCK_COMPAT_PW | LCK_CW)
#define LCK_COMPAT_CR  (LCK_COMPAT_CW | LCK_PR | LCK_PW)
#define LCK_COMPAT_NL  (LCK_COMPAT_CR | LCK_EX | LCK_GROUP)
#define LCK_COMPAT_GROUP  (LCK_GROUP | LCK_NL)
#define LCK_COMPAT_COS (LCK_COS)
/** @} Lock Compatibility Matrix */

extern enum ldlm_mode lck_compat_array[];

static inline void lockmode_verify(enum ldlm_mode mode)
{
	LASSERT(mode > LCK_MINMODE && mode < LCK_MAXMODE);
}

static inline int lockmode_compat(enum ldlm_mode exist_mode,
				  enum ldlm_mode new_mode)
{
	return (lck_compat_array[exist_mode] & new_mode);
}

/*
 *
 * cluster name spaces
 *
 */

#define DLM_OST_NAMESPACE 1
#define DLM_MDS_NAMESPACE 2

/* XXX
 * - do we just separate this by security domains and use a prefix for
 *    multiple namespaces in the same domain?
 */

/**
 * Locking rules for LDLM:
 *
 * lr_lock
 *
 * lr_lock
 *     waiting_locks_spinlock
 *
 * lr_lock
 *     led_lock
 *
 * lr_lock
 *     ns_lock
 *
 * lr_lvb_mutex
 *     lr_lock
 *
 */

/* Cancel lru flag, it indicates we cancel aged locks. */
enum ldlm_lru_flags {
	LDLM_LRU_FLAG_NO_WAIT	= 0x1,	/* Cancel locks w/o blocking (neither
					 * sending nor waiting for any RPCs)
					 */
	LDLM_LRU_FLAG_CLEANUP   = 0x2,	/* Used when clearing lru, tells
					 * prepare_lru_list to set discard flag
					 * on PR extent locks so we don't waste
					 * time saving pages that will be
					 * discarded momentarily
					 */
};

struct ldlm_pool;
struct ldlm_lock;
struct ldlm_resource;
struct ldlm_namespace;

/**
 * Operations on LDLM pools.
 * LDLM pool is a pool of locks in the namespace without any implicitly
 * specified limits.
 * Locks in the pool are organized in LRU.
 * Local memory pressure or server instructions (e.g. mempressure on server)
 * can trigger freeing of locks from the pool
 */
struct ldlm_pool_ops {
	/** Recalculate pool @pl usage */
	int (*po_recalc)(struct ldlm_pool *pl, bool force);
	/** Cancel at least @nr locks from pool @pl */
	int (*po_shrink)(struct ldlm_pool *pl, int nr,
			 gfp_t gfp_mask);
};

/** One second for pools thread check interval. Each pool has own period. */
#define LDLM_POOLS_THREAD_PERIOD (1)

/** ~6% margin for modest pools. See ldlm_pool.c for details. */
#define LDLM_POOLS_MODEST_MARGIN_SHIFT (4)

/** Default recalc period for server side pools in sec. */
#define LDLM_POOL_SRV_DEF_RECALC_PERIOD (1)

/** Default recalc period for client side pools in sec. */
#define LDLM_POOL_CLI_DEF_RECALC_PERIOD (10)

/**
 * LDLM pool structure to track granted locks.
 * For purposes of determining when to release locks on e.g. memory pressure.
 * This feature is commonly referred to as lru_resize.
 */
struct ldlm_pool {
	/** Pool debugfs directory. */
	struct dentry		*pl_debugfs_entry;
	/** Pool name, must be long enough to hold compound proc entry name. */
	char			pl_name[100];
	/** Lock for protecting SLV/CLV updates. */
	spinlock_t		pl_lock;
	/** Number of allowed locks in in pool, both, client and server side. */
	atomic_t		pl_limit;
	/** Number of granted locks in */
	atomic_t		pl_granted;
	/** Grant rate per T. */
	atomic_t		pl_grant_rate;
	/** Cancel rate per T. */
	atomic_t		pl_cancel_rate;
	/** Server lock volume (SLV). Protected by pl_lock. */
	u64			pl_server_lock_volume;
	/** Current biggest client lock volume. Protected by pl_lock. */
	u64			pl_client_lock_volume;
	/** Lock volume factor, shown in percents in procfs, but internally
	 *  Client SLV calculated as: server_slv * lock_volume_factor >> 8.
	 */
	atomic_t		pl_lock_volume_factor;
	/** Time when last SLV from server was obtained. */
	time64_t		pl_recalc_time;
	/** Recalculation period for pool. */
	time64_t		pl_recalc_period;
	/** Recalculation and shrink operations. */
	const struct ldlm_pool_ops	*pl_ops;
	/** Number of planned locks for next period. */
	int			pl_grant_plan;
	/** Pool statistics. */
	struct lprocfs_stats	*pl_stats;

	/* sysfs object */
	struct kobject		 pl_kobj;
	struct completion	 pl_kobj_unregister;
};

typedef int (*ldlm_cancel_cbt)(struct ldlm_lock *lock);

/**
 * LVB operations.
 * LVB is Lock Value Block. This is a special opaque (to LDLM) value that could
 * be associated with an LDLM lock and transferred from client to server and
 * back.
 *
 * Currently LVBs are used by:
 *  - OSC-OST code to maintain current object size/times
 *  - layout lock code to return the layout when the layout lock is granted
 *
 * To ensure delayed LVB initialization, it is highly recommended to use the set
 * of ldlm_[res_]lvbo_[init,update,fill]() functions.
 */
struct ldlm_valblock_ops {
	int (*lvbo_free)(struct ldlm_resource *res);
};

/**
 * LDLM pools related, type of lock pool in the namespace.
 * Greedy means release cached locks aggressively
 */
enum ldlm_appetite {
	LDLM_NAMESPACE_GREEDY = BIT(0),
	LDLM_NAMESPACE_MODEST = BIT(1),
};

struct ldlm_ns_bucket {
	/** back pointer to namespace */
	struct ldlm_namespace      *nsb_namespace;
	/**
	 * Estimated lock callback time.  Used by adaptive timeout code to
	 * avoid spurious client evictions due to unresponsiveness when in
	 * fact the network or overall system load is at fault
	 */
	struct adaptive_timeout     nsb_at_estimate;
	/* counter of entries in this bucket */
	atomic_t		nsb_count;
};

enum {
	/** LDLM namespace lock stats */
	LDLM_NSS_LOCKS	  = 0,
	LDLM_NSS_LAST
};

enum ldlm_ns_type {
	/** invalid type */
	LDLM_NS_TYPE_UNKNOWN    = 0,
	/** mdc namespace */
	LDLM_NS_TYPE_MDC,
	/** mds namespace */
	LDLM_NS_TYPE_MDT,
	/** osc namespace */
	LDLM_NS_TYPE_OSC,
	/** ost namespace */
	LDLM_NS_TYPE_OST,
	/** mgc namespace */
	LDLM_NS_TYPE_MGC,
	/** mgs namespace */
	LDLM_NS_TYPE_MGT,
};

enum ldlm_namespace_flags {
	/**
	 * Flag to indicate the LRU cancel is in progress.
	 * Used to limit the process by 1 thread only.
	 */
	LDLM_LRU_CANCEL = 0
};

/**
 * LDLM Namespace.
 *
 * Namespace serves to contain locks related to a particular service.
 * There are two kinds of namespaces:
 * - Server namespace has knowledge of all locks and is therefore authoritative
 *   to make decisions like what locks could be granted and what conflicts
 *   exist during new lock enqueue.
 * - Client namespace only has limited knowledge about locks in the namespace,
 *   only seeing locks held by the client.
 *
 * Every Lustre service has one server namespace present on the server serving
 * that service. Every client connected to the service has a client namespace
 * for it.
 * Every lock obtained by client in that namespace is actually represented by
 * two in-memory locks. One on the server and one on the client. The locks are
 * linked by a special cookie by which one node can tell to the other which lock
 * it actually means during communications. Such locks are called remote locks.
 * The locks held by server only without any reference to a client are called
 * local locks.
 */
struct ldlm_namespace {
	/** Backward link to OBD, required for LDLM pool to store new SLV. */
	struct obd_device	*ns_obd;

	/** Flag indicating if namespace is on client instead of server */
	enum ldlm_side		ns_client;

	/** name of this namespace */
	char			*ns_name;

	/** Resource hash table for namespace. */
	struct cfs_hash		*ns_rs_hash;
	struct ldlm_ns_bucket	*ns_rs_buckets;
	unsigned int		ns_bucket_bits;

	/** serialize */
	spinlock_t		ns_lock;

	/** big refcount (by bucket) */
	atomic_t		ns_bref;

	/**
	 * Namespace connect flags supported by server (may be changed via
	 * sysfs, LRU resize may be disabled/enabled).
	 */
	u64			ns_connect_flags;

	/** Client side original connect flags supported by server. */
	u64			ns_orig_connect_flags;

	/* namespace debugfs dir entry */
	struct dentry		*ns_debugfs_entry;

	/**
	 * Position in global namespace list linking all namespaces on
	 * the node.
	 */
	struct list_head	ns_list_chain;

	/**
	 * List of unused locks for this namespace. This list is also called
	 * LRU lock list.
	 * Unused locks are locks with zero reader/writer reference counts.
	 * This list is only used on clients for lock caching purposes.
	 * When we want to release some locks voluntarily or if server wants
	 * us to release some locks due to e.g. memory pressure, we take locks
	 * to release from the head of this list.
	 * Locks are linked via l_lru field in \see struct ldlm_lock.
	 */
	struct list_head	ns_unused_list;
	/** Number of locks in the LRU list above */
	int			ns_nr_unused;
	struct list_head	*ns_last_pos;

	/**
	 * Maximum number of locks permitted in the LRU. If 0, means locks
	 * are managed by pools and there is no preset limit, rather it is all
	 * controlled by available memory on this client and on server.
	 */
	unsigned int		ns_max_unused;

	/**
	 * Cancel batch, if unused lock count exceed lru_size
	 * Only be used if LRUR disable.
	 */
	unsigned int		ns_cancel_batch;

	/**
	 * How much the SLV should decrease in %% to trigger LRU cancel
	 * urgently.
	 */
	unsigned int		ns_recalc_pct;

	/** Maximum allowed age (last used time) for locks in the LRU. Set in
	 * seconds from userspace, but stored in ns to avoid repeat conversions.
	 */
	ktime_t			ns_max_age;
	/**
	 * Number of (nano)seconds since the lock was last used. The client
	 * may cancel the lock older than this age and flush related data if
	 * another client shows interest in this lock by doing glimpse request.
	 * This allows to cache stat data locally for such files early. Set in
	 * seconds from userspace, but stored in ns to avoid repeat conversions.
	 */
	ktime_t			ns_dirty_age_limit;
	/**
	 * Used to rate-limit ldlm_namespace_dump calls.
	 * \see ldlm_namespace_dump. Increased by 10 seconds every time
	 * it is called.
	 */
	time64_t		ns_next_dump;

	/**
	 * LVB operations for this namespace.
	 * \see struct ldlm_valblock_ops
	 */
	struct ldlm_valblock_ops *ns_lvbo;

	/**
	 * Used by filter code to store pointer to OBD of the service.
	 * Should be dropped in favor of @ns_obd
	 */
	void			*ns_lvbp;

	/**
	 * Wait queue used by __ldlm_namespace_free. Gets woken up every time
	 * a resource is removed.
	 */
	wait_queue_head_t	ns_waitq;
	/** LDLM pool structure for this namespace */
	struct ldlm_pool	ns_pool;
	/** Definition of how eagerly unused locks will be released from LRU */
	enum ldlm_appetite	ns_appetite;

	/** Limit of parallel AST RPC count. */
	unsigned int		ns_max_parallel_ast;

	/**
	 * Callback to check if a lock is good to be canceled by ELC or
	 * during recovery.
	 */
	ldlm_cancel_cbt		ns_cancel;

	/** LDLM lock stats */
	struct lprocfs_stats	*ns_stats;

	/**
	 * Flag to indicate namespace is being freed. Used to determine if
	 * recalculation of LDLM pool statistics should be skipped.
	 */
	unsigned int		ns_stopping:1,

	/**
	 * Flag to indicate the LRU recalc on RPC reply is in progress.
	 * Used to limit the process by 1 thread only.
	 */
				ns_rpc_recalc:1;

	struct kobject		ns_kobj; /* sysfs object */
	struct completion	ns_kobj_unregister;

	/**
	 * To avoid another ns_lock usage, a separate bitops field.
	 */
	unsigned long		ns_flags;
};

/**
 * Returns 1 if namespace @ns supports early lock cancel (ELC).
 */
static inline int ns_connect_cancelset(struct ldlm_namespace *ns)
{
	return !!(ns->ns_connect_flags & OBD_CONNECT_CANCELSET);
}

/**
 * Returns 1 if this namespace supports lru_resize.
 */
static inline int ns_connect_lru_resize(struct ldlm_namespace *ns)
{
	return !!(ns->ns_connect_flags & OBD_CONNECT_LRU_RESIZE);
}

static inline void ns_register_cancel(struct ldlm_namespace *ns,
				      ldlm_cancel_cbt arg)
{
	ns->ns_cancel = arg;
}

struct ldlm_lock;

/** Type for blocking callback function of a lock. */
typedef int (*ldlm_blocking_callback)(struct ldlm_lock *lock,
				      struct ldlm_lock_desc *new, void *data,
				      int flag);
/** Type for completion callback function of a lock. */
typedef int (*ldlm_completion_callback)(struct ldlm_lock *lock, u64 flags,
					void *data);
/** Type for glimpse callback function of a lock. */
typedef int (*ldlm_glimpse_callback)(struct ldlm_lock *lock, void *data);

/** Work list for sending GL ASTs to multiple locks. */
struct ldlm_glimpse_work {
	struct ldlm_lock	*gl_lock; /* lock to glimpse */
	struct list_head	 gl_list; /* linkage to other gl work structs */
	u32			 gl_flags;/* see LDLM_GL_WORK_* below */
	union ldlm_gl_desc	*gl_desc; /* glimpse descriptor to be packed in
					   * glimpse callback request
					   */
};

/* The ldlm_glimpse_work was slab allocated & must be freed accordingly.*/
#define LDLM_GL_WORK_SLAB_ALLOCATED 0x1

/**
 * Interval tree for extent locks.
 * The interval tree must be accessed under the resource lock.
 * Interval trees are used for granted extent locks to speed up conflicts
 * lookup.
 */
struct ldlm_interval_tree {
	/** Tree size. */
	int			lit_size;
	enum ldlm_mode		lit_mode;  /* lock mode */
	struct rb_root_cached	lit_root; /* actual interval tree */
};

/** Whether to track references to exports by LDLM locks. */
#define LUSTRE_TRACKS_LOCK_EXP_REFS (0)

/** Cancel flags. */
enum ldlm_cancel_flags {
	LCF_ASYNC      = 0x1, /* Cancel locks asynchronously. */
	LCF_LOCAL      = 0x2, /* Cancel locks locally, not notifing server */
	LCF_BL_AST     = 0x4, /* Cancel locks marked as LDLM_FL_BL_AST
			       * in the same RPC
			       */
};

struct ldlm_flock {
	u64			start;
	u64			end;
	u64			owner;
	u64			blocking_owner;
	struct obd_export	*blocking_export;
	u32			pid;
};

union ldlm_policy_data {
	struct ldlm_extent	l_extent;
	struct ldlm_flock	l_flock;
	struct ldlm_inodebits	l_inodebits;
};

void ldlm_convert_policy_to_local(struct obd_export *exp, enum ldlm_type type,
				  const union ldlm_wire_policy_data *wpolicy,
				  union ldlm_policy_data *lpolicy);

enum lvb_type {
	LVB_T_NONE	= 0,
	LVB_T_OST	= 1,
	LVB_T_LQUOTA	= 2,
	LVB_T_LAYOUT	= 3,
};

/**
 * LDLM_GID_ANY is used to match any group id in ldlm_lock_match().
 */
#define LDLM_GID_ANY	((u64)-1)

/**
 * LDLM lock structure
 *
 * Represents a single LDLM lock and its state in memory. Each lock is
 * associated with a single ldlm_resource, the object which is being
 * locked. There may be multiple ldlm_locks on a single resource,
 * depending on the lock type and whether the locks are conflicting or
 * not.
 */
struct ldlm_lock {
	/**
	 * Local lock handle.
	 * When remote side wants to tell us about a lock, they address
	 * it by this opaque handle.  The handle does not hold a
	 * reference on the ldlm_lock, so it can be safely passed to
	 * other threads or nodes. When the lock needs to be accessed
	 * from the handle, it is looked up again in the lock table, and
	 * may no longer exist.
	 *
	 * Must be first in the structure.
	 */
	struct portals_handle		l_handle;
	/**
	 * Pointer to actual resource this lock is in.
	 * ldlm_lock_change_resource() can change this on the client.
	 * When this is possible, rcu must be used to stablise
	 * the resource while we lock and check it hasn't been changed.
	 */
	struct ldlm_resource		*l_resource;
	/**
	 * List item for client side LRU list.
	 * Protected by ns_lock in struct ldlm_namespace.
	 */
	struct list_head		l_lru;
	/**
	 * Linkage to resource's lock queues according to current lock state.
	 * (could be granted, waiting or converting)
	 * Protected by lr_lock in struct ldlm_resource.
	 */
	struct list_head		l_res_link;

	/**
	 * Internal structure per lock type..
	 */
	/* LDLM_EXTENT locks only */
	struct ldlm_extent		l_req_extent;
	struct rb_node			l_rb;
	u64				l_subtree_last;

	/**
	 * Requested mode.
	 * Protected by lr_lock.
	 */
	enum ldlm_mode			l_req_mode;
	/**
	 * Granted mode, also protected by lr_lock.
	 */
	enum ldlm_mode			l_granted_mode;
	/** Lock completion handler pointer. Called when lock is granted. */
	ldlm_completion_callback	l_completion_ast;
	/**
	 * Lock blocking AST handler pointer.
	 * It plays two roles:
	 * - as a notification of an attempt to queue a conflicting lock (once)
	 * - as a notification when the lock is being cancelled.
	 *
	 * As such it's typically called twice: once for the initial conflict
	 * and then once more when the last user went away and the lock is
	 * cancelled (could happen recursively).
	 */
	ldlm_blocking_callback		l_blocking_ast;
	/**
	 * Lock glimpse handler.
	 * Glimpse handler is used to obtain LVB updates from a client by
	 * server
	 */
	ldlm_glimpse_callback		l_glimpse_ast;

	/**
	 * Lock export.
	 * This is a pointer to actual client export for locks that were granted
	 * to clients. Used server-side.
	 */
	struct obd_export		*l_export;
	/**
	 * Lock connection export.
	 * Pointer to server export on a client.
	 */
	struct obd_export		*l_conn_export;

	/**
	 * Remote lock handle.
	 * If the lock is remote, this is the handle of the other side lock
	 * (l_handle)
	 */
	struct lustre_handle		l_remote_handle;

	/**
	 * Representation of private data specific for a lock type.
	 * Examples are: extent range for extent lock or bitmask for ibits locks
	 */
	union ldlm_policy_data		l_policy_data;

	/**
	 * Lock state flags. Protected by lr_lock.
	 * \see lustre_dlm_flags.h where the bits are defined.
	 */
	u64				l_flags;

	/**
	 * Lock r/w usage counters.
	 * Protected by lr_lock.
	 */
	u32				l_readers;
	u32				l_writers;
	/**
	 * If the lock is granted, a process sleeps on this waitq to learn when
	 * it's no longer in use.  If the lock is not granted, a process sleeps
	 * on this waitq to learn when it becomes granted.
	 */
	wait_queue_head_t		l_waitq;

	/**
	 * Time, in nanoseconds, last used by e.g. being matched by lock match.
	 */
	ktime_t				l_last_used;

	/*
	 * Client-side-only members.
	 */

	enum lvb_type			l_lvb_type;

	/**
	 * Temporary storage for a LVB received during an enqueue operation.
	 */
	u32				l_lvb_len;
	void				*l_lvb_data;

	/** Private storage for lock user. Opaque to LDLM. */
	void				*l_ast_data;

	/**
	 * Seconds. It will be updated if there is any activity related to
	 * the lock at client, e.g. enqueue the lock.
	 */
	time64_t			l_activity;

	/* Separate ost_lvb used mostly by Data-on-MDT for now.
	 * It is introduced to don't mix with layout lock data.
	 */
	struct ost_lvb		 l_ost_lvb;
	/*
	 * Server-side-only members.
	 */

	/**
	 * Connection cookie for the client originating the operation.
	 * Used by Commit on Share (COS) code. Currently only used for
	 * inodebits locks on MDS.
	 */
	u64				l_client_cookie;

	/**
	 * List item for locks waiting for cancellation from clients.
	 * The lists this could be linked into are:
	 * waiting_locks_list (protected by waiting_locks_spinlock),
	 * then if the lock timed out, it is moved to
	 * expired_lock_list for further processing.
	 */
	struct list_head		l_pending_chain;

	/**
	 * Set when lock is sent a blocking AST. Time in seconds when timeout
	 * is reached and client holding this lock could be evicted.
	 * This timeout could be further extended by e.g. certain IO activity
	 * under this lock.
	 * \see ost_rw_prolong_locks
	 */
	time64_t			l_callback_timestamp;

	/** Local PID of process which created this lock. */
	u32				l_pid;

	/**
	 * Number of times blocking AST was sent for this lock.
	 * This is for debugging. Valid values are 0 and 1, if there is an
	 * attempt to send blocking AST more than once, an assertion would be
	 * hit. \see ldlm_work_bl_ast_lock
	 */
	int				l_bl_ast_run;
	/** List item ldlm_add_ast_work_item() for case of blocking ASTs. */
	struct list_head		l_bl_ast;
	/** List item ldlm_add_ast_work_item() for case of completion ASTs. */
	struct list_head		l_cp_ast;
	/** For ldlm_add_ast_work_item() for "revoke" AST used in COS. */
	struct list_head		l_rk_ast;

	/**
	 * Pointer to a conflicting lock that caused blocking AST to be sent
	 * for this lock
	 */
	struct ldlm_lock		*l_blocking_lock;

	/**
	 * Protected by lr_lock, linkages to "skip lists".
	 * For more explanations of skip lists see ldlm/ldlm_inodebits.c
	 */
	struct list_head		l_sl_mode;
	struct list_head		l_sl_policy;

	/** Reference tracking structure to debug leaked locks. */
	struct lu_ref			l_reference;
#if LUSTRE_TRACKS_LOCK_EXP_REFS
	/* Debugging stuff for bug 20498, for tracking export references. */
	/** number of export references taken */
	int				l_exp_refs_nr;
	/** link all locks referencing one export */
	struct list_head		l_exp_refs_link;
	/** referenced export object */
	struct obd_export		*l_exp_refs_target;
#endif
};

enum ldlm_match_flags {
	LDLM_MATCH_UNREF	= BIT(0),
	LDLM_MATCH_AST		= BIT(1),
	LDLM_MATCH_AST_ANY	= BIT(2),
	LDLM_MATCH_RIGHT	= BIT(3),
	LDLM_MATCH_GROUP	= BIT(4),
};

#define extent_last(tree) rb_entry_safe(rb_last(&tree->lit_root.rb_root),\
					struct ldlm_lock, l_rb)
#define extent_first(tree) rb_entry_safe(rb_first(&tree->lit_root.rb_root),\
					 struct ldlm_lock, l_rb)
#define extent_top(tree) rb_entry_safe(tree->lit_root.rb_root.rb_node, \
				       struct ldlm_lock, l_rb)
#define extent_prev(lock) rb_entry_safe(rb_prev(&lock->l_rb),		\
					struct ldlm_lock, l_rb)

/**
 * Describe the overlap between two locks.  itree_overlap_cb data.
 */
struct ldlm_match_data {
	struct ldlm_lock	*lmd_old;
	struct ldlm_lock	*lmd_lock;
	enum ldlm_mode		*lmd_mode;
	union ldlm_policy_data	*lmd_policy;
	u64			 lmd_flags;
	u64			 lmd_skip_flags;
	enum ldlm_match_flags	 lmd_match;
};

/**
 * LDLM resource description.
 * Basically, resource is a representation for a single object.
 * Object has a name which is currently 4 64-bit integers. LDLM user is
 * responsible for creation of a mapping between objects it wants to be
 * protected and resource names.
 *
 * A resource can only hold locks of a single lock type, though there may be
 * multiple ldlm_locks on a single resource, depending on the lock type and
 * whether the locks are conflicting or not.
 */
struct ldlm_resource {
	struct ldlm_ns_bucket		*lr_ns_bucket;

	/**
	 * List item for list in namespace hash.
	 * protected by ns_lock.
	 * Shared with linkage for RCU-delayed free.
	 */
	union {
		struct hlist_node		lr_hash;
		struct rcu_head			lr_rcu;
	};

	/** Reference count for this resource */
	atomic_t			lr_refcount;

	/** Spinlock to protect locks under this resource. */
	spinlock_t			lr_lock;

	/**
	 * protected by lr_lock
	 * @{
	 */
	/** List of locks in granted state */
	struct list_head		lr_granted;
	/**
	 * List of locks that could not be granted due to conflicts and
	 * that are waiting for conflicts to go away
	 */
	struct list_head		lr_waiting;
	/** @} */

	/** Resource name */
	struct ldlm_res_id		lr_name;

	/**
	 * Interval trees (only for extent locks) for all modes of this resource
	 */
	struct ldlm_interval_tree	*lr_itree;

	/** Type of locks this resource can hold. Only one type per resource.
	 *  LDLM_{PLAIN,EXTENT,FLOCK,IBITS}
	 */
	enum ldlm_type			lr_type;

	/**
	 * Server-side-only lock value block elements.
	 * To serialize lvbo_init.
	 */
	int				lr_lvb_len;
	struct mutex			lr_lvb_mutex;

	/**
	 * Associated inode, used only on client side.
	 */
	struct inode			*lr_lvb_inode;

	/** List of references to this resource. For debugging. */
	struct lu_ref			lr_reference;
};

static inline int ldlm_is_granted(struct ldlm_lock *lock)
{
	return lock->l_req_mode == lock->l_granted_mode;
}

static inline bool ldlm_has_layout(struct ldlm_lock *lock)
{
	return lock->l_resource->lr_type == LDLM_IBITS &&
		lock->l_policy_data.l_inodebits.bits & MDS_INODELOCK_LAYOUT;
}

static inline bool ldlm_has_dom(struct ldlm_lock *lock)
{
	return lock->l_resource->lr_type == LDLM_IBITS &&
	       lock->l_policy_data.l_inodebits.bits & MDS_INODELOCK_DOM;
}

static inline char *
ldlm_ns_name(struct ldlm_namespace *ns)
{
	return ns->ns_name;
}

static inline struct ldlm_namespace *
ldlm_res_to_ns(struct ldlm_resource *res)
{
	return res->lr_ns_bucket->nsb_namespace;
}

static inline struct ldlm_namespace *
ldlm_lock_to_ns(struct ldlm_lock *lock)
{
	return ldlm_res_to_ns(lock->l_resource);
}

static inline char *
ldlm_lock_to_ns_name(struct ldlm_lock *lock)
{
	return ldlm_ns_name(ldlm_lock_to_ns(lock));
}

static inline struct adaptive_timeout *
ldlm_lock_to_ns_at(struct ldlm_lock *lock)
{
	return &lock->l_resource->lr_ns_bucket->nsb_at_estimate;
}

struct ldlm_ast_work {
	struct ldlm_lock       *w_lock;
	int			w_blocking;
	struct ldlm_lock_desc	w_desc;
	struct list_head	w_list;
	int			w_flags;
	void		       *w_data;
	int			w_datalen;
};

/**
 * Common ldlm_enqueue parameters
 */
struct ldlm_enqueue_info {
	/* Type of the lock being enqueued. */
	enum ldlm_type		ei_type;
	/* Mode of the lock being enqueued. */
	enum ldlm_mode		ei_mode;
	/* blocking lock callback */
	void			*ei_cb_bl;
	/* lock completion callback */
	void			*ei_cb_cp;
	/* lock glimpse callback */
	void			*ei_cb_gl;
	/* Data to be passed into callbacks. */
	void			*ei_cbdata;
	/* whether enqueue slave stripes */
	unsigned int		ei_enq_slave:1;
	/* whether acquire rpc slot */
	unsigned int		ei_req_slot:1;
	/** whether acquire mod rpc slot */
	unsigned int		ei_mod_slot:1;
};

extern struct obd_ops ldlm_obd_ops;

extern char *ldlm_lockname[];
const char *ldlm_it2str(enum ldlm_intent_flags it);

/**
 * Just a fancy CDEBUG call with log level preset to LDLM_DEBUG.
 * For the cases where we do not have actual lock to print along
 * with a debugging message that is ldlm-related
 */
#define LDLM_DEBUG_NOLOCK(format, a...)			\
	CDEBUG(D_DLMTRACE, "### " format "\n", ##a)

/**
 * Support function for lock information printing into debug logs.
 * \see LDLM_DEBUG
 */
#define ldlm_lock_debug(msgdata, mask, cdls, lock, fmt, a...) do {      \
	CFS_CHECK_STACK(msgdata, mask, cdls);				\
									\
	if (((mask) & D_CANTMASK) != 0 ||				\
	    ((libcfs_debug & (mask)) != 0 &&				\
	     (libcfs_subsystem_debug & DEBUG_SUBSYSTEM) != 0))		\
		_ldlm_lock_debug(lock, msgdata, fmt, ##a);		\
} while (0)

void _ldlm_lock_debug(struct ldlm_lock *lock,
		      struct libcfs_debug_msg_data *data,
		      const char *fmt, ...)
	__printf(3, 4);

/**
 * Rate-limited version of lock printing function.
 */
#define LDLM_DEBUG_LIMIT(mask, lock, fmt, a...) do {			\
	static struct cfs_debug_limit_state _ldlm_cdls;			\
	LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, mask, &_ldlm_cdls);		\
	ldlm_lock_debug(&msgdata, mask, &_ldlm_cdls, lock, "### " fmt, ##a);\
} while (0)

#define LDLM_ERROR(lock, fmt, a...) LDLM_DEBUG_LIMIT(D_ERROR, lock, fmt, ## a)
#define LDLM_WARN(lock, fmt, a...)  LDLM_DEBUG_LIMIT(D_WARNING, lock, fmt, ## a)

/** Non-rate-limited lock printing function for debugging purposes. */
#define LDLM_DEBUG(lock, fmt, a...)   do {				\
	if (likely(lock)) {						\
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_DLMTRACE, NULL);	\
		ldlm_lock_debug(&msgdata, D_DLMTRACE, NULL, lock,	\
				"### " fmt, ##a);			\
	} else {							\
		LDLM_DEBUG_NOLOCK("no dlm lock: " fmt, ##a);		\
	}								\
} while (0)

typedef int (*ldlm_processing_policy)(struct ldlm_lock *lock, u64 *flags,
				      int first_enq, enum ldlm_error *err,
				      struct list_head *work_list);

/**
 * Return values for lock iterators.
 * Also used during deciding of lock grants and cancellations.
 */
#define LDLM_ITER_CONTINUE 1 /* keep iterating */
#define LDLM_ITER_STOP     2 /* stop iterating */

typedef int (*ldlm_iterator_t)(struct ldlm_lock *, void *);
typedef int (*ldlm_res_iterator_t)(struct ldlm_resource *, void *);

/** \defgroup ldlm_iterator Lock iterators
 *
 * LDLM provides for a way to iterate through every lock on a resource or
 * namespace or every resource in a namespace.
 * @{
 */
int ldlm_resource_iterate(struct ldlm_namespace *ns,
			  const struct ldlm_res_id *res_id,
			  ldlm_iterator_t iter, void *data);
/** @} ldlm_iterator */

int ldlm_replay_locks(struct obd_import *imp);

/* ldlm_flock.c */
int ldlm_flock_completion_ast(struct ldlm_lock *lock, u64 flags, void *data);

/* ldlm_extent.c */
u64 ldlm_extent_shift_kms(struct ldlm_lock *lock, u64 old_kms);

struct ldlm_callback_suite {
	ldlm_completion_callback	lcs_completion;
	ldlm_blocking_callback		lcs_blocking;
	ldlm_glimpse_callback		lcs_glimpse;
};

/* ldlm_lockd.c */
int ldlm_get_ref(void);
void ldlm_put_ref(void);
struct ldlm_lock *ldlm_request_lock(struct ptlrpc_request *req);

/* ldlm_lock.c */
void ldlm_lock2handle(const struct ldlm_lock *lock,
		      struct lustre_handle *lockh);
struct ldlm_lock *__ldlm_handle2lock(const struct lustre_handle *lh,
				     u64 flags);
void ldlm_cancel_callback(struct ldlm_lock *lock);
int ldlm_lock_remove_from_lru(struct ldlm_lock *lock);
int ldlm_lock_set_data(const struct lustre_handle *lockh, void *data);

/**
 * Obtain a lock reference by its handle.
 */
static inline struct ldlm_lock *ldlm_handle2lock(const struct lustre_handle *h)
{
	return __ldlm_handle2lock(h, 0);
}

#define LDLM_LOCK_REF_DEL(lock) \
	lu_ref_del(&lock->l_reference, "handle", lock)

static inline struct ldlm_lock *
ldlm_handle2lock_long(const struct lustre_handle *h, u64 flags)
{
	struct ldlm_lock *lock;

	lock = __ldlm_handle2lock(h, flags);
	if (lock)
		LDLM_LOCK_REF_DEL(lock);
	return lock;
}

int is_granted_or_cancelled_nolock(struct ldlm_lock *lock);

int ldlm_error2errno(enum ldlm_error error);

#if LUSTRE_TRACKS_LOCK_EXP_REFS
void ldlm_dump_export_locks(struct obd_export *exp);
#endif

/**
 * Release a temporary lock reference obtained by ldlm_handle2lock() or
 * __ldlm_handle2lock().
 */
#define LDLM_LOCK_PUT(lock)		\
do {					\
	LDLM_LOCK_REF_DEL(lock);	\
	/*LDLM_DEBUG((lock), "put");*/	\
	ldlm_lock_put(lock);		\
} while (0)

/**
 * Release a lock reference obtained by some other means (see
 * LDLM_LOCK_PUT()).
 */
#define LDLM_LOCK_RELEASE(lock)		\
do {					\
	/*LDLM_DEBUG((lock), "put");*/	\
	ldlm_lock_put(lock);		\
} while (0)

#define LDLM_LOCK_GET(lock)		\
({					\
	ldlm_lock_get(lock);		\
	/*LDLM_DEBUG((lock), "get");*/	\
	lock;				\
})

#define ldlm_lock_list_put(head, member, count)			\
({								\
	struct ldlm_lock *_lock, *_next;			\
	int c = count;						\
	list_for_each_entry_safe(_lock, _next, head, member) {	\
		if (c-- == 0)					\
			break;					\
		list_del_init(&_lock->member);			\
		LDLM_LOCK_RELEASE(_lock);			\
	}							\
	LASSERT(c <= 0);					\
})

struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock);
void ldlm_lock_put(struct ldlm_lock *lock);
void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc);
void ldlm_lock_addref(const struct lustre_handle *lockh, enum ldlm_mode mode);
int  ldlm_lock_addref_try(const struct lustre_handle *lockh,
			  enum ldlm_mode mode);
void ldlm_lock_decref(const struct lustre_handle *lockh, enum ldlm_mode mode);
void ldlm_lock_decref_and_cancel(const struct lustre_handle *lockh,
				 enum ldlm_mode mode);
void ldlm_lock_fail_match_locked(struct ldlm_lock *lock);
void ldlm_lock_allow_match(struct ldlm_lock *lock);
void ldlm_lock_allow_match_locked(struct ldlm_lock *lock);

enum ldlm_mode ldlm_lock_match_with_skip(struct ldlm_namespace *ns,
					 u64 flags, u64 skip_flags,
					 const struct ldlm_res_id *res_id,
					 enum ldlm_type type,
					 union ldlm_policy_data *policy,
					 enum ldlm_mode mode,
					 struct lustre_handle *lh,
					 enum ldlm_match_flags match_flags);
static inline enum ldlm_mode ldlm_lock_match(struct ldlm_namespace *ns,
					     u64 flags,
					     const struct ldlm_res_id *res_id,
					     enum ldlm_type type,
					     union ldlm_policy_data *policy,
					     enum ldlm_mode mode,
					     struct lustre_handle *lh)
{
	return ldlm_lock_match_with_skip(ns, flags, 0, res_id, type, policy,
					 mode, lh, 0);
}
struct ldlm_lock *search_itree(struct ldlm_resource *res,
			       struct ldlm_match_data *data);
enum ldlm_mode ldlm_revalidate_lock_handle(const struct lustre_handle *lockh,
					   u64 *bits);
void ldlm_lock_cancel(struct ldlm_lock *lock);
void ldlm_lock_dump_handle(int level, const struct lustre_handle *);
void ldlm_unlink_lock_skiplist(struct ldlm_lock *req);

/* resource.c */
struct ldlm_namespace *
ldlm_namespace_new(struct obd_device *obd, char *name,
		   enum ldlm_side client, enum ldlm_appetite apt,
		   enum ldlm_ns_type ns_type);
int ldlm_namespace_cleanup(struct ldlm_namespace *ns, u64 flags);
void ldlm_namespace_free_prior(struct ldlm_namespace *ns,
			       struct obd_import *imp,
			       int force);
void ldlm_namespace_free_post(struct ldlm_namespace *ns);
void ldlm_namespace_get(struct ldlm_namespace *ns);
void ldlm_namespace_put(struct ldlm_namespace *ns);
void ldlm_debugfs_setup(void);
void ldlm_debugfs_cleanup(void);

static inline void ldlm_svc_get_eopc(const struct ldlm_request *dlm_req,
				      struct lprocfs_stats *srv_stats)
{
	int lock_type = 0, op = 0;

	lock_type = dlm_req->lock_desc.l_resource.lr_type;

	switch (lock_type) {
	case LDLM_PLAIN:
		op = PTLRPC_LAST_CNTR + LDLM_PLAIN_ENQUEUE;
		break;
	case LDLM_EXTENT:
		op = PTLRPC_LAST_CNTR + LDLM_EXTENT_ENQUEUE;
		break;
	case LDLM_FLOCK:
		op = PTLRPC_LAST_CNTR + LDLM_FLOCK_ENQUEUE;
		break;
	case LDLM_IBITS:
		op = PTLRPC_LAST_CNTR + LDLM_IBITS_ENQUEUE;
		break;
	default:
		op = 0;
		break;
	}

	if (op != 0)
		lprocfs_counter_incr(srv_stats, op);
}

/* resource.c - internal */
struct ldlm_resource *ldlm_resource_get(struct ldlm_namespace *ns,
					const struct ldlm_res_id *,
					enum ldlm_type type, int create);
struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res);
void ldlm_resource_putref(struct ldlm_resource *res);
void ldlm_resource_add_lock(struct ldlm_resource *res,
			    struct list_head *head,
			    struct ldlm_lock *lock);
void ldlm_resource_unlink_lock(struct ldlm_lock *lock);
void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc);
void ldlm_dump_all_namespaces(enum ldlm_side client, int level);
void ldlm_namespace_dump(int level, struct ldlm_namespace *);
void ldlm_resource_dump(int level, struct ldlm_resource *);
int ldlm_lock_change_resource(struct ldlm_namespace *, struct ldlm_lock *,
			      const struct ldlm_res_id *);

#define LDLM_RESOURCE_ADDREF(res) do {					\
	lu_ref_add_atomic(&(res)->lr_reference, __func__, current);	\
} while (0)

#define LDLM_RESOURCE_DELREF(res) do {				\
	lu_ref_del(&(res)->lr_reference, __func__, current);	\
} while (0)

/* ldlm_request.c */
/** \defgroup ldlm_local_ast Default AST handlers for local locks
 * These AST handlers are typically used for server-side local locks and are
 * also used by client-side lock handlers to perform minimum level base
 * processing.
 * @{
 */
int ldlm_completion_ast(struct ldlm_lock *lock, u64 flags, void *data);
/** @} ldlm_local_ast */

/** \defgroup ldlm_cli_api API to operate on locks from actual LDLM users.
 * These are typically used by client and server (*_local versions)
 * to obtain and release locks.
 * @{
 */
int ldlm_cli_enqueue(struct obd_export *exp, struct ptlrpc_request **reqp,
		     struct ldlm_enqueue_info *einfo,
		     const struct ldlm_res_id *res_id,
		     union ldlm_policy_data const *policy, u64 *flags,
		     void *lvb, u32 lvb_len, enum lvb_type lvb_type,
		     struct lustre_handle *lockh, int async);
int ldlm_prep_enqueue_req(struct obd_export *exp,
			  struct ptlrpc_request *req,
			  struct list_head *cancels,
			  int count);
int ldlm_prep_elc_req(struct obd_export *exp,
		      struct ptlrpc_request *req,
		      int version, int opc, int canceloff,
		      struct list_head *cancels, int count);

struct ptlrpc_request *ldlm_enqueue_pack(struct obd_export *exp, int lvb_len);
int ldlm_cli_enqueue_fini(struct obd_export *exp, struct req_capsule *pill,
			  struct ldlm_enqueue_info *einfo, u8 with_policy,
			  u64 *flags, void *lvb, u32 lvb_len,
			  const struct lustre_handle *lockh, int rc,
			  bool request_slot);
int ldlm_cli_lock_create_pack(struct obd_export *exp,
			      struct ldlm_request *dlmreq,
			      struct ldlm_enqueue_info *einfo,
			      const struct ldlm_res_id *res_id,
			      union ldlm_policy_data const *policy,
			      u64 *flags, void *lvb, u32 lvb_len,
			      enum lvb_type lvb_type,
			      struct lustre_handle *lockh);
int ldlm_cli_convert_req(struct ldlm_lock *lock, u32 *flags, u64 new_bits);
int ldlm_cli_convert(struct ldlm_lock *lock,
		     enum ldlm_cancel_flags cancel_flags);
int ldlm_cli_update_pool(struct ptlrpc_request *req);
int ldlm_cli_cancel(const struct lustre_handle *lockh,
		    enum ldlm_cancel_flags cancel_flags);
int ldlm_cli_cancel_unused(struct ldlm_namespace *, const struct ldlm_res_id *,
			   enum ldlm_cancel_flags flags, void *opaque);
int ldlm_cli_cancel_unused_resource(struct ldlm_namespace *ns,
				    const struct ldlm_res_id *res_id,
				    union ldlm_policy_data *policy,
				    enum ldlm_mode mode,
				    enum ldlm_cancel_flags flags,
				    void *opaque);
int ldlm_cancel_resource_local(struct ldlm_resource *res,
			       struct list_head *cancels,
			       union ldlm_policy_data *policy,
			       enum ldlm_mode mode, u64 lock_flags,
			       enum ldlm_cancel_flags cancel_flags,
			       void *opaque);
int ldlm_cli_cancel_list_local(struct list_head *cancels, int count,
			       enum ldlm_cancel_flags flags);
int ldlm_cli_cancel_list(struct list_head *head, int count,
			 struct ptlrpc_request *req,
			 enum ldlm_cancel_flags flags);
/** @} ldlm_cli_api */

extern unsigned int ldlm_enqueue_min;

int ldlm_inodebits_drop(struct ldlm_lock *lock, u64 to_drop);
int ldlm_cli_inodebits_convert(struct ldlm_lock *lock,
			       enum ldlm_cancel_flags cancel_flags);

/* mds/handler.c */
/* This has to be here because recursive inclusion sucks. */
int intent_disposition(struct ldlm_reply *rep, int flag);
void intent_set_disposition(struct ldlm_reply *rep, int flag);

/**
 * "Modes" of acquiring lock_res, necessary to tell lockdep that taking more
 * than one lock_res is dead-lock safe.
 */
enum lock_res_type {
	LRT_NORMAL,
	LRT_NEW
};

/** Lock resource. */
static inline void lock_res(struct ldlm_resource *res)
{
	spin_lock(&res->lr_lock);
}

/** Lock resource with a way to instruct lockdep code about nestedness-safe. */
static inline void lock_res_nested(struct ldlm_resource *res,
				   enum lock_res_type mode)
{
	spin_lock_nested(&res->lr_lock, mode);
}

/** Unlock resource. */
static inline void unlock_res(struct ldlm_resource *res)
{
	spin_unlock(&res->lr_lock);
}

/** Check if resource is already locked, assert if not. */
static inline void check_res_locked(struct ldlm_resource *res)
{
	assert_spin_locked(&res->lr_lock);
}

struct ldlm_resource *lock_res_and_lock(struct ldlm_lock *lock);
void unlock_res_and_lock(struct ldlm_lock *lock);

/* ldlm_pool.c */
/** \defgroup ldlm_pools Various LDLM pool related functions
 * There are not used outside of ldlm.
 * @{
 */
int ldlm_pools_init(void);
void ldlm_pools_fini(void);

int ldlm_pool_init(struct ldlm_pool *pl, struct ldlm_namespace *ns,
		   int idx, enum ldlm_side client);
void ldlm_pool_fini(struct ldlm_pool *pl);
timeout_t ldlm_pool_recalc(struct ldlm_pool *pl, bool force);
void ldlm_pool_add(struct ldlm_pool *pl, struct ldlm_lock *lock);
void ldlm_pool_del(struct ldlm_pool *pl, struct ldlm_lock *lock);
/** @} */

static inline int ldlm_extent_overlap(const struct ldlm_extent *ex1,
				      const struct ldlm_extent *ex2)
{
	return ex1->start <= ex2->end && ex2->start <= ex1->end;
}

/* check if @ex1 contains @ex2 */
static inline int ldlm_extent_contain(const struct ldlm_extent *ex1,
				      const struct ldlm_extent *ex2)
{
	return ex1->start <= ex2->start && ex1->end >= ex2->end;
}

int ldlm_inodebits_drop(struct ldlm_lock *lock, u64 to_drop);

#endif
/** @} LDLM */

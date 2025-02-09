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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ldlm/ldlm_lockd.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/kthread.h>
#include <linux/sched/mm.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include <linux/list.h>
#include "ldlm_internal.h"

static int ldlm_num_threads;
module_param(ldlm_num_threads, int, 0444);
MODULE_PARM_DESC(ldlm_num_threads, "number of DLM service threads to start");

static unsigned int ldlm_cpu_bind = 1;
module_param(ldlm_cpu_bind, uint, 0444);
MODULE_PARM_DESC(ldlm_cpu_bind,
		 "bind DLM service threads to particular CPU partitions");

static char *ldlm_cpts;
module_param(ldlm_cpts, charp, 0444);
MODULE_PARM_DESC(ldlm_cpts, "CPU partitions ldlm threads should run on");

static DEFINE_MUTEX(ldlm_ref_mutex);
static int ldlm_refcount;

static struct kobject *ldlm_kobj;
struct kset *ldlm_ns_kset;
static struct kset *ldlm_svc_kset;

struct ldlm_cb_async_args {
	struct ldlm_cb_set_arg *ca_set_arg;
	struct ldlm_lock       *ca_lock;
};

/* LDLM state */

static struct ldlm_state *ldlm_state;
struct ldlm_bl_pool {
	spinlock_t		blp_lock;

	/*
	 * blp_prio_list is used for callbacks that should be handled
	 * as a priority. It is used for LDLM_FL_DISCARD_DATA requests.
	 * see b=13843
	 */
	struct list_head	blp_prio_list;

	/*
	 * blp_list is used for all other callbacks which are likely
	 * to take longer to process.
	 */
	struct list_head	blp_list;

	wait_queue_head_t	blp_waitq;
	struct completion	blp_comp;
	atomic_t		blp_num_threads;
	atomic_t		blp_busy_threads;
	int			blp_min_threads;
	int			blp_max_threads;
	int			blp_total_locks;
	int			blp_total_blwis;
};

struct ldlm_bl_work_item {
	struct list_head	blwi_entry;
	struct ldlm_namespace  *blwi_ns;
	struct ldlm_lock_desc   blwi_ld;
	struct ldlm_lock       *blwi_lock;
	struct list_head	blwi_head;
	int			blwi_count;
	struct completion	blwi_comp;
	enum ldlm_cancel_flags	blwi_flags;
	int			blwi_mem_pressure;
};

/**
 * Server may pass additional information about blocking lock.
 * For IBITS locks it is conflicting bits which can be used for
 * lock convert instead of cancel.
 */
void ldlm_bl_desc2lock(const struct ldlm_lock_desc *ld, struct ldlm_lock *lock)
{
	check_res_locked(lock->l_resource);
	if (ld &&
	    (lock->l_resource->lr_type == LDLM_IBITS)) {
		/*
		 * Lock description contains policy of blocking lock, and its
		 * cancel_bits is used to pass conflicting bits.  NOTE: ld can
		 * be NULL or can be not NULL but zeroed if passed from
		 * ldlm_bl_thread_blwi(), check below used bits in ld to make
		 * sure it is valid description.
		 *
		 * If server may replace lock resource keeping the same
		 * cookie, never use cancel bits from different resource, full
		 * cancel is to be used.
		 */
		if (ld->l_policy_data.l_inodebits.cancel_bits &&
		    ldlm_res_eq(&ld->l_resource.lr_name,
				&lock->l_resource->lr_name) &&
		    !(ldlm_is_cbpending(lock) &&
		      lock->l_policy_data.l_inodebits.cancel_bits == 0)) {
			/* always combine conflicting ibits */
			lock->l_policy_data.l_inodebits.cancel_bits |=
				ld->l_policy_data.l_inodebits.cancel_bits;
		} else {
			/* If cancel_bits are not obtained or
			 * if the lock is already CBPENDING and
			 * has no cancel_bits set
			 * - the full lock is to be cancelled
			 */
			lock->l_policy_data.l_inodebits.cancel_bits = 0;
		}
	}
}

/**
 * Callback handler for receiving incoming blocking ASTs.
 *
 * This can only happen on client side.
 */
void ldlm_handle_bl_callback(struct ldlm_namespace *ns,
			     struct ldlm_lock_desc *ld, struct ldlm_lock *lock)
{
	int do_ast;

	LDLM_DEBUG(lock, "client blocking AST callback handler");

	lock_res_and_lock(lock);

	/* get extra information from desc if any */
	ldlm_bl_desc2lock(ld, lock);
	ldlm_set_cbpending(lock);

	do_ast = !lock->l_readers && !lock->l_writers;
	unlock_res_and_lock(lock);

	if (do_ast) {
		CDEBUG(D_DLMTRACE,
		       "Lock %p already unused, calling callback (%p)\n", lock,
		       lock->l_blocking_ast);
		if (lock->l_blocking_ast)
			lock->l_blocking_ast(lock, ld, lock->l_ast_data,
					     LDLM_CB_BLOCKING);
	} else {
		CDEBUG(D_DLMTRACE,
		       "Lock %p is referenced, will be cancelled later\n",
		       lock);
	}

	LDLM_DEBUG(lock, "client blocking callback handler END");
	LDLM_LOCK_RELEASE(lock);
}

static int ldlm_callback_reply(struct ptlrpc_request *req, int rc)
{
	if (req->rq_no_reply)
		return 0;

	req->rq_status = rc;
	if (!req->rq_packed_final) {
		rc = lustre_pack_reply(req, 1, NULL, NULL);
		if (rc)
			return rc;
	}
	return ptlrpc_reply(req);
}

/*
 * Callback handler for receiving incoming completion ASTs.
 *
 * This only can happen on client side.
 */
static int ldlm_handle_cp_callback(struct ptlrpc_request *req,
				   struct ldlm_namespace *ns,
				   struct ldlm_request *dlm_req,
				   struct ldlm_lock *lock)
{
	int lvb_len;
	LIST_HEAD(ast_list);
	int rc = 0;

	LDLM_DEBUG(lock, "client completion callback handler START");

	if (CFS_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_BL_CB_RACE)) {
		long to = HZ;

		ldlm_callback_reply(req, 0);

		while (to > 0) {
			to = schedule_timeout_interruptible(to);
			if (ldlm_is_granted(lock) ||
			    ldlm_is_destroyed(lock))
				break;
		}
	}

	lvb_len = req_capsule_get_size(&req->rq_pill, &RMF_DLM_LVB, RCL_CLIENT);
	if (lvb_len < 0) {
		LDLM_ERROR(lock, "Fail to get lvb_len, rc = %d", lvb_len);
		rc = lvb_len;
		goto out;
	} else if (lvb_len > 0) {
		if (lock->l_lvb_len > 0) {
			/* for extent lock, lvb contains ost_lvb{}. */
			LASSERT(lock->l_lvb_data);

			if (unlikely(lock->l_lvb_len < lvb_len)) {
				LDLM_ERROR(lock,
					   "Replied LVB is larger than expectation, expected = %d, replied = %d",
					   lock->l_lvb_len, lvb_len);
				rc = -EINVAL;
				goto out;
			}
		}
	}

	lock_res_and_lock(lock);

	if (!ldlm_res_eq(&dlm_req->lock_desc.l_resource.lr_name,
			 &lock->l_resource->lr_name)) {
		ldlm_resource_unlink_lock(lock);
		unlock_res_and_lock(lock);
		rc = ldlm_lock_change_resource(ns, lock,
				&dlm_req->lock_desc.l_resource.lr_name);
		if (rc < 0) {
			LDLM_ERROR(lock, "Failed to allocate resource");
			goto out;
		}
		LDLM_DEBUG(lock, "completion AST, new resource");
		lock_res_and_lock(lock);
	}

	if (ldlm_is_failed(lock)) {
		unlock_res_and_lock(lock);
		LDLM_LOCK_RELEASE(lock);
		return -EINVAL;
	}

	if (ldlm_is_destroyed(lock) ||
	    ldlm_is_granted(lock)) {
		/* bug 11300: the lock has already been granted */
		unlock_res_and_lock(lock);
		LDLM_DEBUG(lock, "Double grant race happened");
		rc = 0;
		goto out;
	}

	/*
	 * If we receive the completion AST before the actual enqueue
	 * returned, then we might need to switch lock modes, resources, or
	 * extents.
	 */
	if (dlm_req->lock_desc.l_granted_mode != lock->l_req_mode) {
		lock->l_req_mode = dlm_req->lock_desc.l_granted_mode;
		LDLM_DEBUG(lock, "completion AST, new lock mode");
	}

	if (lock->l_resource->lr_type != LDLM_PLAIN) {
		ldlm_convert_policy_to_local(req->rq_export,
					     dlm_req->lock_desc.l_resource.lr_type,
					     &dlm_req->lock_desc.l_policy_data,
					     &lock->l_policy_data);
		LDLM_DEBUG(lock, "completion AST, new policy data");
	}

	ldlm_resource_unlink_lock(lock);

	if (dlm_req->lock_flags & LDLM_FL_AST_SENT) {
		/*
		 * BL_AST locks are not needed in LRU.
		 * Let ldlm_cancel_lru() be fast.
		 */
		ldlm_lock_remove_from_lru(lock);
		ldlm_bl_desc2lock(&dlm_req->lock_desc, lock);
		lock->l_flags |= LDLM_FL_CBPENDING | LDLM_FL_BL_AST;
		LDLM_DEBUG(lock, "completion AST includes blocking AST");
	}

	if (lock->l_lvb_len > 0) {
		rc = ldlm_fill_lvb(lock, &req->rq_pill, RCL_CLIENT,
				   lock->l_lvb_data, lvb_len);
		if (rc < 0) {
			unlock_res_and_lock(lock);
			goto out;
		}
	}

	ldlm_grant_lock(lock, &ast_list);
	unlock_res_and_lock(lock);

	LDLM_DEBUG(lock, "callback handler finished, about to run_ast_work");

	/* Let Enqueue to call osc_lock_upcall() and initialize l_ast_data */
	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_CP_ENQ_RACE, 2);

	ldlm_run_ast_work(ns, &ast_list, LDLM_WORK_CP_AST);

	LDLM_DEBUG_NOLOCK("client completion callback handler END (lock %p)",
			  lock);
	goto out;

out:
	if (rc < 0) {
		lock_res_and_lock(lock);
		ldlm_set_failed(lock);
		unlock_res_and_lock(lock);
		wake_up(&lock->l_waitq);
	}
	LDLM_LOCK_RELEASE(lock);

	return 0;
}

/**
 * Callback handler for receiving incoming glimpse ASTs.
 *
 * This only can happen on client side.  After handling the glimpse AST
 * we also consider dropping the lock here if it is unused locally for a
 * long time.
 */
static void ldlm_handle_gl_callback(struct ptlrpc_request *req,
				    struct ldlm_namespace *ns,
				    struct ldlm_request *dlm_req,
				    struct ldlm_lock *lock)
{
	struct ldlm_lock_desc *ld = &dlm_req->lock_desc;
	int rc = -ENXIO;

	LDLM_DEBUG(lock, "client glimpse AST callback handler");

	if (lock->l_glimpse_ast)
		rc = lock->l_glimpse_ast(lock, req);

	if (req->rq_repmsg) {
		ptlrpc_reply(req);
	} else {
		req->rq_status = rc;
		ptlrpc_error(req);
	}

	lock_res_and_lock(lock);
	if (lock->l_granted_mode == LCK_PW &&
	    !lock->l_readers && !lock->l_writers &&
	    ktime_after(ktime_get(),
			ktime_add(lock->l_last_used, ns->ns_dirty_age_limit))) {
		unlock_res_and_lock(lock);

		/* For MDS glimpse it is always DOM lock, set corresponding
		 * cancel_bits to perform lock convert if needed
		 */
		if (lock->l_resource->lr_type == LDLM_IBITS)
			ld->l_policy_data.l_inodebits.cancel_bits =
							MDS_INODELOCK_DOM;
		if (ldlm_bl_to_thread_lock(ns, ld, lock))
			ldlm_handle_bl_callback(ns, ld, lock);

		return;
	}
	unlock_res_and_lock(lock);
	LDLM_LOCK_RELEASE(lock);
}

static int __ldlm_bl_to_thread(struct ldlm_bl_work_item *blwi,
			       enum ldlm_cancel_flags cancel_flags)
{
	struct ldlm_bl_pool *blp = ldlm_state->ldlm_bl_pool;
	char *prio = "regular";
	int count;

	spin_lock(&blp->blp_lock);
	/* cannot access blwi after added to list and lock is dropped */
	count = blwi->blwi_lock ? 1 : blwi->blwi_count;

	/* if the server is waiting on a lock to be cancelled (bl_ast), this is
	 * an urgent request and should go in the priority queue so it doesn't
	 * get stuck behind non-priority work (eg, lru size management)
	 *
	 * We also prioritize discard_data, which is for eviction handling
	 */
	if (blwi->blwi_lock &&
	    (ldlm_is_discard_data(blwi->blwi_lock) ||
	     ldlm_is_bl_ast(blwi->blwi_lock))) {
		list_add_tail(&blwi->blwi_entry, &blp->blp_prio_list);
		prio = "priority";
	} else {
		/* other blocking callbacks are added to the regular list */
		list_add_tail(&blwi->blwi_entry, &blp->blp_list);
	}
	blp->blp_total_locks += count;
	blp->blp_total_blwis++;
	spin_unlock(&blp->blp_lock);

	wake_up(&blp->blp_waitq);

	/* unlocked read of blp values is intentional - OK for debug */
	CDEBUG(D_DLMTRACE,
	       "added %d/%d locks to %s blp list, %d blwis in pool\n",
	       count, blp->blp_total_locks, prio, blp->blp_total_blwis);

	/*
	 * Can not check blwi->blwi_flags as blwi could be already freed in
	 * LCF_ASYNC mode
	 */
	if (!(cancel_flags & LCF_ASYNC))
		wait_for_completion(&blwi->blwi_comp);

	return 0;
}

static inline void init_blwi(struct ldlm_bl_work_item *blwi,
			     struct ldlm_namespace *ns,
			     struct ldlm_lock_desc *ld,
			     struct list_head *cancels, int count,
			     struct ldlm_lock *lock,
			     enum ldlm_cancel_flags cancel_flags)
{
	init_completion(&blwi->blwi_comp);
	INIT_LIST_HEAD(&blwi->blwi_head);

	if (current->flags & PF_MEMALLOC)
		blwi->blwi_mem_pressure = 1;

	blwi->blwi_ns = ns;
	blwi->blwi_flags = cancel_flags;
	if (ld)
		blwi->blwi_ld = *ld;
	if (count) {
		list_splice_init(cancels, &blwi->blwi_head);
		blwi->blwi_count = count;
	} else {
		blwi->blwi_lock = lock;
	}
}

/**
 * Queues a list of locks @cancels containing @count locks
 * for later processing by a blocking thread. If @count is zero,
 * then the lock referenced as @lock is queued instead.
 *
 * The blocking thread would then call ->l_blocking_ast callback in the lock.
 * If list addition fails an error is returned and caller is supposed to
 * call ->l_blocking_ast itself.
 */
static int ldlm_bl_to_thread(struct ldlm_namespace *ns,
			     struct ldlm_lock_desc *ld,
			     struct ldlm_lock *lock,
			     struct list_head *cancels, int count,
			     enum ldlm_cancel_flags cancel_flags)
{
	int rc = 0;

	if (cancels && count == 0)
		return rc;

	if (cancel_flags & LCF_ASYNC) {
		struct ldlm_bl_work_item *blwi;

		blwi = kzalloc(sizeof(*blwi), GFP_NOFS);
		if (!blwi)
			return -ENOMEM;
		init_blwi(blwi, ns, ld, cancels, count, lock, cancel_flags);

		rc = __ldlm_bl_to_thread(blwi, cancel_flags);
	} else {
		/*
		 * If it is synchronous call do minimum mem alloc, as it could
		 * be triggered from kernel shrinker
		 */
		struct ldlm_bl_work_item blwi;

		memset(&blwi, 0, sizeof(blwi));
		init_blwi(&blwi, ns, ld, cancels, count, lock, cancel_flags);
		rc = __ldlm_bl_to_thread(&blwi, cancel_flags);
	}
	return rc;
}

int ldlm_bl_to_thread_lock(struct ldlm_namespace *ns, struct ldlm_lock_desc *ld,
			   struct ldlm_lock *lock)
{
	return ldlm_bl_to_thread(ns, ld, lock, NULL, 0, LCF_ASYNC);
}

int ldlm_bl_to_thread_list(struct ldlm_namespace *ns, struct ldlm_lock_desc *ld,
			   struct list_head *cancels, int count,
			   enum ldlm_cancel_flags cancel_flags)
{
	return ldlm_bl_to_thread(ns, ld, NULL, cancels, count, cancel_flags);
}

int ldlm_bl_to_thread_ns(struct ldlm_namespace *ns)
{
	return ldlm_bl_to_thread(ns, NULL, NULL, NULL, 0, LCF_ASYNC);
}

int ldlm_bl_thread_wakeup(void)
{
	wake_up(&ldlm_state->ldlm_bl_pool->blp_waitq);
	return 0;
}

/* Setinfo coming from Server (eg MDT) to Client (eg MDC)! */
static int ldlm_handle_setinfo(struct ptlrpc_request *req)
{
	struct obd_device *obd = req->rq_export->exp_obd;
	char *key;
	void *val;
	int keylen, vallen;
	int rc = -ENXIO;

	DEBUG_REQ(D_HSM, req, "%s: handle setinfo\n", obd->obd_name);

	req_capsule_set(&req->rq_pill, &RQF_OBD_SET_INFO);

	key = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
	if (!key) {
		DEBUG_REQ(D_IOCTL, req, "no set_info key");
		return -EFAULT;
	}
	keylen = req_capsule_get_size(&req->rq_pill, &RMF_SETINFO_KEY,
				      RCL_CLIENT);
	val = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_VAL);
	if (!val) {
		DEBUG_REQ(D_IOCTL, req, "no set_info val");
		return -EFAULT;
	}
	vallen = req_capsule_get_size(&req->rq_pill, &RMF_SETINFO_VAL,
				      RCL_CLIENT);

	/* We are responsible for swabbing contents of val */

	if (KEY_IS(KEY_HSM_COPYTOOL_SEND))
		/* Pass it on to mdc (the "export" in this case) */
		rc = obd_set_info_async(req->rq_svc_thread->t_env,
					req->rq_export,
					sizeof(KEY_HSM_COPYTOOL_SEND),
					KEY_HSM_COPYTOOL_SEND,
					vallen, val, NULL);
	else
		DEBUG_REQ(D_WARNING, req, "ignoring unknown key %s", key);

	return rc;
}

static inline void ldlm_callback_errmsg(struct ptlrpc_request *req,
					const char *msg, int rc,
					const struct lustre_handle *handle)
{
	DEBUG_REQ((req->rq_no_reply || rc) ? D_WARNING : D_DLMTRACE, req,
		  "%s: NID=%s lock=%#llx: rc = %d",
		  msg, libcfs_idstr(&req->rq_peer),
		  handle ? handle->cookie : 0, rc);
	if (req->rq_no_reply)
		CWARN("No reply was sent, maybe cause bug 21636.\n");
	else if (rc)
		CWARN("Send reply failed, maybe cause bug 21636.\n");
}

/* TODO: handle requests in a similar way as MDT: see mdt_handle_common() */
static int ldlm_callback_handler(struct ptlrpc_request *req)
{
	struct ldlm_namespace *ns;
	struct ldlm_request *dlm_req;
	struct ldlm_lock *lock;
	int rc;

	/*
	 * Requests arrive in sender's byte order.  The ptlrpc service
	 * handler has already checked and, if necessary, byte-swapped the
	 * incoming request message body, but I am responsible for the
	 * message buffers.
	 */

	/* do nothing for sec context finalize */
	if (lustre_msg_get_opc(req->rq_reqmsg) == SEC_CTX_FINI)
		return 0;

	req_capsule_init(&req->rq_pill, req, RCL_SERVER);

	if (!req->rq_export) {
		rc = ldlm_callback_reply(req, -ENOTCONN);
		ldlm_callback_errmsg(req, "Operate on unconnected server",
				     rc, NULL);
		return 0;
	}

	LASSERT(req->rq_export->exp_obd);

	switch (lustre_msg_get_opc(req->rq_reqmsg)) {
	case LDLM_BL_CALLBACK:
		if (CFS_FAIL_CHECK(OBD_FAIL_LDLM_BL_CALLBACK_NET)) {
			if (cfs_fail_err)
				ldlm_callback_reply(req, -(int)cfs_fail_err);
			return 0;
		}
		break;
	case LDLM_CP_CALLBACK:
		if (CFS_FAIL_CHECK(OBD_FAIL_LDLM_CP_CALLBACK_NET))
			return 0;
		break;
	case LDLM_GL_CALLBACK:
		if (CFS_FAIL_CHECK(OBD_FAIL_LDLM_GL_CALLBACK_NET))
			return 0;
		break;
	case LDLM_SET_INFO:
		rc = ldlm_handle_setinfo(req);
		ldlm_callback_reply(req, rc);
		return 0;
	default:
		CERROR("unknown opcode %u\n",
		       lustre_msg_get_opc(req->rq_reqmsg));
		ldlm_callback_reply(req, -EPROTO);
		return 0;
	}

	ns = req->rq_export->exp_obd->obd_namespace;
	LASSERT(ns);

	req_capsule_set(&req->rq_pill, &RQF_LDLM_CALLBACK);

	dlm_req = req_capsule_client_get(&req->rq_pill, &RMF_DLM_REQ);
	if (!dlm_req) {
		rc = ldlm_callback_reply(req, -EPROTO);
		ldlm_callback_errmsg(req, "Operate without parameter", rc,
				     NULL);
		return 0;
	}

	/*
	 * Force a known safe race, send a cancel to the server for a lock
	 * which the server has already started a blocking callback on.
	 */
	if (CFS_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_BL_CB_RACE) &&
	    lustre_msg_get_opc(req->rq_reqmsg) == LDLM_BL_CALLBACK) {
		rc = ldlm_cli_cancel(&dlm_req->lock_handle[0], 0);
		if (rc < 0)
			CERROR("ldlm_cli_cancel: %d\n", rc);
	}

	lock = ldlm_handle2lock_long(&dlm_req->lock_handle[0], 0);
	if (!lock) {
		CDEBUG(D_DLMTRACE,
		       "callback on lock %#llx - lock disappeared\n",
		       dlm_req->lock_handle[0].cookie);
		rc = ldlm_callback_reply(req, -EINVAL);
		ldlm_callback_errmsg(req, "Operate with invalid parameter", rc,
				     &dlm_req->lock_handle[0]);
		return 0;
	}

	if (ldlm_is_fail_loc(lock) &&
	    lustre_msg_get_opc(req->rq_reqmsg) == LDLM_BL_CALLBACK)
		CFS_RACE(OBD_FAIL_LDLM_CP_BL_RACE);

	/* Copy hints/flags (e.g. LDLM_FL_DISCARD_DATA) from AST. */
	lock_res_and_lock(lock);
	lock->l_flags |= ldlm_flags_from_wire(dlm_req->lock_flags &
					      LDLM_FL_AST_MASK);
	if (lustre_msg_get_opc(req->rq_reqmsg) == LDLM_BL_CALLBACK) {
		/*
		 * If somebody cancels lock and cache is already dropped,
		 * or lock is failed before cp_ast received on client,
		 * we can tell the server we have no lock. Otherwise, we
		 * should send cancel after dropping the cache.
		 */
		if ((ldlm_is_canceling(lock) && ldlm_is_bl_done(lock)) ||
		     ldlm_is_failed(lock)) {
			LDLM_DEBUG(lock,
				   "callback on lock %#llx - lock disappeared",
				   dlm_req->lock_handle[0].cookie);
			unlock_res_and_lock(lock);
			LDLM_LOCK_RELEASE(lock);
			rc = ldlm_callback_reply(req, -EINVAL);
			ldlm_callback_errmsg(req, "Operate on stale lock", rc,
					     &dlm_req->lock_handle[0]);
			return 0;
		}
		/*
		 * BL_AST locks are not needed in LRU.
		 * Let ldlm_cancel_lru() be fast.
		 */
		ldlm_lock_remove_from_lru(lock);
		ldlm_set_bl_ast(lock);
	}
	if (lock->l_remote_handle.cookie == 0)
		lock->l_remote_handle = dlm_req->lock_handle[1];
	unlock_res_and_lock(lock);

	/*
	 * We want the ost thread to get this reply so that it can respond
	 * to ost requests (write cache writeback) that might be triggered
	 * in the callback.
	 *
	 * But we'd also like to be able to indicate in the reply that we're
	 * cancelling right now, because it's unused, or have an intent result
	 * in the reply, so we might have to push the responsibility for
	 * sending the reply down into the AST handlers, alas.
	 */

	switch (lustre_msg_get_opc(req->rq_reqmsg)) {
	case LDLM_BL_CALLBACK:
		LDLM_DEBUG(lock, "blocking ast\n");
		req_capsule_extend(&req->rq_pill, &RQF_LDLM_BL_CALLBACK);
		if (!ldlm_is_cancel_on_block(lock)) {
			rc = ldlm_callback_reply(req, 0);
			if (req->rq_no_reply || rc)
				ldlm_callback_errmsg(req, "Normal process", rc,
						     &dlm_req->lock_handle[0]);
		}
		if (ldlm_bl_to_thread_lock(ns, &dlm_req->lock_desc, lock))
			ldlm_handle_bl_callback(ns, &dlm_req->lock_desc, lock);
		break;
	case LDLM_CP_CALLBACK:
		LDLM_DEBUG(lock, "completion ast\n");
		req_capsule_extend(&req->rq_pill, &RQF_LDLM_CP_CALLBACK);
		rc = ldlm_handle_cp_callback(req, ns, dlm_req, lock);
		if (!CFS_FAIL_CHECK(OBD_FAIL_LDLM_CANCEL_BL_CB_RACE))
			ldlm_callback_reply(req, rc);
		break;
	case LDLM_GL_CALLBACK:
		LDLM_DEBUG(lock, "glimpse ast\n");
		req_capsule_extend(&req->rq_pill, &RQF_LDLM_GL_CALLBACK);
		ldlm_handle_gl_callback(req, ns, dlm_req, lock);
		break;
	default:
		LBUG();			/* checked above */
	}

	return 0;
}

static int ldlm_bl_get_work(struct ldlm_bl_pool *blp,
			    struct ldlm_bl_work_item **p_blwi,
			    struct obd_export **p_exp)
{
	int num_th = atomic_read(&blp->blp_num_threads);
	struct ldlm_bl_work_item *blwi = NULL;
	static unsigned int num_bl;

	spin_lock(&blp->blp_lock);
	/* process a request from the blp_list at least every blp_num_threads */
	if (!list_empty(&blp->blp_list) &&
	    (list_empty(&blp->blp_prio_list) || num_bl == 0))
		blwi = list_first_entry(&blp->blp_list,
					struct ldlm_bl_work_item, blwi_entry);
	else
		if (!list_empty(&blp->blp_prio_list))
			blwi = list_first_entry(&blp->blp_prio_list,
						struct ldlm_bl_work_item,
						blwi_entry);

	if (blwi) {
		if (++num_bl >= num_th)
			num_bl = 0;
		list_del(&blwi->blwi_entry);
	}
	spin_unlock(&blp->blp_lock);
	*p_blwi = blwi;

	/* intentional unlocked read of blp values - OK for debug */
	if (blwi) {
		CDEBUG(D_DLMTRACE,
		       "Got %d locks of %d total in blp.  (%d blwis in pool)\n",
		       blwi->blwi_lock ? 1 : blwi->blwi_count,
		       blp->blp_total_locks, blp->blp_total_blwis);
	} else {
		CDEBUG(D_DLMTRACE,
		       "No blwi found in queue (no bl locks in queue)\n");
	}

	return (*p_blwi || *p_exp) ? 1 : 0;
}

/* This only contains temporary data until the thread starts */
struct ldlm_bl_thread_data {
	struct ldlm_bl_pool	*bltd_blp;
	struct completion	bltd_comp;
	int			bltd_num;
};

static int ldlm_bl_thread_main(void *arg);

static int ldlm_bl_thread_start(struct ldlm_bl_pool *blp, bool check_busy)
{
	struct ldlm_bl_thread_data bltd = { .bltd_blp = blp };
	struct task_struct *task;

	init_completion(&bltd.bltd_comp);

	bltd.bltd_num = atomic_inc_return(&blp->blp_num_threads);
	if (bltd.bltd_num >= blp->blp_max_threads) {
		atomic_dec(&blp->blp_num_threads);
		return 0;
	}

	LASSERTF(bltd.bltd_num > 0, "thread num:%d\n", bltd.bltd_num);
	if (check_busy &&
	    atomic_read(&blp->blp_busy_threads) < (bltd.bltd_num - 1)) {
		atomic_dec(&blp->blp_num_threads);
		return 0;
	}

	task = kthread_run(ldlm_bl_thread_main, &bltd, "ldlm_bl_%02d",
			   bltd.bltd_num);
	if (IS_ERR(task)) {
		CERROR("cannot start LDLM thread ldlm_bl_%02d: rc %ld\n",
		       bltd.bltd_num, PTR_ERR(task));
		atomic_dec(&blp->blp_num_threads);
		return PTR_ERR(task);
	}
	wait_for_completion(&bltd.bltd_comp);

	return 0;
}

/* Not fatal if racy and have a few too many threads */
static int ldlm_bl_thread_need_create(struct ldlm_bl_pool *blp,
				      struct ldlm_bl_work_item *blwi)
{
	if (atomic_read(&blp->blp_num_threads) >= blp->blp_max_threads)
		return 0;

	if (atomic_read(&blp->blp_busy_threads) <
	    atomic_read(&blp->blp_num_threads))
		return 0;

	if (blwi && (!blwi->blwi_ns || blwi->blwi_mem_pressure))
		return 0;

	return 1;
}

static int ldlm_bl_thread_blwi(struct ldlm_bl_pool *blp,
			       struct ldlm_bl_work_item *blwi)
{
	unsigned int flags = 0;

	if (!blwi->blwi_ns)
		/* added by ldlm_cleanup() */
		return LDLM_ITER_STOP;

	if (blwi->blwi_mem_pressure)
		flags = memalloc_noreclaim_save();

	CFS_FAIL_TIMEOUT(OBD_FAIL_LDLM_PAUSE_CANCEL2, 4);

	if (blwi->blwi_count) {
		int count;

		/*
		 * The special case when we cancel locks in lru
		 * asynchronously, we pass the list of locks here.
		 * Thus locks are marked LDLM_FL_CANCELING, but NOT
		 * canceled locally yet.
		 */
		count = ldlm_cli_cancel_list_local(&blwi->blwi_head,
						   blwi->blwi_count,
						   LCF_BL_AST);
		ldlm_cli_cancel_list(&blwi->blwi_head, count, NULL,
				     blwi->blwi_flags);
	} else if (blwi->blwi_lock) {
		ldlm_handle_bl_callback(blwi->blwi_ns, &blwi->blwi_ld,
					blwi->blwi_lock);
	} else {
		ldlm_pool_recalc(&blwi->blwi_ns->ns_pool, true);
		spin_lock(&blwi->blwi_ns->ns_lock);
		blwi->blwi_ns->ns_rpc_recalc = 0;
		spin_unlock(&blwi->blwi_ns->ns_lock);
		ldlm_namespace_put(blwi->blwi_ns);
	}
	if (blwi->blwi_mem_pressure)
		memalloc_noreclaim_restore(flags);

	if (blwi->blwi_flags & LCF_ASYNC)
		kfree(blwi);
	else
		complete(&blwi->blwi_comp);

	return 0;
}

/**
 * Main blocking requests processing thread.
 *
 * Callers put locks into its queue by calling ldlm_bl_to_thread.
 * This thread in the end ends up doing actual call to ->l_blocking_ast
 * for queued locks.
 */
static int ldlm_bl_thread_main(void *arg)
{
	struct lu_env *env;
	struct ldlm_bl_pool *blp;
	struct ldlm_bl_thread_data *bltd = arg;
	int rc;

	env = kzalloc(sizeof(*env), GFP_NOFS);
	if (!env)
		return -ENOMEM;
	rc = lu_env_init(env, LCT_DT_THREAD);
	if (rc)
		goto out_env;
	rc = lu_env_add(env);
	if (rc)
		goto out_env_fini;

	blp = bltd->bltd_blp;

	complete(&bltd->bltd_comp);
	/* cannot use bltd after this, it is only on caller's stack */

	while (1) {
		struct ldlm_bl_work_item *blwi = NULL;
		struct obd_export *exp = NULL;
		int rc;

		rc = ldlm_bl_get_work(blp, &blwi, &exp);
		if (!rc)
			wait_event_idle_exclusive(blp->blp_waitq,
						  ldlm_bl_get_work(blp, &blwi,
								   &exp));
		atomic_inc(&blp->blp_busy_threads);

		if (ldlm_bl_thread_need_create(blp, blwi))
			/* discard the return value, we tried */
			ldlm_bl_thread_start(blp, true);

		if (blwi)
			rc = ldlm_bl_thread_blwi(blp, blwi);

		atomic_dec(&blp->blp_busy_threads);

		if (rc == LDLM_ITER_STOP)
			break;

		/*
		 * If there are many namespaces, we will not sleep waiting for
		 * work, and must do a cond_resched to avoid holding the CPU
		 * for too long
		 */
		cond_resched();
	}

	atomic_dec(&blp->blp_num_threads);
	complete(&blp->blp_comp);

	lu_env_remove(env);
out_env_fini:
	lu_env_fini(env);
out_env:
	kfree(env);
	return rc;
}

static int ldlm_setup(void);
static int ldlm_cleanup(void);

int ldlm_get_ref(void)
{
	int rc = 0;

	rc = ptlrpc_inc_ref();
	if (rc)
		return rc;

	mutex_lock(&ldlm_ref_mutex);
	if (++ldlm_refcount == 1) {
		rc = ldlm_setup();
		if (rc)
			ldlm_refcount--;
	}
	mutex_unlock(&ldlm_ref_mutex);

	if (rc)
		ptlrpc_dec_ref();

	return rc;
}

void ldlm_put_ref(void)
{
	int rc = 0;

	mutex_lock(&ldlm_ref_mutex);
	if (ldlm_refcount == 1) {
		rc = ldlm_cleanup();

		if (rc)
			CERROR("ldlm_cleanup failed: %d\n", rc);
		else
			ldlm_refcount--;
	} else {
		ldlm_refcount--;
	}
	mutex_unlock(&ldlm_ref_mutex);
	if (!rc)
		ptlrpc_dec_ref();
}

static ssize_t cancel_unused_locks_before_replay_show(struct kobject *kobj,
						      struct attribute *attr,
						      char *buf)
{
	return sprintf(buf, "%d\n", ldlm_cancel_unused_locks_before_replay);
}

static ssize_t cancel_unused_locks_before_replay_store(struct kobject *kobj,
						       struct attribute *attr,
						       const char *buffer,
						       size_t count)
{
	int rc;
	unsigned long val;

	rc = kstrtoul(buffer, 10, &val);
	if (rc)
		return rc;

	ldlm_cancel_unused_locks_before_replay = val;

	return count;
}
LUSTRE_RW_ATTR(cancel_unused_locks_before_replay);

/* These are for root of /sys/fs/lustre/ldlm */
static struct attribute *ldlm_attrs[] = {
	&lustre_attr_cancel_unused_locks_before_replay.attr,
	NULL,
};

static const struct attribute_group ldlm_attr_group = {
	.attrs = ldlm_attrs,
};

static int ldlm_setup(void)
{
	static struct ptlrpc_service_conf conf;
	struct ldlm_bl_pool *blp = NULL;
	int rc = 0;
	int i;

	if (ldlm_state)
		return -EALREADY;

	ldlm_state = kzalloc(sizeof(*ldlm_state), GFP_NOFS);
	if (!ldlm_state)
		return -ENOMEM;

	ldlm_kobj = kobject_create_and_add("ldlm", &lustre_kset->kobj);
	if (!ldlm_kobj) {
		rc = -ENOMEM;
		goto out;
	}

	rc = sysfs_create_group(ldlm_kobj, &ldlm_attr_group);
	if (rc)
		goto out;

	ldlm_ns_kset = kset_create_and_add("namespaces", NULL, ldlm_kobj);
	if (!ldlm_ns_kset) {
		rc = -ENOMEM;
		goto out;
	}

	ldlm_svc_kset = kset_create_and_add("services", NULL, ldlm_kobj);
	if (!ldlm_svc_kset) {
		rc = -ENOMEM;
		goto out;
	}

	ldlm_debugfs_setup();

	memset(&conf, 0, sizeof(conf));
	conf = (typeof(conf)) {
		.psc_name		= "ldlm_cbd",
		.psc_watchdog_factor	= 2,
		.psc_buf		= {
			.bc_nbufs		= LDLM_CLIENT_NBUFS,
			.bc_buf_size		= LDLM_BUFSIZE,
			.bc_req_max_size	= LDLM_MAXREQSIZE,
			.bc_rep_max_size	= LDLM_MAXREPSIZE,
			.bc_req_portal		= LDLM_CB_REQUEST_PORTAL,
			.bc_rep_portal		= LDLM_CB_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ldlm_cb",
			.tc_thr_factor		= LDLM_THR_FACTOR,
			.tc_nthrs_init		= LDLM_NTHRS_INIT,
			.tc_nthrs_base		= LDLM_NTHRS_BASE,
			.tc_nthrs_max		= LDLM_NTHRS_MAX,
			.tc_nthrs_user		= ldlm_num_threads,
			.tc_cpu_bind		= ldlm_cpu_bind,
			.tc_ctx_tags		= LCT_MD_THREAD | LCT_DT_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= ldlm_cpts,
			.cc_affinity		= true,
		},
		.psc_ops		= {
			.so_req_handler		= ldlm_callback_handler,
		},
	};
	ldlm_state->ldlm_cb_service =
			ptlrpc_register_service(&conf, ldlm_svc_kset,
						ldlm_svc_debugfs_dir);
	if (IS_ERR(ldlm_state->ldlm_cb_service)) {
		CERROR("failed to start service\n");
		rc = PTR_ERR(ldlm_state->ldlm_cb_service);
		ldlm_state->ldlm_cb_service = NULL;
		goto out;
	}

	blp = kzalloc(sizeof(*blp), GFP_NOFS);
	if (!blp) {
		rc = -ENOMEM;
		goto out;
	}
	ldlm_state->ldlm_bl_pool = blp;

	spin_lock_init(&blp->blp_lock);
	INIT_LIST_HEAD(&blp->blp_list);
	INIT_LIST_HEAD(&blp->blp_prio_list);
	init_waitqueue_head(&blp->blp_waitq);
	atomic_set(&blp->blp_num_threads, 0);
	atomic_set(&blp->blp_busy_threads, 0);
	blp->blp_total_locks = 0;
	blp->blp_total_blwis = 0;

	if (ldlm_num_threads == 0) {
		blp->blp_min_threads = LDLM_NTHRS_INIT;
		blp->blp_max_threads = LDLM_NTHRS_MAX;
	} else {
		blp->blp_min_threads = min_t(int, LDLM_NTHRS_MAX,
					     max_t(int, LDLM_NTHRS_INIT,
						   ldlm_num_threads));

		blp->blp_max_threads = blp->blp_min_threads;
	}

	for (i = 0; i < blp->blp_min_threads; i++) {
		rc = ldlm_bl_thread_start(blp, false);
		if (rc < 0)
			goto out;
	}

	rc = ldlm_pools_init();
	if (rc) {
		CERROR("Failed to initialize LDLM pools: %d\n", rc);
		goto out;
	}
	return 0;

 out:
	ldlm_cleanup();
	return rc;
}

static int ldlm_cleanup(void)
{
	if (!list_empty(ldlm_namespace_list(LDLM_NAMESPACE_SERVER)) ||
	    !list_empty(ldlm_namespace_list(LDLM_NAMESPACE_CLIENT))) {
		CERROR("ldlm still has namespaces; clean these up first.\n");
		ldlm_dump_all_namespaces(LDLM_NAMESPACE_SERVER, D_DLMTRACE);
		ldlm_dump_all_namespaces(LDLM_NAMESPACE_CLIENT, D_DLMTRACE);
		return -EBUSY;
	}

	ldlm_pools_fini();

	if (ldlm_state->ldlm_bl_pool) {
		struct ldlm_bl_pool *blp = ldlm_state->ldlm_bl_pool;

		while (atomic_read(&blp->blp_num_threads) > 0) {
			struct ldlm_bl_work_item blwi = { .blwi_ns = NULL };

			init_completion(&blp->blp_comp);

			spin_lock(&blp->blp_lock);
			list_add_tail(&blwi.blwi_entry, &blp->blp_list);
			wake_up(&blp->blp_waitq);
			spin_unlock(&blp->blp_lock);

			wait_for_completion(&blp->blp_comp);
		}

		kfree(blp);
	}

	if (ldlm_state->ldlm_cb_service)
		ptlrpc_unregister_service(ldlm_state->ldlm_cb_service);

	if (ldlm_ns_kset)
		kset_unregister(ldlm_ns_kset);
	if (ldlm_svc_kset)
		kset_unregister(ldlm_svc_kset);
	if (ldlm_kobj) {
		sysfs_remove_group(ldlm_kobj, &ldlm_attr_group);
		kobject_put(ldlm_kobj);
	}

	ldlm_debugfs_cleanup();

	kfree(ldlm_state);
	ldlm_state = NULL;

	return 0;
}

void ldlm_resource_init_once(void *p)
{
	/*
	 * It is import to initialise the spinlock only once,
	 * as ldlm_lock_change_resource() could try to lock
	 * the resource *after* it has been freed and possibly
	 * reused. SLAB_TYPESAFE_BY_RCU ensures the memory won't
	 * be freed while the lock is being taken, but we need to
	 * ensure that it doesn't get reinitialized either.
	 */
	struct ldlm_resource *res = p;

	memset(res, 0, sizeof(*res));
	mutex_init(&res->lr_lvb_mutex);
	spin_lock_init(&res->lr_lock);
}

int ldlm_init(void)
{
	mutex_init(&ldlm_ref_mutex);
	mutex_init(ldlm_namespace_lock(LDLM_NAMESPACE_SERVER));
	mutex_init(ldlm_namespace_lock(LDLM_NAMESPACE_CLIENT));
	ldlm_resource_slab = kmem_cache_create("ldlm_resources",
					       sizeof(struct ldlm_resource), 0,
					       SLAB_TYPESAFE_BY_RCU |
					       SLAB_HWCACHE_ALIGN,
					       ldlm_resource_init_once);
	if (!ldlm_resource_slab)
		return -ENOMEM;

	ldlm_lock_slab = kmem_cache_create("ldlm_locks",
					   sizeof(struct ldlm_lock), 0,
					   SLAB_HWCACHE_ALIGN, NULL);
	if (!ldlm_lock_slab)
		goto out_resource;

	ldlm_interval_tree_slab = kmem_cache_create("interval_tree",
						    sizeof(struct ldlm_interval_tree) * LCK_MODE_NUM,
						    0, SLAB_HWCACHE_ALIGN,
						    NULL);
	if (!ldlm_interval_tree_slab)
		goto out_lock_slab;

#if LUSTRE_TRACKS_LOCK_EXP_REFS
	class_export_dump_hook = ldlm_dump_export_locks;
#endif
	return 0;

out_lock_slab:
	kmem_cache_destroy(ldlm_lock_slab);
out_resource:
	kmem_cache_destroy(ldlm_resource_slab);

	return -ENOMEM;
}

void ldlm_exit(void)
{
	if (ldlm_refcount)
		CERROR("ldlm_refcount is %d in %s!\n", ldlm_refcount, __func__);
	synchronize_rcu();
	kmem_cache_destroy(ldlm_resource_slab);
	/*
	 * ldlm_lock_put() use RCU to call ldlm_lock_free, so need call
	 * rcu_barrier() to wait all outstanding RCU callbacks to complete,
	 * so that ldlm_lock_free() get a chance to be called.
	 */
	rcu_barrier();
	kmem_cache_destroy(ldlm_lock_slab);
	kmem_cache_destroy(ldlm_interval_tree_slab);
}

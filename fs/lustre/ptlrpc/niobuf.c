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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC
#include <linux/sched/mm.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_lib.h>
#include <obd.h>
#include <obd_class.h>
#include "ptlrpc_internal.h"

/**
 * Helper function. Sends @len bytes from @base at offset @offset
 * over @conn connection to portal @portal.
 * Returns 0 on success or error code.
 */
static int ptl_send_buf(struct lnet_handle_md *mdh, void *base, int len,
			enum lnet_ack_req ack, struct ptlrpc_cb_id *cbid,
			struct lnet_nid *self, struct lnet_processid *peer_id,
			int portal, u64 xid, unsigned int offset,
			struct lnet_handle_md *bulk_cookie)
{
	int rc;
	struct lnet_md md;

	LASSERT(portal != 0);
	CDEBUG(D_INFO, "peer_id %s\n", libcfs_idstr(peer_id));
	md.start = base;
	md.length = len;
	md.threshold = (ack == LNET_ACK_REQ) ? 2 : 1;
	md.options = PTLRPC_MD_OPTIONS;
	md.user_ptr = cbid;
	md.handler = ptlrpc_handler;
	md.bulk_handle.cookie = LNET_WIRE_HANDLE_COOKIE_NONE;

	if (bulk_cookie) {
		md.bulk_handle = *bulk_cookie;
		md.options |= LNET_MD_BULK_HANDLE;
	}

	if (CFS_FAIL_CHECK_ORSET(OBD_FAIL_PTLRPC_ACK, OBD_FAIL_ONCE) &&
	    ack == LNET_ACK_REQ) {
		/* don't ask for the ack to simulate failing client */
		ack = LNET_NOACK_REQ;
	}

	rc = LNetMDBind(&md, LNET_UNLINK, mdh);
	if (unlikely(rc != 0)) {
		CERROR("LNetMDBind failed: %d\n", rc);
		LASSERT(rc == -ENOMEM);
		return -ENOMEM;
	}

	CDEBUG(D_NET, "Sending %d bytes to portal %d, xid %lld, offset %u\n",
	       len, portal, xid, offset);

	percpu_ref_get(&ptlrpc_pending);

	rc = LNetPut(self, *mdh, ack,
		     peer_id, portal, xid, offset, 0);
	if (unlikely(rc != 0)) {
		int rc2;
		/* We're going to get an UNLINK event when I unlink below,
		 * which will complete just like any other failed send, so
		 * I fall through and return success here!
		 */
		CERROR("LNetPut(%s, %d, %lld) failed: %d\n",
		       libcfs_idstr(peer_id), portal, xid, rc);
		rc2 = LNetMDUnlink(*mdh);
		LASSERTF(rc2 == 0, "rc2 = %d\n", rc2);
	}

	return 0;
}

#define mdunlink_iterate_helper(mds, count) \
		__mdunlink_iterate_helper(mds, count, false)
static void __mdunlink_iterate_helper(struct lnet_handle_md *bd_mds,
				      int count, bool discard)
{
	int i;

	for (i = 0; i < count; i++)
		__LNetMDUnlink(bd_mds[i], discard);
}

/**
 * Register bulk at the sender for later transfer.
 * Returns 0 on success or error code.
 */
static int ptlrpc_register_bulk(struct ptlrpc_request *req)
{
	struct ptlrpc_bulk_desc *desc = req->rq_bulk;
	struct lnet_processid peer;
	int rc = 0;
	int posted_md;
	int total_md;
	u64 mbits;
	struct lnet_me *me;
	struct lnet_md md;

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_BULK_GET_NET))
		return 0;

	/* NB no locking required until desc is on the network */
	LASSERT(desc->bd_nob > 0);
	LASSERT(desc->bd_md_max_brw <= PTLRPC_BULK_OPS_COUNT);
	LASSERT(desc->bd_iov_count <= PTLRPC_MAX_BRW_PAGES);
	LASSERT(desc->bd_req);
	LASSERT(ptlrpc_is_bulk_op_passive(desc->bd_type));

	/* cleanup the state of the bulk for it will be reused */
	if (req->rq_resend || req->rq_send_state == LUSTRE_IMP_REPLAY)
		desc->bd_nob_transferred = 0;
	else if (desc->bd_nob_transferred != 0)
		/* If the network failed after an RPC was sent, this condition
		 * could happen.  Rather than assert (was here before), return
		 * an EIO error.
		 */
		return -EIO;

	desc->bd_failure = 0;

	peer = desc->bd_import->imp_connection->c_peer;

	LASSERT(desc->bd_cbid.cbid_fn == client_bulk_callback);
	LASSERT(desc->bd_cbid.cbid_arg == desc);

	total_md = desc->bd_md_count;
	/* rq_mbits is matchbits of the final bulk */
	mbits = req->rq_mbits - desc->bd_md_count + 1;

	LASSERTF(mbits == (req->rq_mbits & PTLRPC_BULK_OPS_MASK),
		 "first mbits = x%llu, last mbits = x%llu\n",
		 mbits, req->rq_mbits);
	LASSERTF(!(desc->bd_registered &&
		   req->rq_send_state != LUSTRE_IMP_REPLAY) ||
		 mbits != desc->bd_last_mbits,
		 "registered: %d  rq_mbits: %llu bd_last_mbits: %llu\n",
		 desc->bd_registered, mbits, desc->bd_last_mbits);

	desc->bd_registered = 1;
	desc->bd_last_mbits = mbits;
	desc->bd_refs = total_md;
	md.user_ptr = &desc->bd_cbid;
	md.handler = ptlrpc_handler;
	md.threshold = 1;		/* PUT or GET */

	for (posted_md = 0; posted_md < desc->bd_md_count;
	     posted_md++, mbits++) {
		md.options = PTLRPC_MD_OPTIONS |
			     (ptlrpc_is_bulk_op_get(desc->bd_type) ?
			      LNET_MD_OP_GET : LNET_MD_OP_PUT);
		ptlrpc_fill_bulk_md(&md, desc, posted_md);

		if (posted_md > 0 && posted_md + 1 == desc->bd_md_count &&
		    CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_BULK_ATTACH)) {
			rc = -ENOMEM;
		} else {
			me = LNetMEAttach(desc->bd_portal, &peer, mbits, 0,
					  LNET_UNLINK, LNET_INS_AFTER);
			rc = PTR_ERR_OR_ZERO(me);
		}
		if (rc != 0) {
			CERROR("%s: LNetMEAttach failed x%llu/%d: rc = %d\n",
			       desc->bd_import->imp_obd->obd_name, mbits,
			       posted_md, rc);
			break;
		}
		percpu_ref_get(&ptlrpc_pending);

		/* About to let the network at it... */
		rc = LNetMDAttach(me, &md, LNET_UNLINK,
				  &desc->bd_mds[posted_md]);
		if (rc != 0) {
			CERROR("%s: LNetMDAttach failed x%llu/%d: rc = %d\n",
			       desc->bd_import->imp_obd->obd_name, mbits,
			       posted_md, rc);
			break;
		}
	}

	if (rc != 0) {
		LASSERT(rc == -ENOMEM);
		spin_lock(&desc->bd_lock);
		desc->bd_refs -= total_md - posted_md;
		spin_unlock(&desc->bd_lock);
		LASSERT(desc->bd_refs >= 0);
		mdunlink_iterate_helper(desc->bd_mds, desc->bd_md_max_brw);
		req->rq_status = -ENOMEM;
		desc->bd_registered = 0;
		return -ENOMEM;
	}

	spin_lock(&desc->bd_lock);
	/* Holler if peer manages to touch buffers before he knows the mbits */
	if (desc->bd_refs != total_md)
		CWARN("%s: Peer %s touched %d buffers while I registered\n",
		      desc->bd_import->imp_obd->obd_name, libcfs_idstr(&peer),
		      total_md - desc->bd_refs);
	spin_unlock(&desc->bd_lock);

	CDEBUG(D_NET,
	       "Setup %u bulk %s buffers: %u pages %u bytes, mbits x%#llx-%#llx, portal %u\n",
	       desc->bd_refs,
	       ptlrpc_is_bulk_op_get(desc->bd_type) ? "get-source" : "put-sink",
	       desc->bd_iov_count, desc->bd_nob,
	       desc->bd_last_mbits, req->rq_mbits, desc->bd_portal);

	return 0;
}

/**
 * Disconnect a bulk desc from the network. Idempotent. Not
 * thread-safe (i.e. only interlocks with completion callback).
 * Returns 1 on success or 0 if network unregistration failed for whatever
 * reason.
 */
int ptlrpc_unregister_bulk(struct ptlrpc_request *req, int async)
{
	struct ptlrpc_bulk_desc *desc = req->rq_bulk;

	LASSERT(!in_interrupt());     /* might sleep */

	if (desc)
		desc->bd_registered = 0;

	/* Let's setup deadline for reply unlink. */
	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_LONG_BULK_UNLINK) &&
	    async && req->rq_bulk_deadline == 0 && cfs_fail_val == 0)
		req->rq_bulk_deadline = ktime_get_real_seconds() +
					PTLRPC_REQ_LONG_UNLINK;

	if (ptlrpc_client_bulk_active(req) == 0)	/* completed or */
		return 1;				/* never registered */

	LASSERT(desc->bd_req == req);  /* bd_req NULL until registered */

	/* the unlink ensures the callback happens ASAP and is the last
	 * one.  If it fails, it must be because completion just happened,
	 * but we must still wait_event() in this case to give lustre
	 * a chance to run client_bulk_callback()
	 */
	mdunlink_iterate_helper(desc->bd_mds, desc->bd_md_max_brw);

	if (ptlrpc_client_bulk_active(req) == 0)	/* completed or */
		return 1;				/* never registered */

	/* Move to "Unregistering" phase as bulk was not unlinked yet. */
	ptlrpc_rqphase_move(req, RQ_PHASE_UNREG_BULK);

	/* Do not wait for unlink to finish. */
	if (async)
		return 0;

	for (;;) {
		/* The wq argument is ignored by user-space wait_event macros */
		wait_queue_head_t *wq = (req->rq_set != NULL) ?
					&req->rq_set->set_waitq :
					&req->rq_reply_waitq;
		/*
		 * Network access will complete in finite time but the HUGE
		 * timeout lets us CWARN for visibility of sluggish LNDs
		 */
		int seconds = PTLRPC_REQ_LONG_UNLINK;

		while (seconds > PTLRPC_REQ_LONG_UNLINK &&
		       wait_event_idle_timeout(*wq,
					       !ptlrpc_client_bulk_active(req),
					       HZ) == 0)
			seconds -= 1;
		if (seconds > 0) {
			ptlrpc_rqphase_move(req, req->rq_next_phase);
			return 1;
		}

		DEBUG_REQ(D_WARNING, req, "Unexpectedly long timeout: desc %p",
			  desc);
	}
	return 0;
}

static void ptlrpc_at_set_reply(struct ptlrpc_request *req, int flags)
{
	struct ptlrpc_service_part *svcpt = req->rq_rqbd->rqbd_svcpt;
	struct ptlrpc_service *svc = svcpt->scp_service;
	timeout_t service_timeout;

	service_timeout = clamp_t(timeout_t, ktime_get_real_seconds() -
					     req->rq_arrival_time.tv_sec, 1,
				  (AT_OFF ? obd_timeout * 3 / 2 : at_max));
	if (!(flags & PTLRPC_REPLY_EARLY) &&
	    (req->rq_type != PTL_RPC_MSG_ERR) && req->rq_reqmsg &&
	    !(lustre_msg_get_flags(req->rq_reqmsg) &
	      (MSG_RESENT | MSG_REPLAY |
	       MSG_REQ_REPLAY_DONE | MSG_LOCK_REPLAY_DONE))) {
		/* early replies, errors and recovery requests don't count
		 * toward our service time estimate
		 */
		timeout_t oldse = at_measured(&svcpt->scp_at_estimate,
					      service_timeout);

		if (oldse != 0) {
			DEBUG_REQ(D_ADAPTTO, req,
				  "svc %s changed estimate from %d to %d",
				  svc->srv_name, oldse,
				  at_get(&svcpt->scp_at_estimate));
		}
	}
	/* Report actual service time for client latency calc */
	lustre_msg_set_service_timeout(req->rq_repmsg, service_timeout);
	/* Report service time estimate for future client reqs, but report 0
	 * (to be ignored by client) if it's a error reply during recovery.
	 * (bz15815)
	 */
	if (req->rq_type == PTL_RPC_MSG_ERR && !req->rq_export)
		lustre_msg_set_timeout(req->rq_repmsg, 0);
	else
		lustre_msg_set_timeout(req->rq_repmsg,
				       at_get(&svcpt->scp_at_estimate));

	if (req->rq_reqmsg &&
	    !(lustre_msghdr_get_flags(req->rq_reqmsg) & MSGHDR_AT_SUPPORT)) {
		CDEBUG(D_ADAPTTO,
		       "No early reply support: flags=%#x req_flags=%#x magic=%x/%x len=%d\n",
		       flags, lustre_msg_get_flags(req->rq_reqmsg),
		       lustre_msg_get_magic(req->rq_reqmsg),
		       lustre_msg_get_magic(req->rq_repmsg), req->rq_replen);
	}
}

/**
 * Send request reply from request @req reply buffer.
 * @flags defines reply types
 * Returns 0 on success or error code
 */
int ptlrpc_send_reply(struct ptlrpc_request *req, int flags)
{
	struct ptlrpc_reply_state *rs = req->rq_reply_state;
	struct ptlrpc_connection *conn;
	int rc;

	/* We must already have a reply buffer (only ptlrpc_error() may be
	 * called without one). The reply generated by sptlrpc layer (e.g.
	 * error notify, etc.) might have NULL rq->reqmsg; Otherwise we must
	 * have a request buffer which is either the actual (swabbed) incoming
	 * request, or a saved copy if this is a req saved in
	 * target_queue_final_reply().
	 */
	LASSERT(req->rq_no_reply == 0);
	LASSERT(req->rq_reqbuf);
	LASSERT(rs);
	LASSERT((flags & PTLRPC_REPLY_MAYBE_DIFFICULT) || !rs->rs_difficult);
	LASSERT(req->rq_repmsg);
	LASSERT(req->rq_repmsg == rs->rs_msg);
	LASSERT(rs->rs_cb_id.cbid_fn == reply_out_callback);
	LASSERT(rs->rs_cb_id.cbid_arg == rs);

	/* There may be no rq_export during failover */

	if (unlikely(req->rq_export && req->rq_export->exp_obd &&
		     req->rq_export->exp_obd->obd_fail)) {
		/* Failed obd's only send ENODEV */
		req->rq_type = PTL_RPC_MSG_ERR;
		req->rq_status = -ENODEV;
		CDEBUG(D_HA, "sending ENODEV from failed obd %d\n",
		       req->rq_export->exp_obd->obd_minor);
	}

	if (req->rq_type != PTL_RPC_MSG_ERR)
		req->rq_type = PTL_RPC_MSG_REPLY;

	lustre_msg_set_type(req->rq_repmsg, req->rq_type);
	lustre_msg_set_status(req->rq_repmsg,
			      ptlrpc_status_hton(req->rq_status));
	lustre_msg_set_opc(req->rq_repmsg,
			   req->rq_reqmsg ?
			   lustre_msg_get_opc(req->rq_reqmsg) : 0);

	target_pack_pool_reply(req);

	ptlrpc_at_set_reply(req, flags);

	if (!req->rq_export || !req->rq_export->exp_connection)
		conn = ptlrpc_connection_get(&req->rq_peer, &req->rq_self,
					     NULL);
	else
		conn = ptlrpc_connection_addref(req->rq_export->exp_connection);

	if (unlikely(!conn)) {
		CERROR("not replying on NULL connection\n"); /* bug 9635 */
		return -ENOTCONN;
	}
	ptlrpc_rs_addref(rs);		/* +1 ref for the network */

	rc = sptlrpc_svc_wrap_reply(req);
	if (unlikely(rc))
		goto out;

	req->rq_sent = ktime_get_real_seconds();

	rc = ptl_send_buf(&rs->rs_md_h, rs->rs_repbuf, rs->rs_repdata_len,
			  (rs->rs_difficult && !rs->rs_no_ack) ?
			  LNET_ACK_REQ : LNET_NOACK_REQ,
			  &rs->rs_cb_id, &req->rq_self,
			  &req->rq_source,
			  ptlrpc_req2svc(req)->srv_rep_portal,
			  req->rq_rep_mbits ? req->rq_rep_mbits : req->rq_xid,
			  req->rq_reply_off, NULL);
out:
	if (unlikely(rc != 0))
		ptlrpc_req_drop_rs(req);
	ptlrpc_connection_put(conn);
	return rc;
}

int ptlrpc_reply(struct ptlrpc_request *req)
{
	if (req->rq_no_reply)
		return 0;
	return ptlrpc_send_reply(req, 0);
}

/**
 * For request @req send an error reply back. Create empty
 * reply buffers if necessary.
 */
int ptlrpc_send_error(struct ptlrpc_request *req, int may_be_difficult)
{
	int rc;

	if (req->rq_no_reply)
		return 0;

	if (!req->rq_repmsg) {
		rc = lustre_pack_reply(req, 1, NULL, NULL);
		if (rc)
			return rc;
	}

	if (req->rq_status != -ENOSPC && req->rq_status != -EACCES &&
	    req->rq_status != -EPERM && req->rq_status != -ENOENT &&
	    req->rq_status != -EINPROGRESS && req->rq_status != -EDQUOT &&
	    req->rq_status != -EROFS)
		req->rq_type = PTL_RPC_MSG_ERR;

	rc = ptlrpc_send_reply(req, may_be_difficult);
	return rc;
}

int ptlrpc_error(struct ptlrpc_request *req)
{
	return ptlrpc_send_error(req, 0);
}

/**
 * Send request @request.
 * if @noreply is set, don't expect any reply back and don't set up
 * reply buffers.
 * Returns 0 on success or error code.
 */
int ptl_send_rpc(struct ptlrpc_request *request, int noreply)
{
	int rc;
	u32 opc;
	unsigned int mpflag = 0;
	bool rep_mbits = false;
	struct lnet_handle_md bulk_cookie;
	struct lnet_processid peer;
	struct ptlrpc_connection *connection;
	struct lnet_me *reply_me;
	struct lnet_md reply_md;
	struct obd_import *imp = request->rq_import;
	struct obd_device *obd = imp->imp_obd;

	bulk_cookie.cookie = LNET_WIRE_HANDLE_COOKIE_NONE;

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_DROP_RPC))
		return 0;

	LASSERT(request->rq_type == PTL_RPC_MSG_REQUEST);
	LASSERT(request->rq_wait_ctx == 0);

	/* If this is a re-transmit, we're required to have disengaged
	 * cleanly from the previous attempt
	 */
	LASSERT(!request->rq_receiving_reply);
	LASSERT(!((lustre_msg_get_flags(request->rq_reqmsg) & MSG_REPLAY) &&
		  (imp->imp_state == LUSTRE_IMP_FULL)));

	if (unlikely(obd && obd->obd_fail)) {
		CDEBUG(D_HA, "muting rpc for failed imp obd %s\n",
		       obd->obd_name);
		/* this prevents us from waiting in ptlrpc_queue_wait */
		spin_lock(&request->rq_lock);
		request->rq_err = 1;
		spin_unlock(&request->rq_lock);
		request->rq_status = -ENODEV;
		return -ENODEV;
	}

	connection = imp->imp_connection;

	lustre_msg_set_handle(request->rq_reqmsg,
			      &imp->imp_remote_handle);
	lustre_msg_set_type(request->rq_reqmsg, PTL_RPC_MSG_REQUEST);
	lustre_msg_set_conn_cnt(request->rq_reqmsg, imp->imp_conn_cnt);
	lustre_msghdr_set_flags(request->rq_reqmsg, imp->imp_msghdr_flags);

	/*
	 * If it's the first time to resend the request for EINPROGRESS,
	 * we need to allocate a new XID (see after_reply()), it's different
	 * from the resend for reply timeout.
	 */
	if (request->rq_nr_resend && list_empty(&request->rq_unreplied_list)) {
		u64 min_xid = 0;
		/*
		 * resend for EINPROGRESS, allocate new xid to avoid reply
		 * reconstruction
		 */
		spin_lock(&imp->imp_lock);
		ptlrpc_assign_next_xid_nolock(request);
		min_xid = ptlrpc_known_replied_xid(imp);
		spin_unlock(&imp->imp_lock);

		lustre_msg_set_last_xid(request->rq_reqmsg, min_xid);
		DEBUG_REQ(D_RPCTRACE, request,
			  "Allocating new XID for resend on EINPROGRESS");
	}

	opc = lustre_msg_get_opc(request->rq_reqmsg);
	if (opc != OST_CONNECT && opc != MDS_CONNECT &&
	    opc != MGS_CONNECT && OCD_HAS_FLAG(&imp->imp_connect_data, FLAGS2))
		rep_mbits = imp->imp_connect_data.ocd_connect_flags2 &
			    OBD_CONNECT2_REP_MBITS;

	if (request->rq_bulk || rep_mbits) {
		ptlrpc_set_mbits(request);
		lustre_msg_set_mbits(request->rq_reqmsg, request->rq_mbits);
	}

	if (list_empty(&request->rq_unreplied_list) ||
	    request->rq_xid <= imp->imp_known_replied_xid) {
		DEBUG_REQ(D_ERROR, request,
			  "xid=%llu, replied=%llu, list_empty=%d",
			  request->rq_xid, imp->imp_known_replied_xid,
			  list_empty(&request->rq_unreplied_list));
		LBUG();
	}

	/**
	 * For enabled AT all request should have AT_SUPPORT in the
	 * FULL import state when OBD_CONNECT_AT is set.
	 * This check has a race with ptlrpc_connect_import_locked()
	 * with low chance, don't panic, only report.
	 */
	if (!(AT_OFF || imp->imp_state != LUSTRE_IMP_FULL ||
	    (imp->imp_msghdr_flags & MSGHDR_AT_SUPPORT) ||
	    !(imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_AT))) {
		DEBUG_REQ(D_HA, request,
			  "Wrong state of import detected, AT=%d, imp=%d, msghdr=%d, conn=%d\n",
			  AT_OFF, imp->imp_state != LUSTRE_IMP_FULL,
			  (imp->imp_msghdr_flags & MSGHDR_AT_SUPPORT),
			  !(imp->imp_connect_data.ocd_connect_flags &
			    OBD_CONNECT_AT));
	}
	if (request->rq_resend)
		lustre_msg_add_flags(request->rq_reqmsg, MSG_RESENT);

	if (request->rq_memalloc)
		mpflag = memalloc_noreclaim_save();

	rc = sptlrpc_cli_wrap_request(request);
	if (rc)
		goto out;

	/* bulk register should be done after wrap_request() */
	if (request->rq_bulk) {
		rc = ptlrpc_register_bulk(request);
		if (rc != 0)
			goto cleanup_bulk;
		/*
		 * All the mds in the request will have the same cpt
		 * encoded in the cookie. So we can just get the first
		 * one.
		 */
		bulk_cookie = request->rq_bulk->bd_mds[0];
	}

	if (!noreply) {
		LASSERT(request->rq_replen != 0);
		if (!request->rq_repbuf) {
			LASSERT(!request->rq_repdata);
			LASSERT(!request->rq_repmsg);
			rc = sptlrpc_cli_alloc_repbuf(request,
						      request->rq_replen);
			if (rc) {
				/* this prevents us from looping in
				 * ptlrpc_queue_wait
				 */
				spin_lock(&request->rq_lock);
				request->rq_err = 1;
				spin_unlock(&request->rq_lock);
				request->rq_status = rc;
				goto cleanup_bulk;
			}
		} else {
			request->rq_repdata = NULL;
			request->rq_repmsg = NULL;
		}

		peer = connection->c_peer;
		if (request->rq_bulk &&
		    CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_BULK_REPLY_ATTACH)) {
			reply_me = ERR_PTR(-ENOMEM);
		} else {
			reply_me = LNetMEAttach(request->rq_reply_portal,
						&peer,
						rep_mbits ? request->rq_mbits :
						request->rq_xid,
						0, LNET_UNLINK, LNET_INS_AFTER);
		}

		if (IS_ERR(reply_me)) {
			rc = PTR_ERR(reply_me);
			CERROR("LNetMEAttach failed: %d\n", rc);
			LASSERT(rc == -ENOMEM);
			rc = -ENOMEM;
			goto cleanup_bulk;
		}
	}

	spin_lock(&request->rq_lock);
	/* We are responsible for unlinking the reply buffer */
	request->rq_reply_unlinked = noreply;
	request->rq_receiving_reply = !noreply;
	/* Clear any flags that may be present from previous sends. */
	request->rq_req_unlinked = 0;
	request->rq_replied = 0;
	request->rq_err = 0;
	request->rq_timedout = 0;
	request->rq_net_err = 0;
	request->rq_resend = 0;
	request->rq_restart = 0;
	request->rq_reply_truncated = 0;
	spin_unlock(&request->rq_lock);

	if (!noreply) {
		reply_md.start = request->rq_repbuf;
		reply_md.length = request->rq_repbuf_len;
		/* Allow multiple early replies */
		reply_md.threshold = LNET_MD_THRESH_INF;
		/* Manage remote for early replies */
		reply_md.options = PTLRPC_MD_OPTIONS | LNET_MD_OP_PUT |
			LNET_MD_MANAGE_REMOTE |
			LNET_MD_TRUNCATE; /* allow to make EOVERFLOW error */
		reply_md.user_ptr = &request->rq_reply_cbid;
		reply_md.handler = ptlrpc_handler;

		/* We must see the unlink callback to set rq_reply_unlinked,
		 * so we can't auto-unlink
		 */
		rc = LNetMDAttach(reply_me, &reply_md, LNET_RETAIN,
				  &request->rq_reply_md_h);
		if (rc != 0) {
			CERROR("LNetMDAttach failed: %d\n", rc);
			LASSERT(rc == -ENOMEM);
			spin_lock(&request->rq_lock);
			/* ...but the MD attach didn't succeed... */
			request->rq_receiving_reply = 0;
			spin_unlock(&request->rq_lock);
			rc = -ENOMEM;
			goto cleanup_bulk;
		}
		percpu_ref_get(&ptlrpc_pending);

		CDEBUG(D_NET,
		       "Setup reply buffer: %u bytes, xid %llu, portal %u\n",
		       request->rq_repbuf_len, request->rq_xid,
		       request->rq_reply_portal);
	}

	/* add references on request for request_out_callback */
	ptlrpc_request_addref(request);
	if (obd && obd->obd_svc_stats)
		lprocfs_counter_add(obd->obd_svc_stats, PTLRPC_REQACTIVE_CNTR,
			atomic_read(&imp->imp_inflight));

	CFS_FAIL_TIMEOUT(OBD_FAIL_PTLRPC_DELAY_SEND, request->rq_timeout + 5);

	request->rq_sent_ns = ktime_get_real();
	request->rq_sent = ktime_get_real_seconds();
	/* We give the server rq_timeout secs to process the req, and
	 * add the network latency for our local timeout.
	 */
	request->rq_deadline = request->rq_sent + request->rq_timeout +
			       ptlrpc_at_get_net_latency(request);

	if (unlikely(opc == OBD_PING &&
	    CFS_FAIL_TIMEOUT(OBD_FAIL_PTLRPC_DELAY_SEND_FAIL, cfs_fail_val)))
		goto skip_send;

	DEBUG_REQ(D_INFO, request, "send flags=%x",
		  lustre_msg_get_flags(request->rq_reqmsg));
	rc = ptl_send_buf(&request->rq_req_md_h,
			  request->rq_reqbuf, request->rq_reqdata_len,
			  LNET_NOACK_REQ, &request->rq_req_cbid,
			  NULL,
			  &connection->c_peer,
			  request->rq_request_portal,
			  request->rq_xid, 0, &bulk_cookie);
	if (likely(rc == 0))
		goto out;

skip_send:
	request->rq_req_unlinked = 1;
	ptlrpc_req_finished(request);
	if (noreply)
		goto out;

	LNetMDUnlink(request->rq_reply_md_h);

	/* UNLINKED callback called synchronously */
	LASSERT(!request->rq_receiving_reply);

cleanup_bulk:
	/* We do sync unlink here as there was no real transfer here so
	 * the chance to have long unlink to sluggish net is smaller here.
	 */
	ptlrpc_unregister_bulk(request, 0);
out:
	if (rc == -ENOMEM) {
		/*
		 * set rq_sent so that this request is treated
		 * as a delayed send in the upper layers
		 */
		request->rq_sent = ktime_get_seconds();
	}

	if (request->rq_memalloc)
		memalloc_noreclaim_restore(mpflag);

	return rc;
}
EXPORT_SYMBOL(ptl_send_rpc);

/**
 * Register request buffer descriptor for request receiving.
 */
int ptlrpc_register_rqbd(struct ptlrpc_request_buffer_desc *rqbd)
{
	struct ptlrpc_service *service = rqbd->rqbd_svcpt->scp_service;
	static struct lnet_processid match_id = {
		.nid = LNET_ANY_NID,
		.pid = LNET_PID_ANY
	};
	int rc;
	struct lnet_md md;
	struct lnet_me *me;

	CDEBUG(D_NET, "%s: registering portal %d\n", service->srv_name,
	       service->srv_req_portal);

	if (CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_RQBD))
		return -ENOMEM;

	/* NB: CPT affinity service should use new LNet flag LNET_INS_LOCAL,
	 * which means buffer can only be attached on local CPT, and LND
	 * threads can find it by grabbing a local lock
	 */
	me = LNetMEAttach(service->srv_req_portal,
			  &match_id, 0, ~0, LNET_UNLINK,
			  rqbd->rqbd_svcpt->scp_cpt >= 0 ?
			  LNET_INS_LOCAL : LNET_INS_AFTER);
	if (IS_ERR(me)) {
		CERROR("%s: LNetMEAttach failed: rc = %ld\n",
		       service->srv_name, PTR_ERR(me));
		return PTR_ERR(me);
	}

	LASSERT(rqbd->rqbd_refcount == 0);
	rqbd->rqbd_refcount = 1;

	md.start = rqbd->rqbd_buffer;
	md.length = service->srv_buf_size;
	md.max_size = service->srv_max_req_size;
	md.threshold = LNET_MD_THRESH_INF;
	md.options = PTLRPC_MD_OPTIONS | LNET_MD_OP_PUT | LNET_MD_MAX_SIZE;
	md.user_ptr = &rqbd->rqbd_cbid;
	md.handler = ptlrpc_handler;

	rc = LNetMDAttach(me, &md, LNET_UNLINK, &rqbd->rqbd_md_h);
	if (rc == 0) {
		percpu_ref_get(&ptlrpc_pending);
		return 0;
	}

	CERROR("%s: LNetMDAttach failed: rc = %d\n", service->srv_name, rc);
	LASSERT(rc == -ENOMEM);
	rqbd->rqbd_refcount = 0;

	return rc;
}

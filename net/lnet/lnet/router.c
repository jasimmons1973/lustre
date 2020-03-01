// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 *   This file is part of Portals
 *   http://sourceforge.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/completion.h>
#include <linux/lnet/lib-lnet.h>

#define LNET_NRB_TINY_MIN	512	/* min value for each CPT */
#define LNET_NRB_TINY		(LNET_NRB_TINY_MIN * 4)
#define LNET_NRB_SMALL_MIN	4096	/* min value for each CPT */
#define LNET_NRB_SMALL		(LNET_NRB_SMALL_MIN * 4)
#define LNET_NRB_SMALL_PAGES	1
#define LNET_NRB_LARGE_MIN	256	/* min value for each CPT */
#define LNET_NRB_LARGE		(LNET_NRB_LARGE_MIN * 4)
#define LNET_NRB_LARGE_PAGES   ((LNET_MTU + PAGE_SIZE - 1) >> \
				 PAGE_SHIFT)

static char *forwarding = "";
module_param(forwarding, charp, 0444);
MODULE_PARM_DESC(forwarding, "Explicitly enable/disable forwarding between networks");

static int tiny_router_buffers;
module_param(tiny_router_buffers, int, 0444);
MODULE_PARM_DESC(tiny_router_buffers, "# of 0 payload messages to buffer in the router");
static int small_router_buffers;
module_param(small_router_buffers, int, 0444);
MODULE_PARM_DESC(small_router_buffers, "# of small (1 page) messages to buffer in the router");
static int large_router_buffers;
module_param(large_router_buffers, int, 0444);
MODULE_PARM_DESC(large_router_buffers, "# of large messages to buffer in the router");
static int peer_buffer_credits;
module_param(peer_buffer_credits, int, 0444);
MODULE_PARM_DESC(peer_buffer_credits, "# router buffer credits per peer");

static int auto_down = 1;
module_param(auto_down, int, 0444);
MODULE_PARM_DESC(auto_down, "Automatically mark peers down on comms error");

int
lnet_peer_buffer_credits(struct lnet_net *net)
{
	/* NI option overrides LNet default */
	if (net->net_tunables.lct_peer_rtr_credits > 0)
		return net->net_tunables.lct_peer_rtr_credits;
	if (peer_buffer_credits > 0)
		return peer_buffer_credits;

	/*
	 * As an approximation, allow this peer the same number of router
	 * buffers as it is allowed outstanding sends
	 */
	return net->net_tunables.lct_peer_tx_credits;
}

static int check_routers_before_use;
module_param(check_routers_before_use, int, 0444);
MODULE_PARM_DESC(check_routers_before_use, "Assume routers are down and ping them before use");

int avoid_asym_router_failure = 1;
module_param(avoid_asym_router_failure, int, 0644);
MODULE_PARM_DESC(avoid_asym_router_failure, "Avoid asymmetrical router failures (0 to disable)");

static int dead_router_check_interval = 60;
module_param(dead_router_check_interval, int, 0644);
MODULE_PARM_DESC(dead_router_check_interval, "Seconds between dead router health checks (<= 0 to disable)");

static int live_router_check_interval = 60;
module_param(live_router_check_interval, int, 0644);
MODULE_PARM_DESC(live_router_check_interval, "Seconds between live router health checks (<= 0 to disable)");

static int router_ping_timeout = 50;
module_param(router_ping_timeout, int, 0644);
MODULE_PARM_DESC(router_ping_timeout, "Seconds to wait for the reply to a router health query");

int
lnet_peers_start_down(void)
{
	return check_routers_before_use;
}

void
lnet_notify_locked(struct lnet_peer_ni *lp, int notifylnd, int alive,
		   time64_t when)
{
	if (lp->lpni_timestamp > when) { /* out of date information */
		CDEBUG(D_NET, "Out of date\n");
		return;
	}

	/*
	 * This function can be called with different cpt locks being
	 * held. lpni_alive_count modification needs to be properly protected.
	 * Significant reads to lpni_alive_count are also protected with
	 * the same lock
	 */
	spin_lock(&lp->lpni_lock);

	lp->lpni_timestamp = when;		/* update timestamp */

	if (lp->lpni_alive_count &&		/* got old news */
	    (!lp->lpni_alive) == (!alive)) {	/* new date for old news */
		spin_unlock(&lp->lpni_lock);
		CDEBUG(D_NET, "Old news\n");
		return;
	}

	/* Flag that notification is outstanding */

	lp->lpni_alive_count++;
	lp->lpni_alive = !!alive;	/* 1 bit! */
	lp->lpni_notify = 1;
	lp->lpni_notifylnd = notifylnd;
	if (lp->lpni_alive)
		lp->lpni_ping_feats = LNET_PING_FEAT_INVAL; /* reset */

	spin_unlock(&lp->lpni_lock);

	CDEBUG(D_NET, "set %s %d\n", libcfs_nid2str(lp->lpni_nid), alive);
}

/*
 * This function will always be called with lp->lpni_cpt lock held.
 */
static void
lnet_ni_notify_locked(struct lnet_ni *ni, struct lnet_peer_ni *lp)
{
	int alive;
	int notifylnd;

	/*
	 * Notify only in 1 thread at any time to ensure ordered notification.
	 * NB individual events can be missed; the only guarantee is that you
	 * always get the most recent news
	 */
	spin_lock(&lp->lpni_lock);

	if (lp->lpni_notifying || !ni) {
		spin_unlock(&lp->lpni_lock);
		return;
	}

	lp->lpni_notifying = 1;

	/*
	 * lp->lpni_notify needs to be protected because it can be set in
	 * lnet_notify_locked().
	 */
	while (lp->lpni_notify) {
		alive = lp->lpni_alive;
		notifylnd = lp->lpni_notifylnd;

		lp->lpni_notifylnd = 0;
		lp->lpni_notify = 0;

		if (notifylnd && ni->ni_net->net_lnd->lnd_notify) {
			spin_unlock(&lp->lpni_lock);
			lnet_net_unlock(lp->lpni_cpt);

			/*
			 * A new notification could happen now; I'll handle it
			 * when control returns to me
			 */
			ni->ni_net->net_lnd->lnd_notify(ni, lp->lpni_nid,
							alive);

			lnet_net_lock(lp->lpni_cpt);
			spin_lock(&lp->lpni_lock);
		}
	}

	lp->lpni_notifying = 0;
	spin_unlock(&lp->lpni_lock);
}

struct lnet_remotenet *
lnet_find_rnet_locked(u32 net)
{
	struct lnet_remotenet *rnet;
	struct list_head *rn_list;

	LASSERT(the_lnet.ln_state == LNET_STATE_RUNNING);

	rn_list = lnet_net2rnethash(net);
	list_for_each_entry(rnet, rn_list, lrn_list) {
		if (rnet->lrn_net == net)
			return rnet;
	}
	return NULL;
}

int
lnet_add_route(u32 net, u32 hops, lnet_nid_t gateway,
	       unsigned int priority)
{
	net = net;
	hops = hops;
	gateway = gateway;
	priority = priority;
	return -EINVAL;
}

/* TODO: reimplement lnet_check_routes() */
int
lnet_del_route(u32 net, lnet_nid_t gw_nid)
{
	net = net;
	gw_nid = gw_nid;
	return -EINVAL;
}

void
lnet_destroy_routes(void)
{
	lnet_del_route(LNET_NIDNET(LNET_NID_ANY), LNET_NID_ANY);
}

int lnet_get_rtr_pool_cfg(int cpt, struct lnet_ioctl_pool_cfg *pool_cfg)
{
	struct lnet_rtrbufpool *rbp;
	int i, rc = -ENOENT, j;

	if (!the_lnet.ln_rtrpools)
		return rc;


	cfs_percpt_for_each(rbp, i, the_lnet.ln_rtrpools) {
		if (i != cpt)
			continue;

		lnet_net_lock(i);
		for (j = 0; j < LNET_NRBPOOLS; j++) {
			pool_cfg->pl_pools[j].pl_npages = rbp[j].rbp_npages;
			pool_cfg->pl_pools[j].pl_nbuffers = rbp[j].rbp_nbuffers;
			pool_cfg->pl_pools[j].pl_credits = rbp[j].rbp_credits;
			pool_cfg->pl_pools[j].pl_mincredits =
				rbp[j].rbp_mincredits;
		}
		lnet_net_unlock(i);
		rc = 0;
		break;
	}

	lnet_net_lock(LNET_LOCK_EX);
	pool_cfg->pl_routing = the_lnet.ln_routing;
	lnet_net_unlock(LNET_LOCK_EX);

	return rc;
}

int
lnet_get_route(int idx, u32 *net, u32 *hops,
	       lnet_nid_t *gateway, u32 *alive, u32 *priority)
{
	struct lnet_remotenet *rnet;
	struct lnet_route *route;
	int cpt;
	int i;
	struct list_head *rn_list;

	cpt = lnet_net_lock_current();

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++) {
		rn_list = &the_lnet.ln_remote_nets_hash[i];
		list_for_each_entry(rnet, rn_list, lrn_list) {
			list_for_each_entry(route, &rnet->lrn_routes, lr_list) {
				if (!idx--) {
					*net = rnet->lrn_net;
					*hops = route->lr_hops;
					*priority = route->lr_priority;
					*gateway =
					    route->lr_gateway->lp_primary_nid;
					*alive = lnet_is_route_alive(route);
					lnet_net_unlock(cpt);
					return 0;
				}
			}
		}
	}

	lnet_net_unlock(cpt);
	return -ENOENT;
}

void
lnet_swap_pinginfo(struct lnet_ping_buffer *pbuf)
{
	struct lnet_ni_status *stat;
	int nnis;
	int i;

	__swab32s(&pbuf->pb_info.pi_magic);
	__swab32s(&pbuf->pb_info.pi_features);
	__swab32s(&pbuf->pb_info.pi_pid);
	__swab32s(&pbuf->pb_info.pi_nnis);
	nnis = pbuf->pb_info.pi_nnis;
	if (nnis > pbuf->pb_nnis)
		nnis = pbuf->pb_nnis;
	for (i = 0; i < nnis; i++) {
		stat = &pbuf->pb_info.pi_ni[i];
		__swab64s(&stat->ns_nid);
		__swab32s(&stat->ns_status);
	}
}

/**
 * TODO: re-implement
 */
static void
lnet_parse_rc_info(struct lnet_rc_data *rcd)
{
	rcd = rcd;
}

static void
lnet_router_checker_event(struct lnet_event *event)
{
	struct lnet_rc_data *rcd = event->md.user_ptr;
	struct lnet_peer_ni *lp;

	LASSERT(rcd);

	if (event->unlinked) {
		LNetInvalidateMDHandle(&rcd->rcd_mdh);
		return;
	}

	LASSERT(event->type == LNET_EVENT_SEND ||
		event->type == LNET_EVENT_REPLY);

	lp = rcd->rcd_gateway;
	LASSERT(lp);

	/*
	 * NB: it's called with holding lnet_res_lock, we have a few
	 * places need to hold both locks at the same time, please take
	 * care of lock ordering
	 */
	lnet_net_lock(lp->lpni_cpt);
	if (!lnet_isrouter(lp) || lp->lpni_rcd != rcd) {
		/* ignore if no longer a router or rcd is replaced */
		goto out;
	}

	if (event->type == LNET_EVENT_SEND) {
		if (!event->status)
			goto out;
	}

	/* LNET_EVENT_REPLY */
	/*
	 * A successful REPLY means the router is up.  If _any_ comms
	 * to the router fail I assume it's down (this will happen if
	 * we ping alive routers to try to detect router death before
	 * apps get burned).
	 */
	lnet_notify_locked(lp, 1, !event->status, ktime_get_seconds());

	/*
	 * The router checker will wake up very shortly and do the
	 * actual notification.
	 * XXX If 'lp' stops being a router before then, it will still
	 * have the notification pending!!!
	 */
	if (avoid_asym_router_failure && !event->status)
		lnet_parse_rc_info(rcd);

out:
	lnet_net_unlock(lp->lpni_cpt);
}

static void
lnet_wait_known_routerstate(void)
{
	struct lnet_peer *rtr;
	int all_known;

	LASSERT(the_lnet.ln_mt_state == LNET_MT_STATE_RUNNING);

	for (;;) {
		int cpt = lnet_net_lock_current();

		all_known = 1;
		list_for_each_entry(rtr, &the_lnet.ln_routers, lp_rtr_list) {
			spin_lock(&rtr->lp_lock);

			if (!(rtr->lp_state & LNET_PEER_DISCOVERED)) {
				all_known = 0;
				spin_unlock(&rtr->lp_lock);
				break;
			}
			spin_unlock(&rtr->lp_lock);
		}

		lnet_net_unlock(cpt);

		if (all_known)
			return;

		schedule_timeout_uninterruptible(HZ);
	}
}

/* TODO: reimplement */
void
lnet_router_ni_update_locked(struct lnet_peer_ni *gw, u32 net)
{
	struct lnet_route *rte;
	struct lnet_peer *lp;

	if ((gw->lpni_ping_feats & LNET_PING_FEAT_NI_STATUS))
		lp = gw->lpni_peer_net->lpn_peer;
	else
		return;

	list_for_each_entry(rte, &lp->lp_routes, lr_gwlist) {
		if (rte->lr_net == net) {
			rte->lr_downis = 0;
			break;
		}
	}
}

static void
lnet_update_ni_status_locked(void)
{
	struct lnet_ni *ni = NULL;
	time64_t now;
	time64_t timeout;

	LASSERT(the_lnet.ln_routing);

	timeout = router_ping_timeout +
		  max(live_router_check_interval, dead_router_check_interval);

	now = ktime_get_real_seconds();
	while ((ni = lnet_get_next_ni_locked(NULL, ni))) {
		if (ni->ni_net->net_lnd->lnd_type == LOLND)
			continue;

		if (now < ni->ni_last_alive + timeout)
			continue;

		lnet_ni_lock(ni);
		/* re-check with lock */
		if (now < ni->ni_last_alive + timeout) {
			lnet_ni_unlock(ni);
			continue;
		}

		LASSERT(ni->ni_status);

		if (ni->ni_status->ns_status != LNET_NI_STATUS_DOWN) {
			CDEBUG(D_NET, "NI(%s:%lld) status changed to down\n",
			       libcfs_nid2str(ni->ni_nid), timeout);
			/*
			 * NB: so far, this is the only place to set
			 * NI status to "down"
			 */
			ni->ni_status->ns_status = LNET_NI_STATUS_DOWN;
		}
		lnet_ni_unlock(ni);
	}
}

int lnet_router_pre_mt_start(void)
{
	int rc;

	if (check_routers_before_use &&
	    dead_router_check_interval <= 0) {
		LCONSOLE_ERROR_MSG(0x10a, "'dead_router_check_interval' must be set if 'check_routers_before_use' is set\n");
		return -EINVAL;
	}

	rc = LNetEQAlloc(0, lnet_router_checker_event, &the_lnet.ln_rc_eqh);
	if (rc) {
		CERROR("Can't allocate EQ(0): %d\n", rc);
		return -ENOMEM;
	}

	return 0;
}

void lnet_router_post_mt_start(void)
{
	if (check_routers_before_use) {
		/*
		 * Note that a helpful side-effect of pinging all known routers
		 * at startup is that it makes them drop stale connections they
		 * may have to a previous instance of me.
		 */
		lnet_wait_known_routerstate();
	}
}

void lnet_router_cleanup(void)
{
	int rc;

	rc = LNetEQFree(the_lnet.ln_rc_eqh);
	LASSERT(rc == 0);
}

void lnet_prune_rc_data(int wait_unlink)
{
	wait_unlink = wait_unlink;
}

/*
 * This function is called from the monitor thread to check if there are
 * any active routers that need to be checked.
 */
bool lnet_router_checker_active(void)
{
	if (the_lnet.ln_mt_state != LNET_MT_STATE_RUNNING)
		return true;

	/*
	 * Router Checker thread needs to run when routing is enabled in
	 * order to call lnet_update_ni_status_locked()
	 */
	if (the_lnet.ln_routing)
		return true;

	/* if there are routers that need to be cleaned up then do so */
	if (!list_empty(&the_lnet.ln_rcd_deathrow) ||
	    !list_empty(&the_lnet.ln_rcd_zombie))
		return true;

	return !list_empty(&the_lnet.ln_routers) &&
		(live_router_check_interval > 0 ||
		 dead_router_check_interval > 0);
}

void
lnet_check_routers(void)
{
	struct lnet_peer *rtr;
	u64 version;
	int cpt;

	cpt = lnet_net_lock_current();
rescan:
	version = the_lnet.ln_routers_version;

	list_for_each_entry(rtr, &the_lnet.ln_routers, lp_rtr_list) {
		/* TODO use discovery to determine if router is alive */

		/* NB dropped lock */
		if (version != the_lnet.ln_routers_version) {
			/* the routers list has changed */
			goto rescan;
		}
	}

	if (the_lnet.ln_routing)
		lnet_update_ni_status_locked();

	lnet_net_unlock(cpt);

	lnet_prune_rc_data(0); /* don't wait for UNLINK */
}

void
lnet_destroy_rtrbuf(struct lnet_rtrbuf *rb, int npages)
{
	while (--npages >= 0)
		__free_page(rb->rb_kiov[npages].bv_page);

	kfree(rb);
}

static struct lnet_rtrbuf *
lnet_new_rtrbuf(struct lnet_rtrbufpool *rbp, int cpt)
{
	int npages = rbp->rbp_npages;
	int sz = offsetof(struct lnet_rtrbuf, rb_kiov[npages]);
	struct page *page;
	struct lnet_rtrbuf *rb;
	int i;

	rb = kzalloc_cpt(sz, GFP_NOFS, cpt);
	if (!rb)
		return NULL;

	rb->rb_pool = rbp;

	for (i = 0; i < npages; i++) {
		page = alloc_pages_node(
				cfs_cpt_spread_node(lnet_cpt_table(), cpt),
				GFP_KERNEL | __GFP_ZERO, 0);
		if (!page) {
			while (--i >= 0)
				__free_page(rb->rb_kiov[i].bv_page);

			kfree(rb);
			return NULL;
		}

		rb->rb_kiov[i].bv_len = PAGE_SIZE;
		rb->rb_kiov[i].bv_offset = 0;
		rb->rb_kiov[i].bv_page = page;
	}

	return rb;
}

static void
lnet_rtrpool_free_bufs(struct lnet_rtrbufpool *rbp, int cpt)
{
	int npages = rbp->rbp_npages;
	struct list_head tmp;
	struct lnet_rtrbuf *rb;

	if (!rbp->rbp_nbuffers) /* not initialized or already freed */
		return;

	INIT_LIST_HEAD(&tmp);

	lnet_net_lock(cpt);
	list_splice_init(&rbp->rbp_msgs, &tmp);
	lnet_drop_routed_msgs_locked(&tmp, cpt);
	list_splice_init(&rbp->rbp_bufs, &tmp);
	rbp->rbp_req_nbuffers = 0;
	rbp->rbp_nbuffers = 0;
	rbp->rbp_credits = 0;
	rbp->rbp_mincredits = 0;
	lnet_net_unlock(cpt);

	/* Free buffers on the free list. */
	while (!list_empty(&tmp)) {
		rb = list_first_entry(&tmp, struct lnet_rtrbuf, rb_list);
		list_del(&rb->rb_list);
		lnet_destroy_rtrbuf(rb, npages);
	}
}

static int
lnet_rtrpool_adjust_bufs(struct lnet_rtrbufpool *rbp, int nbufs, int cpt)
{
	struct list_head rb_list;
	struct lnet_rtrbuf *rb;
	int num_rb;
	int num_buffers = 0;
	int old_req_nbufs;
	int npages = rbp->rbp_npages;

	lnet_net_lock(cpt);
	/*
	 * If we are called for less buffers than already in the pool, we
	 * just lower the req_nbuffers number and excess buffers will be
	 * thrown away as they are returned to the free list.  Credits
	 * then get adjusted as well.
	 * If we already have enough buffers allocated to serve the
	 * increase requested, then we can treat that the same way as we
	 * do the decrease.
	 */
	num_rb = nbufs - rbp->rbp_nbuffers;
	if (nbufs <= rbp->rbp_req_nbuffers || num_rb <= 0) {
		rbp->rbp_req_nbuffers = nbufs;
		lnet_net_unlock(cpt);
		return 0;
	}
	/*
	 * store the older value of rbp_req_nbuffers and then set it to
	 * the new request to prevent lnet_return_rx_credits_locked() from
	 * freeing buffers that we need to keep around
	 */
	old_req_nbufs = rbp->rbp_req_nbuffers;
	rbp->rbp_req_nbuffers = nbufs;
	lnet_net_unlock(cpt);

	INIT_LIST_HEAD(&rb_list);

	/*
	 * allocate the buffers on a local list first.  If all buffers are
	 * allocated successfully then join this list to the rbp buffer
	 * list. If not then free all allocated buffers.
	 */
	while (num_rb-- > 0) {
		rb = lnet_new_rtrbuf(rbp, cpt);
		if (!rb) {
			CERROR("Failed to allocate %d route bufs of %d pages\n",
			       nbufs, npages);

			lnet_net_lock(cpt);
			rbp->rbp_req_nbuffers = old_req_nbufs;
			lnet_net_unlock(cpt);

			goto failed;
		}

		list_add(&rb->rb_list, &rb_list);
		num_buffers++;
	}

	lnet_net_lock(cpt);

	list_splice_tail(&rb_list, &rbp->rbp_bufs);
	rbp->rbp_nbuffers += num_buffers;
	rbp->rbp_credits += num_buffers;
	rbp->rbp_mincredits = rbp->rbp_credits;
	/*
	 * We need to schedule blocked msg using the newly
	 * added buffers.
	 */
	while (!list_empty(&rbp->rbp_bufs) &&
	       !list_empty(&rbp->rbp_msgs))
		lnet_schedule_blocked_locked(rbp);

	lnet_net_unlock(cpt);

	return 0;

failed:
	while ((rb = list_first_entry_or_null(&rb_list,
					      struct lnet_rtrbuf,
					      rb_list)) != NULL) {
		list_del(&rb->rb_list);
		lnet_destroy_rtrbuf(rb, npages);
	}

	return -ENOMEM;
}

static void
lnet_rtrpool_init(struct lnet_rtrbufpool *rbp, int npages)
{
	INIT_LIST_HEAD(&rbp->rbp_msgs);
	INIT_LIST_HEAD(&rbp->rbp_bufs);

	rbp->rbp_npages = npages;
	rbp->rbp_credits = 0;
	rbp->rbp_mincredits = 0;
}

void
lnet_rtrpools_free(int keep_pools)
{
	struct lnet_rtrbufpool *rtrp;
	int i;

	if (!the_lnet.ln_rtrpools) /* uninitialized or freed */
		return;

	cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
		lnet_rtrpool_free_bufs(&rtrp[LNET_TINY_BUF_IDX], i);
		lnet_rtrpool_free_bufs(&rtrp[LNET_SMALL_BUF_IDX], i);
		lnet_rtrpool_free_bufs(&rtrp[LNET_LARGE_BUF_IDX], i);
	}

	if (!keep_pools) {
		cfs_percpt_free(the_lnet.ln_rtrpools);
		the_lnet.ln_rtrpools = NULL;
	}
}

static int
lnet_nrb_tiny_calculate(void)
{
	int nrbs = LNET_NRB_TINY;

	if (tiny_router_buffers < 0) {
		LCONSOLE_ERROR_MSG(0x10c,
				   "tiny_router_buffers=%d invalid when routing enabled\n",
				   tiny_router_buffers);
		return -EINVAL;
	}

	if (tiny_router_buffers > 0)
		nrbs = tiny_router_buffers;

	nrbs /= LNET_CPT_NUMBER;
	return max(nrbs, LNET_NRB_TINY_MIN);
}

static int
lnet_nrb_small_calculate(void)
{
	int nrbs = LNET_NRB_SMALL;

	if (small_router_buffers < 0) {
		LCONSOLE_ERROR_MSG(0x10c,
				   "small_router_buffers=%d invalid when routing enabled\n",
				   small_router_buffers);
		return -EINVAL;
	}

	if (small_router_buffers > 0)
		nrbs = small_router_buffers;

	nrbs /= LNET_CPT_NUMBER;
	return max(nrbs, LNET_NRB_SMALL_MIN);
}

static int
lnet_nrb_large_calculate(void)
{
	int nrbs = LNET_NRB_LARGE;

	if (large_router_buffers < 0) {
		LCONSOLE_ERROR_MSG(0x10c,
				   "large_router_buffers=%d invalid when routing enabled\n",
				   large_router_buffers);
		return -EINVAL;
	}

	if (large_router_buffers > 0)
		nrbs = large_router_buffers;

	nrbs /= LNET_CPT_NUMBER;
	return max(nrbs, LNET_NRB_LARGE_MIN);
}

int
lnet_rtrpools_alloc(int im_a_router)
{
	struct lnet_rtrbufpool *rtrp;
	int nrb_tiny;
	int nrb_small;
	int nrb_large;
	int rc;
	int i;

	if (!strcmp(forwarding, "")) {
		/* not set either way */
		if (!im_a_router)
			return 0;
	} else if (!strcmp(forwarding, "disabled")) {
		/* explicitly disabled */
		return 0;
	} else if (!strcmp(forwarding, "enabled")) {
		/* explicitly enabled */
	} else {
		LCONSOLE_ERROR_MSG(0x10b, "'forwarding' not set to either 'enabled' or 'disabled'\n");
		return -EINVAL;
	}

	nrb_tiny = lnet_nrb_tiny_calculate();
	if (nrb_tiny < 0)
		return -EINVAL;

	nrb_small = lnet_nrb_small_calculate();
	if (nrb_small < 0)
		return -EINVAL;

	nrb_large = lnet_nrb_large_calculate();
	if (nrb_large < 0)
		return -EINVAL;

	the_lnet.ln_rtrpools = cfs_percpt_alloc(lnet_cpt_table(),
						LNET_NRBPOOLS *
						sizeof(struct lnet_rtrbufpool));
	if (!the_lnet.ln_rtrpools) {
		LCONSOLE_ERROR_MSG(0x10c,
				   "Failed to initialize router buffe pool\n");
		return -ENOMEM;
	}

	cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
		lnet_rtrpool_init(&rtrp[LNET_TINY_BUF_IDX], 0);
		rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_TINY_BUF_IDX],
					      nrb_tiny, i);
		if (rc)
			goto failed;

		lnet_rtrpool_init(&rtrp[LNET_SMALL_BUF_IDX],
				  LNET_NRB_SMALL_PAGES);
		rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_SMALL_BUF_IDX],
					      nrb_small, i);
		if (rc)
			goto failed;

		lnet_rtrpool_init(&rtrp[LNET_LARGE_BUF_IDX],
				  LNET_NRB_LARGE_PAGES);
		rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_LARGE_BUF_IDX],
					      nrb_large, i);
		if (rc)
			goto failed;
	}

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_routing = 1;
	lnet_net_unlock(LNET_LOCK_EX);

	return 0;

failed:
	lnet_rtrpools_free(0);
	return rc;
}

static int
lnet_rtrpools_adjust_helper(int tiny, int small, int large)
{
	int nrb = 0;
	int rc = 0;
	int i;
	struct lnet_rtrbufpool *rtrp;

	/*
	 * If the provided values for each buffer pool are different than the
	 * configured values, we need to take action.
	 */
	if (tiny >= 0) {
		tiny_router_buffers = tiny;
		nrb = lnet_nrb_tiny_calculate();
		cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
			rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_TINY_BUF_IDX],
						      nrb, i);
			if (rc)
				return rc;
		}
	}
	if (small >= 0) {
		small_router_buffers = small;
		nrb = lnet_nrb_small_calculate();
		cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
			rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_SMALL_BUF_IDX],
						      nrb, i);
			if (rc)
				return rc;
		}
	}
	if (large >= 0) {
		large_router_buffers = large;
		nrb = lnet_nrb_large_calculate();
		cfs_percpt_for_each(rtrp, i, the_lnet.ln_rtrpools) {
			rc = lnet_rtrpool_adjust_bufs(&rtrp[LNET_LARGE_BUF_IDX],
						      nrb, i);
			if (rc)
				return rc;
		}
	}

	return 0;
}

int
lnet_rtrpools_adjust(int tiny, int small, int large)
{
	/*
	 * this function doesn't revert the changes if adding new buffers
	 * failed.  It's up to the user space caller to revert the
	 * changes.
	 */
	if (!the_lnet.ln_routing)
		return 0;

	return lnet_rtrpools_adjust_helper(tiny, small, large);
}

int
lnet_rtrpools_enable(void)
{
	int rc = 0;

	if (the_lnet.ln_routing)
		return 0;

	if (!the_lnet.ln_rtrpools)
		/*
		 * If routing is turned off, and we have never
		 * initialized the pools before, just call the
		 * standard buffer pool allocation routine as
		 * if we are just configuring this for the first
		 * time.
		 */
		rc = lnet_rtrpools_alloc(1);
	else
		rc = lnet_rtrpools_adjust_helper(0, 0, 0);
	if (rc)
		return rc;

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_routing = 1;

	the_lnet.ln_ping_target->pb_info.pi_features &=
		~LNET_PING_FEAT_RTE_DISABLED;
	lnet_net_unlock(LNET_LOCK_EX);

	return rc;
}

void
lnet_rtrpools_disable(void)
{
	if (!the_lnet.ln_routing)
		return;

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_routing = 0;
	the_lnet.ln_ping_target->pb_info.pi_features |=
		LNET_PING_FEAT_RTE_DISABLED;

	tiny_router_buffers = 0;
	small_router_buffers = 0;
	large_router_buffers = 0;
	lnet_net_unlock(LNET_LOCK_EX);
	lnet_rtrpools_free(1);
}

int
lnet_notify(struct lnet_ni *ni, lnet_nid_t nid, int alive, time64_t when)
{
	struct lnet_peer_ni *lp = NULL;
	time64_t now = ktime_get_seconds();
	int cpt = lnet_cpt_of_nid(nid, ni);

	LASSERT(!in_interrupt());

	CDEBUG(D_NET, "%s notifying %s: %s\n",
	       !ni ? "userspace" : libcfs_nid2str(ni->ni_nid),
	       libcfs_nid2str(nid),
	       alive ? "up" : "down");

	if (ni &&
	    LNET_NIDNET(ni->ni_nid) != LNET_NIDNET(nid)) {
		CWARN("Ignoring notification of %s %s by %s (different net)\n",
		      libcfs_nid2str(nid), alive ? "birth" : "death",
		      libcfs_nid2str(ni->ni_nid));
		return -EINVAL;
	}

	/* can't do predictions... */
	if (when > now) {
		CWARN("Ignoring prediction from %s of %s %s %lld seconds in the future\n",
		      !ni ? "userspace" : libcfs_nid2str(ni->ni_nid),
		      libcfs_nid2str(nid), alive ? "up" : "down", when - now);
		return -EINVAL;
	}

	if (ni && !alive &&	/* LND telling me she's down */
	    !auto_down) {	/* auto-down disabled */
		CDEBUG(D_NET, "Auto-down disabled\n");
		return 0;
	}

	lnet_net_lock(cpt);

	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		lnet_net_unlock(cpt);
		return -ESHUTDOWN;
	}

	lp = lnet_find_peer_ni_locked(nid);
	if (!lp) {
		/* nid not found */
		lnet_net_unlock(cpt);
		CDEBUG(D_NET, "%s not found\n", libcfs_nid2str(nid));
		return 0;
	}

	/*
	 * It is possible for this function to be called for the same peer
	 * but with different NIs. We want to synchronize the notification
	 * between the different calls. So we will use the lpni_cpt to
	 * grab the net lock.
	 */
	if (lp->lpni_cpt != cpt) {
		lnet_net_unlock(cpt);
		cpt = lp->lpni_cpt;
		lnet_net_lock(cpt);
	}

	/*
	 * We can't fully trust LND on reporting exact peer last_alive
	 * if he notifies us about dead peer. For example ksocklnd can
	 * call us with when == _time_when_the_node_was_booted_ if
	 * no connections were successfully established
	 */
	if (ni && !alive && when < lp->lpni_last_alive)
		when = lp->lpni_last_alive;

	lnet_notify_locked(lp, !ni, alive, when);

	if (ni)
		lnet_ni_notify_locked(ni, lp);

	lnet_peer_ni_decref_locked(lp);

	lnet_net_unlock(cpt);
	return 0;
}
EXPORT_SYMBOL(lnet_notify);

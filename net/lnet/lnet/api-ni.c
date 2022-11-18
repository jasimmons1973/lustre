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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <linux/log2.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/sched/signal.h>
#include <net/genetlink.h>

#include <linux/lnet/udsp.h>
#include <linux/lnet/lib-lnet.h>
#include <uapi/linux/lnet/lnet-dlc.h>

#define D_LNI D_CONSOLE

/*
 * initialize ln_api_mutex statically, since it needs to be used in
 * discovery_set callback. That module parameter callback can be called
 * before module init completes. The mutex needs to be ready for use then.
 */
struct lnet the_lnet = {
	.ln_api_mutex		= __MUTEX_INITIALIZER(the_lnet.ln_api_mutex),
};		/* THE state of the network */
EXPORT_SYMBOL(the_lnet);

static char *ip2nets = "";
module_param(ip2nets, charp, 0444);
MODULE_PARM_DESC(ip2nets, "LNET network <- IP table");

static char *networks = "";
module_param(networks, charp, 0444);
MODULE_PARM_DESC(networks, "local networks");

static char *routes = "";
module_param(routes, charp, 0444);
MODULE_PARM_DESC(routes, "routes to non-local networks");

static int rnet_htable_size = LNET_REMOTE_NETS_HASH_DEFAULT;
module_param(rnet_htable_size, int, 0444);
MODULE_PARM_DESC(rnet_htable_size, "size of remote network hash table");

static int use_tcp_bonding;
module_param(use_tcp_bonding, int, 0444);
MODULE_PARM_DESC(use_tcp_bonding,
		 "use_tcp_bonding parameter has been removed");

unsigned int lnet_numa_range;
EXPORT_SYMBOL(lnet_numa_range);
module_param(lnet_numa_range, uint, 0444);
MODULE_PARM_DESC(lnet_numa_range,
		 "NUMA range to consider during Multi-Rail selection");

/* lnet_health_sensitivity determines by how much we decrement the health
 * value on sending error. The value defaults to 100, which means health
 * interface health is decremented by 100 points every failure.
 */
unsigned int lnet_health_sensitivity = 100;
static int sensitivity_set(const char *val, const struct kernel_param *kp);
static struct kernel_param_ops param_ops_health_sensitivity = {
	.set = sensitivity_set,
	.get = param_get_int,
};

#define param_check_health_sensitivity(name, p) \
	__param_check(name, p, int)
module_param(lnet_health_sensitivity, health_sensitivity, 0644);
MODULE_PARM_DESC(lnet_health_sensitivity,
		 "Value to decrement the health value by on error");

/* lnet_recovery_interval determines how often we should perform recovery
 * on unhealthy interfaces.
 */
unsigned int lnet_recovery_interval = 1;
static int recovery_interval_set(const char *val,
				 const struct kernel_param *kp);
static struct kernel_param_ops param_ops_recovery_interval = {
	.set = recovery_interval_set,
	.get = param_get_int,
};

#define param_check_recovery_interval(name, p) \
		__param_check(name, p, int)
module_param(lnet_recovery_interval, recovery_interval, 0644);
MODULE_PARM_DESC(lnet_recovery_interval,
		 "DEPRECATED Interval to recover unhealthy interfaces in seconds");

unsigned int lnet_recovery_limit;
module_param(lnet_recovery_limit, uint, 0644);
MODULE_PARM_DESC(lnet_recovery_limit,
		 "How long to attempt recovery of unhealthy peer interfaces in seconds. Set to 0 to allow indefinite recovery");

unsigned int lnet_max_recovery_ping_interval = 900;
unsigned int lnet_max_recovery_ping_count = 9;
static int max_recovery_ping_interval_set(const char *val,
					  const struct kernel_param *kp);

#define param_check_max_recovery_ping_interval(name, p) \
		__param_check(name, p, int)

static struct kernel_param_ops param_ops_max_recovery_ping_interval = {
	.set = max_recovery_ping_interval_set,
	.get = param_get_int,
};
module_param(lnet_max_recovery_ping_interval, max_recovery_ping_interval, 0644);
MODULE_PARM_DESC(lnet_max_recovery_ping_interval,
		 "The max interval between LNet recovery pings, in seconds");

static int lnet_interfaces_max = LNET_INTERFACES_MAX_DEFAULT;
static int intf_max_set(const char *val, const struct kernel_param *kp);
module_param_call(lnet_interfaces_max, intf_max_set, param_get_int,
		  &lnet_interfaces_max, 0644);
MODULE_PARM_DESC(lnet_interfaces_max,
		 "Maximum number of interfaces in a node.");

unsigned int lnet_peer_discovery_disabled;
static int discovery_set(const char *val, const struct kernel_param *kp);
module_param_call(lnet_peer_discovery_disabled, discovery_set, param_get_int,
		  &lnet_peer_discovery_disabled, 0644);
MODULE_PARM_DESC(lnet_peer_discovery_disabled,
		 "Set to 1 to disable peer discovery on this node.");

unsigned int lnet_drop_asym_route;
static int drop_asym_route_set(const char *val, const struct kernel_param *kp);

static struct kernel_param_ops param_ops_drop_asym_route = {
	.set = drop_asym_route_set,
	.get = param_get_int,
};

#define param_check_drop_asym_route(name, p)	\
	__param_check(name, p, int)
module_param(lnet_drop_asym_route, drop_asym_route, 0644);
MODULE_PARM_DESC(lnet_drop_asym_route,
		 "Set to 1 to drop asymmetrical route messages.");

#define LNET_TRANSACTION_TIMEOUT_DEFAULT 50
unsigned int lnet_transaction_timeout = LNET_TRANSACTION_TIMEOUT_DEFAULT;
static int transaction_to_set(const char *val, const struct kernel_param *kp);
static struct kernel_param_ops param_ops_transaction_timeout = {
	.set = transaction_to_set,
	.get = param_get_int,
};

#define param_check_transaction_timeout(name, p) \
		__param_check(name, p, int)
module_param(lnet_transaction_timeout, transaction_timeout, 0644);
MODULE_PARM_DESC(lnet_transaction_timeout,
		 "Maximum number of seconds to wait for a peer response.");

#define LNET_RETRY_COUNT_DEFAULT 2
unsigned int lnet_retry_count = LNET_RETRY_COUNT_DEFAULT;
static int retry_count_set(const char *val, const struct kernel_param *kp);
static struct kernel_param_ops param_ops_retry_count = {
	.set = retry_count_set,
	.get = param_get_int,
};

#define param_check_retry_count(name, p) \
		__param_check(name, p, int)
module_param(lnet_retry_count, retry_count, 0644);
MODULE_PARM_DESC(lnet_retry_count,
		 "Maximum number of times to retry transmitting a message");

unsigned int lnet_response_tracking = 3;
static int response_tracking_set(const char *val,
				 const struct kernel_param *kp);
static struct kernel_param_ops param_ops_response_tracking = {
	.set = response_tracking_set,
	.get = param_get_int,
};

#define param_check_response_tracking(name, p)  \
		__param_check(name, p, int)
module_param(lnet_response_tracking, response_tracking, 0644);
MODULE_PARM_DESC(lnet_response_tracking,
		 "(0|1|2|3) LNet Internal Only|GET Reply only|PUT ACK only|Full Tracking (default)");

#define LNET_LND_TIMEOUT_DEFAULT ((LNET_TRANSACTION_TIMEOUT_DEFAULT - 1) / \
				  (LNET_RETRY_COUNT_DEFAULT + 1))
unsigned int lnet_lnd_timeout = LNET_LND_TIMEOUT_DEFAULT;
static void lnet_set_lnd_timeout(void)
{
	lnet_lnd_timeout = (lnet_transaction_timeout - 1) /
			   (lnet_retry_count + 1);
}

/*
 * This sequence number keeps track of how many times DLC was used to
 * update the local NIs. It is incremented when a NI is added or
 * removed and checked when sending a message to determine if there is
 * a need to re-run the selection algorithm. See lnet_select_pathway()
 * for more details on its usage.
 */
static atomic_t lnet_dlc_seq_no = ATOMIC_INIT(0);

static int lnet_ping(struct lnet_process_id id4, struct lnet_nid *src_nid,
		     signed long timeout, struct lnet_process_id __user *ids,
		     int n_ids);

static int lnet_discover(struct lnet_process_id id, u32 force,
			 struct lnet_process_id __user *ids, int n_ids);

static int
sensitivity_set(const char *val, const struct kernel_param *kp)
{
	int rc;
	unsigned int *sensitivity = (unsigned int *)kp->arg;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_health_sensitivity'\n");
		return rc;
	}

	/* The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (value > LNET_MAX_HEALTH_VALUE) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		CERROR("Invalid health value. Maximum: %d value = %lu\n",
		       LNET_MAX_HEALTH_VALUE, value);
		return -EINVAL;
	}

	if (*sensitivity != 0 && value == 0 && lnet_retry_count != 0) {
		lnet_retry_count = 0;
		lnet_set_lnd_timeout();
	}

	*sensitivity = value;

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
recovery_interval_set(const char *val, const struct kernel_param *kp)
{
	CWARN("'lnet_recovery_interval' has been deprecated\n");

	return 0;
}

static int
max_recovery_ping_interval_set(const char *val, const struct kernel_param *kp)
{
	int rc;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_max_recovery_ping_interval'\n");
		return rc;
	}

	if (!value) {
		CERROR("Invalid max ping timeout. Must be strictly positive\n");
		return -EINVAL;
	}

	/* The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);
	lnet_max_recovery_ping_interval = value;
	lnet_max_recovery_ping_count = 0;
	value >>= 1;
	while (value) {
		lnet_max_recovery_ping_count++;
		value >>= 1;
	}
	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
discovery_set(const char *val, const struct kernel_param *kp)
{
	int rc;
	unsigned int *discovery_off = (unsigned int *)kp->arg;
	unsigned long value;
	struct lnet_ping_buffer *pbuf;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_peer_discovery_disabled'\n");
		return rc;
	}

	value = !!value;

	/*
	 * The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (value == *discovery_off) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	/* We still want to set the discovery value even when LNet is not
	 * running. This is the case when LNet is being loaded and we want
	 * the module parameters to take effect. Otherwise if we're
	 * changing the value dynamically, we want to set it after
	 * updating the peers
	 */
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		*discovery_off = value;
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	/* tell peers that discovery setting has changed */
	lnet_net_lock(LNET_LOCK_EX);
	pbuf = the_lnet.ln_ping_target;
	if (value)
		pbuf->pb_info.pi_features &= ~LNET_PING_FEAT_DISCOVERY;
	else
		pbuf->pb_info.pi_features |= LNET_PING_FEAT_DISCOVERY;
	lnet_net_unlock(LNET_LOCK_EX);

	/* only send a push when we're turning off discovery */
	if (*discovery_off <= 0 && value > 0)
		lnet_push_update_to_peers(1);
	*discovery_off = value;

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
drop_asym_route_set(const char *val, const struct kernel_param *kp)
{
	int rc;
	unsigned int *drop_asym_route = (unsigned int *)kp->arg;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_drop_asym_route'\n");
		return rc;
	}

	/* The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (value == *drop_asym_route) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	*drop_asym_route = value;

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
transaction_to_set(const char *val, const struct kernel_param *kp)
{
	unsigned int *transaction_to = (unsigned int *)kp->arg;
	unsigned long value;
	int rc;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_transaction_timeout'\n");
		return rc;
	}

	/* The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (value <= lnet_retry_count || value == 0) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		CERROR("Invalid value for lnet_transaction_timeout (%lu). Has to be greater than lnet_retry_count (%u)\n",
		       value, lnet_retry_count);
		return -EINVAL;
	}

	if (value == *transaction_to) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	*transaction_to = value;
	/* Update the lnet_lnd_timeout now that we've modified the
	 * transaction timeout
	 */
	lnet_set_lnd_timeout();

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
retry_count_set(const char *val, const struct kernel_param *kp)
{
	int rc;
	unsigned int *retry_count = (unsigned int *)kp->arg;
	unsigned long value;

	rc = kstrtoul(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_retry_count'\n");
		return rc;
	}

	/* The purpose of locking the api_mutex here is to ensure that
	 * the correct value ends up stored properly.
	 */
	mutex_lock(&the_lnet.ln_api_mutex);

	if (lnet_health_sensitivity == 0 && value > 0) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		CERROR("Can not set lnet_retry_count when health feature is turned off\n");
		return -EINVAL;
	}

	if (value > lnet_transaction_timeout) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		CERROR("Invalid value for lnet_retry_count (%lu). Has to be smaller than lnet_transaction_timeout (%u)\n",
		       value, lnet_transaction_timeout);
		return -EINVAL;
	}

	*retry_count = value;

	/* Update the lnet_lnd_timeout now that we've modified the
	 * transaction timeout
	 */
	lnet_set_lnd_timeout();

	mutex_unlock(&the_lnet.ln_api_mutex);

	return 0;
}

static int
intf_max_set(const char *val, const struct kernel_param *kp)
{
	int value, rc;

	rc = kstrtoint(val, 0, &value);
	if (rc) {
		CERROR("Invalid module parameter value for 'lnet_interfaces_max'\n");
		return rc;
	}

	if (value < LNET_INTERFACES_MIN) {
		CWARN("max interfaces provided are too small, setting to %d\n",
		      LNET_INTERFACES_MAX_DEFAULT);
		value = LNET_INTERFACES_MAX_DEFAULT;
	}

	*(int *)kp->arg = value;

	return 0;
}

static int
response_tracking_set(const char *val, const struct kernel_param *kp)
{
	int rc;
	unsigned long new_value;

	rc = kstrtoul(val, 0, &new_value);
	if (rc) {
		CERROR("Invalid value for 'lnet_response_tracking'\n");
		return -EINVAL;
	}

	if (new_value < 0 || new_value > 3) {
		CWARN("Invalid value (%lu) for 'lnet_response_tracking'\n",
		      new_value);
		return -EINVAL;
	}

	lnet_response_tracking = new_value;

	return 0;
}

static const char *
lnet_get_routes(void)
{
	return routes;
}

static const char *
lnet_get_networks(void)
{
	const char *nets;
	int rc;

	if (*networks && *ip2nets) {
		LCONSOLE_ERROR_MSG(0x101, "Please specify EITHER 'networks' or 'ip2nets' but not both at once\n");
		return NULL;
	}

	if (*ip2nets) {
		rc = lnet_parse_ip2nets(&nets, ip2nets);
		return !rc ? nets : NULL;
	}

	if (*networks)
		return networks;

	return "tcp";
}

static void
lnet_init_locks(void)
{
	spin_lock_init(&the_lnet.ln_eq_wait_lock);
	spin_lock_init(&the_lnet.ln_msg_resend_lock);
	init_completion(&the_lnet.ln_mt_wait_complete);
	mutex_init(&the_lnet.ln_lnd_mutex);
}

struct kmem_cache *lnet_mes_cachep;	   /* MEs kmem_cache */
struct kmem_cache *lnet_small_mds_cachep;  /* <= LNET_SMALL_MD_SIZE bytes
					    *  MDs kmem_cache
					    */
struct kmem_cache *lnet_udsp_cachep;	   /* udsp cache */
struct kmem_cache *lnet_rspt_cachep;	   /* response tracker cache */
struct kmem_cache *lnet_msg_cachep;

static int
lnet_slab_setup(void)
{
	/* create specific kmem_cache for MEs and small MDs (i.e., originally
	 * allocated in <size-xxx> kmem_cache).
	 */
	lnet_mes_cachep = kmem_cache_create("lnet_MEs", sizeof(struct lnet_me),
					    0, 0, NULL);
	if (!lnet_mes_cachep)
		return -ENOMEM;

	lnet_small_mds_cachep = kmem_cache_create("lnet_small_MDs",
						  LNET_SMALL_MD_SIZE, 0, 0,
						  NULL);
	if (!lnet_small_mds_cachep)
		return -ENOMEM;

	lnet_udsp_cachep = kmem_cache_create("lnet_udsp",
					     sizeof(struct lnet_udsp),
					     0, 0, NULL);
	if (!lnet_udsp_cachep)
		return -ENOMEM;

	lnet_rspt_cachep = kmem_cache_create("lnet_rspt",
					     sizeof(struct lnet_rsp_tracker),
					     0, 0, NULL);
	if (!lnet_rspt_cachep)
		return -ENOMEM;

	lnet_msg_cachep = kmem_cache_create("lnet_msg",
					    sizeof(struct lnet_msg),
					    0, 0, NULL);
	if (!lnet_msg_cachep)
		return -ENOMEM;

	return 0;
}

static void
lnet_slab_cleanup(void)
{
	kmem_cache_destroy(lnet_msg_cachep);
	lnet_msg_cachep = NULL;

	kmem_cache_destroy(lnet_rspt_cachep);
	lnet_rspt_cachep = NULL;

	kmem_cache_destroy(lnet_udsp_cachep);
	lnet_udsp_cachep = NULL;

	kmem_cache_destroy(lnet_small_mds_cachep);
	lnet_small_mds_cachep = NULL;

	kmem_cache_destroy(lnet_mes_cachep);
	lnet_mes_cachep = NULL;
}

static int
lnet_create_remote_nets_table(void)
{
	int i;
	struct list_head *hash;

	LASSERT(!the_lnet.ln_remote_nets_hash);
	LASSERT(the_lnet.ln_remote_nets_hbits > 0);
	hash = kvmalloc_array(LNET_REMOTE_NETS_HASH_SIZE, sizeof(*hash),
			      GFP_KERNEL);
	if (!hash) {
		CERROR("Failed to create remote nets hash table\n");
		return -ENOMEM;
	}

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++)
		INIT_LIST_HEAD(&hash[i]);
	the_lnet.ln_remote_nets_hash = hash;
	return 0;
}

static void
lnet_destroy_remote_nets_table(void)
{
	int i;

	if (!the_lnet.ln_remote_nets_hash)
		return;

	for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE; i++)
		LASSERT(list_empty(&the_lnet.ln_remote_nets_hash[i]));

	kvfree(the_lnet.ln_remote_nets_hash);
	the_lnet.ln_remote_nets_hash = NULL;
}

static void
lnet_destroy_locks(void)
{
	if (the_lnet.ln_res_lock) {
		cfs_percpt_lock_free(the_lnet.ln_res_lock);
		the_lnet.ln_res_lock = NULL;
	}

	if (the_lnet.ln_net_lock) {
		cfs_percpt_lock_free(the_lnet.ln_net_lock);
		the_lnet.ln_net_lock = NULL;
	}
}

static int
lnet_create_locks(void)
{
	lnet_init_locks();

	the_lnet.ln_res_lock = cfs_percpt_lock_alloc(lnet_cpt_table());
	if (!the_lnet.ln_res_lock)
		goto failed;

	the_lnet.ln_net_lock = cfs_percpt_lock_alloc(lnet_cpt_table());
	if (!the_lnet.ln_net_lock)
		goto failed;

	return 0;

failed:
	lnet_destroy_locks();
	return -ENOMEM;
}

static void lnet_assert_wire_constants(void)
{
	/*
	 * Wire protocol assertions generated by 'wirecheck'
	 * running on Linux robert.bartonsoftware.com 2.6.8-1.521
	 * #1 Mon Aug 16 09:01:18 EDT 2004 i686 athlon i386 GNU/Linux
	 * with gcc version 3.3.3 20040412 (Red Hat Linux 3.3.3-7)
	 */

	/* Constants... */
	BUILD_BUG_ON(LNET_PROTO_TCP_MAGIC != 0xeebc0ded);
	BUILD_BUG_ON(LNET_PROTO_TCP_VERSION_MAJOR != 1);
	BUILD_BUG_ON(LNET_PROTO_TCP_VERSION_MINOR != 0);
	BUILD_BUG_ON(LNET_MSG_ACK != 0);
	BUILD_BUG_ON(LNET_MSG_PUT != 1);
	BUILD_BUG_ON(LNET_MSG_GET != 2);
	BUILD_BUG_ON(LNET_MSG_REPLY != 3);
	BUILD_BUG_ON(LNET_MSG_HELLO != 4);

	BUILD_BUG_ON((int)sizeof(lnet_nid_t) != 8);
	BUILD_BUG_ON((int)sizeof(lnet_pid_t) != 4);

	/* Checks for struct lnet_nid */
	BUILD_BUG_ON((int)sizeof(struct lnet_nid) != 20);
	BUILD_BUG_ON((int)offsetof(struct lnet_nid, nid_size) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_nid *)0)->nid_size) != 1);
	BUILD_BUG_ON((int)offsetof(struct lnet_nid, nid_type) != 1);
	BUILD_BUG_ON((int)sizeof(((struct lnet_nid *)0)->nid_type) != 1);
	BUILD_BUG_ON((int)offsetof(struct lnet_nid, nid_num) != 2);
	BUILD_BUG_ON((int)sizeof(((struct lnet_nid *)0)->nid_num) != 2);
	BUILD_BUG_ON((int)offsetof(struct lnet_nid, nid_addr) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_nid *)0)->nid_addr) != 16);

	/* Checks for struct lnet_process_id_packed */
	BUILD_BUG_ON((int)sizeof(struct lnet_process_id_packed) != 12);
	BUILD_BUG_ON((int)offsetof(struct lnet_process_id_packed, nid) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_process_id_packed *)0)->nid) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_process_id_packed, pid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_process_id_packed *)0)->pid) != 4);

	/* Checks for struct lnet_handle_wire */
	BUILD_BUG_ON((int)sizeof(struct lnet_handle_wire) != 16);
	BUILD_BUG_ON((int)offsetof(struct lnet_handle_wire, wh_interface_cookie) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_handle_wire *)0)->wh_interface_cookie) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_handle_wire, wh_object_cookie) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_handle_wire *)0)->wh_object_cookie) != 8);

	/* Checks for struct struct lnet_magicversion */
	BUILD_BUG_ON((int)sizeof(struct lnet_magicversion) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_magicversion, magic) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_magicversion *)0)->magic) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_magicversion, version_major) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_magicversion *)0)->version_major) != 2);
	BUILD_BUG_ON((int)offsetof(struct lnet_magicversion, version_minor) != 6);
	BUILD_BUG_ON((int)sizeof(((struct lnet_magicversion *)0)->version_minor) != 2);

	/* Checks for struct _lnet_hdr_nid4 */
	BUILD_BUG_ON((int)sizeof(struct _lnet_hdr_nid4) != 72);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, dest_nid) != 0);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->dest_nid) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, src_nid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->src_nid) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, dest_pid) != 16);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->dest_pid) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, src_pid) != 20);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->src_pid) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, type) != 24);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->type) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, payload_length) != 28);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->payload_length) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg) != 40);

	/* Ack */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.ack.dst_wmd) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.ack.dst_wmd) != 16);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.ack.match_bits) != 48);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.ack.match_bits) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.ack.mlength) != 56);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.ack.mlength) != 4);

	/* Put */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.ack_wmd) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.ack_wmd) != 16);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.match_bits) != 48);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.match_bits) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.hdr_data) != 56);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.hdr_data) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.ptl_index) != 64);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.ptl_index) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.put.offset) != 68);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.put.offset) != 4);

	/* Get */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.return_wmd) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.return_wmd) != 16);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.match_bits) != 48);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.match_bits) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.ptl_index) != 56);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.ptl_index) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.src_offset) != 60);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.src_offset) != 4);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.get.sink_length) != 64);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.get.sink_length) != 4);

	/* Reply */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.reply.dst_wmd) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.reply.dst_wmd) != 16);

	/* Hello */
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.hello.incarnation) != 32);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.hello.incarnation) != 8);
	BUILD_BUG_ON((int)offsetof(struct _lnet_hdr_nid4, msg.hello.type) != 40);
	BUILD_BUG_ON((int)sizeof(((struct _lnet_hdr_nid4 *)0)->msg.hello.type) != 4);

	/* Checks for struct lnet_ni_status and related constants */
	BUILD_BUG_ON(LNET_NI_STATUS_INVALID != 0x00000000);
	BUILD_BUG_ON(LNET_NI_STATUS_UP != 0x15aac0de);
	BUILD_BUG_ON(LNET_NI_STATUS_DOWN != 0xdeadface);

	/* Checks for struct lnet_ni_status */
	BUILD_BUG_ON((int)sizeof(struct lnet_ni_status) != 16);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_status, ns_nid) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_status *)0)->ns_nid) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_status, ns_status) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_status *)0)->ns_status) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_status, ns_msg_size) != 12);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_status *)0)->ns_msg_size) != 4);

	/* Checks for struct lnet_ni_large_status */
	BUILD_BUG_ON((int)sizeof(struct lnet_ni_large_status) != 24);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_large_status, ns_status) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_large_status *)0)->ns_status) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ni_large_status, ns_nid) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ni_large_status *)0)->ns_nid) != 20);

	/* Checks for struct lnet_ping_info and related constants */
	BUILD_BUG_ON(LNET_PROTO_PING_MAGIC != 0x70696E67);
	BUILD_BUG_ON(LNET_PING_FEAT_INVAL != 0);
	BUILD_BUG_ON(LNET_PING_FEAT_BASE != 1);
	BUILD_BUG_ON(LNET_PING_FEAT_NI_STATUS != 2);
	BUILD_BUG_ON(LNET_PING_FEAT_RTE_DISABLED != 4);
	BUILD_BUG_ON(LNET_PING_FEAT_MULTI_RAIL != 8);
	BUILD_BUG_ON(LNET_PING_FEAT_DISCOVERY != 16);
	BUILD_BUG_ON(LNET_PING_FEAT_LARGE_ADDR != 32);
	BUILD_BUG_ON(LNET_PING_FEAT_PRIMARY_LARGE != 64);
	BUILD_BUG_ON(LNET_PING_FEAT_BITS != 127);

	/* Checks for struct lnet_ping_info */
	BUILD_BUG_ON((int)sizeof(struct lnet_ping_info) != 16);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_magic) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_magic) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_features) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_features)
		     != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_pid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_pid) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_nnis) != 12);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_nnis) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_ping_info, pi_ni) != 16);
	BUILD_BUG_ON((int)sizeof(((struct lnet_ping_info *)0)->pi_ni) != 0);

	/* Acceptor connection request */
	BUILD_BUG_ON(LNET_PROTO_ACCEPTOR_VERSION != 1);

	/* Checks for struct lnet_acceptor_connreq */
	BUILD_BUG_ON((int)sizeof(struct lnet_acceptor_connreq) != 16);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq, acr_magic) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq *)0)->acr_magic) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq, acr_version) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq *)0)->acr_version) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq, acr_nid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq *)0)->acr_nid) != 8);

	/* Checks for struct lnet_acceptor_connreq_v2 */
	BUILD_BUG_ON((int)sizeof(struct lnet_acceptor_connreq_v2) != 28);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq_v2, acr_magic) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq_v2 *)0)->acr_magic) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq_v2, acr_version) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq_v2 *)0)->acr_version) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_acceptor_connreq_v2, acr_nid) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_acceptor_connreq_v2 *)0)->acr_nid) != 20);

	/* Checks for struct lnet_counters_common */
	BUILD_BUG_ON((int)sizeof(struct lnet_counters_common) != 60);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_msgs_alloc) != 0);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_msgs_alloc) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_msgs_max) != 4);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_msgs_max) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_errors) != 8);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_errors) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_send_count) != 12);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_send_count) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_recv_count) != 16);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_recv_count) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_route_count) != 20);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_route_count) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_drop_count) != 24);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_drop_count) != 4);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_send_length) != 28);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_send_length) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_recv_length) != 36);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_recv_length) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_route_length) != 44);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_route_length) != 8);
	BUILD_BUG_ON((int)offsetof(struct lnet_counters_common, lcc_drop_length) != 52);
	BUILD_BUG_ON((int)sizeof(((struct lnet_counters_common *)0)->lcc_drop_length) != 8);
}

static struct lnet_lnd *
lnet_find_lnd_by_type(u32 type)
{
	struct lnet_lnd *lnd;

	/* holding lnd mutex */
	if (type >= NUM_LNDS)
		return NULL;
	lnd = the_lnet.ln_lnds[type];
	LASSERT(!lnd || lnd->lnd_type == type);

	return lnd;
}

unsigned int
lnet_get_lnd_timeout(void)
{
	return lnet_lnd_timeout;
}
EXPORT_SYMBOL(lnet_get_lnd_timeout);

void
lnet_register_lnd(struct lnet_lnd *lnd)
{
	mutex_lock(&the_lnet.ln_lnd_mutex);

	LASSERT(libcfs_isknown_lnd(lnd->lnd_type));
	LASSERT(!lnet_find_lnd_by_type(lnd->lnd_type));

	the_lnet.ln_lnds[lnd->lnd_type] = lnd;

	CDEBUG(D_NET, "%s LND registered\n", libcfs_lnd2str(lnd->lnd_type));

	mutex_unlock(&the_lnet.ln_lnd_mutex);
}
EXPORT_SYMBOL(lnet_register_lnd);

void
lnet_unregister_lnd(struct lnet_lnd *lnd)
{
	mutex_lock(&the_lnet.ln_lnd_mutex);

	LASSERT(lnet_find_lnd_by_type(lnd->lnd_type) == lnd);

	the_lnet.ln_lnds[lnd->lnd_type] = NULL;
	CDEBUG(D_NET, "%s LND unregistered\n", libcfs_lnd2str(lnd->lnd_type));

	mutex_unlock(&the_lnet.ln_lnd_mutex);
}
EXPORT_SYMBOL(lnet_unregister_lnd);

static void
lnet_counters_get_common_locked(struct lnet_counters_common *common)
{
	struct lnet_counters *ctr;
	int i;

	/* FIXME !!! Their is no assert_lnet_net_locked() to ensure this
	 * actually called under the protection of the lnet_net_lock.
	 */
	memset(common, 0, sizeof(*common));

	cfs_percpt_for_each(ctr, i, the_lnet.ln_counters) {
		common->lcc_msgs_max	 += ctr->lct_common.lcc_msgs_max;
		common->lcc_msgs_alloc   += ctr->lct_common.lcc_msgs_alloc;
		common->lcc_errors       += ctr->lct_common.lcc_errors;
		common->lcc_send_count   += ctr->lct_common.lcc_send_count;
		common->lcc_recv_count   += ctr->lct_common.lcc_recv_count;
		common->lcc_route_count  += ctr->lct_common.lcc_route_count;
		common->lcc_drop_count   += ctr->lct_common.lcc_drop_count;
		common->lcc_send_length  += ctr->lct_common.lcc_send_length;
		common->lcc_recv_length  += ctr->lct_common.lcc_recv_length;
		common->lcc_route_length += ctr->lct_common.lcc_route_length;
		common->lcc_drop_length  += ctr->lct_common.lcc_drop_length;
	}
}

void
lnet_counters_get_common(struct lnet_counters_common *common)
{
	lnet_net_lock(LNET_LOCK_EX);
	lnet_counters_get_common_locked(common);
	lnet_net_unlock(LNET_LOCK_EX);
}
EXPORT_SYMBOL(lnet_counters_get_common);

int
lnet_counters_get(struct lnet_counters *counters)
{
	struct lnet_counters *ctr;
	struct lnet_counters_health *health = &counters->lct_health;
	int i, rc = 0;

	memset(counters, 0, sizeof(*counters));

	lnet_net_lock(LNET_LOCK_EX);

	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ENODEV;
		goto out_unlock;
	}

	lnet_counters_get_common_locked(&counters->lct_common);

	cfs_percpt_for_each(ctr, i, the_lnet.ln_counters) {
		health->lch_rst_alloc += ctr->lct_health.lch_rst_alloc;
		health->lch_resend_count += ctr->lct_health.lch_resend_count;
		health->lch_response_timeout_count +=
				ctr->lct_health.lch_response_timeout_count;
		health->lch_local_interrupt_count +=
				ctr->lct_health.lch_local_interrupt_count;
		health->lch_local_dropped_count +=
				ctr->lct_health.lch_local_dropped_count;
		health->lch_local_aborted_count +=
				ctr->lct_health.lch_local_aborted_count;
		health->lch_local_no_route_count +=
				ctr->lct_health.lch_local_no_route_count;
		health->lch_local_timeout_count +=
				ctr->lct_health.lch_local_timeout_count;
		health->lch_local_error_count +=
				ctr->lct_health.lch_local_error_count;
		health->lch_remote_dropped_count +=
				ctr->lct_health.lch_remote_dropped_count;
		health->lch_remote_error_count +=
				ctr->lct_health.lch_remote_error_count;
		health->lch_remote_timeout_count +=
				ctr->lct_health.lch_remote_timeout_count;
		health->lch_network_timeout_count +=
				ctr->lct_health.lch_network_timeout_count;
	}
out_unlock:
	lnet_net_unlock(LNET_LOCK_EX);
	return rc;
}
EXPORT_SYMBOL(lnet_counters_get);

void
lnet_counters_reset(void)
{
	struct lnet_counters *counters;
	int i;

	lnet_net_lock(LNET_LOCK_EX);

	if (the_lnet.ln_state != LNET_STATE_RUNNING)
		goto avoid_reset;

	cfs_percpt_for_each(counters, i, the_lnet.ln_counters)
		memset(counters, 0, sizeof(struct lnet_counters));
avoid_reset:
	lnet_net_unlock(LNET_LOCK_EX);
}

static char *
lnet_res_type2str(int type)
{
	switch (type) {
	default:
		LBUG();
	case LNET_COOKIE_TYPE_MD:
		return "MD";
	case LNET_COOKIE_TYPE_ME:
		return "ME";
	case LNET_COOKIE_TYPE_EQ:
		return "EQ";
	}
}

static void
lnet_res_container_cleanup(struct lnet_res_container *rec)
{
	int count = 0;

	if (!rec->rec_type) /* not set yet, it's uninitialized */
		return;

	while (!list_empty(&rec->rec_active)) {
		struct list_head *e = rec->rec_active.next;

		list_del_init(e);
		if (rec->rec_type == LNET_COOKIE_TYPE_MD)
			lnet_md_free(list_entry(e, struct lnet_libmd, md_list));
		else /* NB: Active MEs should be attached on portals */
			LBUG();
		count++;
	}

	if (count > 0) {
		/*
		 * Found alive MD/ME/EQ, user really should unlink/free
		 * all of them before finalize LNet, but if someone didn't,
		 * we have to recycle garbage for him
		 */
		CERROR("%d active elements on exit of %s container\n",
		       count, lnet_res_type2str(rec->rec_type));
	}

	kfree(rec->rec_lh_hash);
	rec->rec_lh_hash = NULL;

	rec->rec_type = 0; /* mark it as finalized */
}

static int
lnet_res_container_setup(struct lnet_res_container *rec, int cpt, int type)
{
	int rc = 0;
	int i;

	LASSERT(!rec->rec_type);

	rec->rec_type = type;
	INIT_LIST_HEAD(&rec->rec_active);
	rec->rec_lh_cookie = (cpt << LNET_COOKIE_TYPE_BITS) | type;

	/* Arbitrary choice of hash table size */
	rec->rec_lh_hash = kvmalloc_cpt(LNET_LH_HASH_SIZE * sizeof(rec->rec_lh_hash[0]),
					GFP_KERNEL, cpt);
	if (!rec->rec_lh_hash) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < LNET_LH_HASH_SIZE; i++)
		INIT_LIST_HEAD(&rec->rec_lh_hash[i]);

	return 0;

out:
	CERROR("Failed to setup %s resource container\n",
	       lnet_res_type2str(type));
	lnet_res_container_cleanup(rec);
	return rc;
}

static void
lnet_res_containers_destroy(struct lnet_res_container **recs)
{
	struct lnet_res_container *rec;
	int i;

	cfs_percpt_for_each(rec, i, recs)
		lnet_res_container_cleanup(rec);

	cfs_percpt_free(recs);
}

static struct lnet_res_container **
lnet_res_containers_create(int type)
{
	struct lnet_res_container **recs;
	struct lnet_res_container *rec;
	int rc;
	int i;

	recs = cfs_percpt_alloc(lnet_cpt_table(), sizeof(*recs[0]));
	if (!recs) {
		CERROR("Failed to allocate %s resource containers\n",
		       lnet_res_type2str(type));
		return NULL;
	}

	cfs_percpt_for_each(rec, i, recs) {
		rc = lnet_res_container_setup(rec, i, type);
		if (rc) {
			lnet_res_containers_destroy(recs);
			return NULL;
		}
	}

	return recs;
}

struct lnet_libhandle *
lnet_res_lh_lookup(struct lnet_res_container *rec, u64 cookie)
{
	/* ALWAYS called with lnet_res_lock held */
	struct list_head *head;
	struct lnet_libhandle *lh;
	unsigned int hash;

	if ((cookie & LNET_COOKIE_MASK) != rec->rec_type)
		return NULL;

	hash = cookie >> (LNET_COOKIE_TYPE_BITS + LNET_CPT_BITS);
	head = &rec->rec_lh_hash[hash & LNET_LH_HASH_MASK];

	list_for_each_entry(lh, head, lh_hash_chain) {
		if (lh->lh_cookie == cookie)
			return lh;
	}

	return NULL;
}

void
lnet_res_lh_initialize(struct lnet_res_container *rec,
		       struct lnet_libhandle *lh)
{
	/* ALWAYS called with lnet_res_lock held */
	unsigned int ibits = LNET_COOKIE_TYPE_BITS + LNET_CPT_BITS;
	unsigned int hash;

	lh->lh_cookie = rec->rec_lh_cookie;
	rec->rec_lh_cookie += 1 << ibits;

	hash = (lh->lh_cookie >> ibits) & LNET_LH_HASH_MASK;

	list_add(&lh->lh_hash_chain, &rec->rec_lh_hash[hash]);
}

struct list_head **
lnet_create_array_of_queues(void)
{
	struct list_head **qs;
	struct list_head *q;
	int i;

	qs = cfs_percpt_alloc(lnet_cpt_table(), sizeof(*qs[0]));
	if (!qs) {
		CERROR("Failed to allocate queues\n");
		return NULL;
	}

	cfs_percpt_for_each(q, i, qs)
		INIT_LIST_HEAD(q);

	return qs;
}

static int lnet_unprepare(void);

static int
lnet_prepare(lnet_pid_t requested_pid)
{
	/* Prepare to bring up the network */
	struct lnet_res_container **recs;
	int rc = 0;

	if (requested_pid == LNET_PID_ANY) {
		/* Don't instantiate LNET just for me */
		return -ENETDOWN;
	}

	LASSERT(!the_lnet.ln_refcount);

	the_lnet.ln_routing = 0;

	LASSERT(!(requested_pid & LNET_PID_USERFLAG));
	the_lnet.ln_pid = requested_pid;

	INIT_LIST_HEAD(&the_lnet.ln_test_peers);
	INIT_LIST_HEAD(&the_lnet.ln_remote_peer_ni_list);
	INIT_LIST_HEAD(&the_lnet.ln_nets);
	INIT_LIST_HEAD(&the_lnet.ln_routers);
	INIT_LIST_HEAD(&the_lnet.ln_drop_rules);
	INIT_LIST_HEAD(&the_lnet.ln_delay_rules);
	INIT_LIST_HEAD(&the_lnet.ln_dc_request);
	INIT_LIST_HEAD(&the_lnet.ln_dc_working);
	INIT_LIST_HEAD(&the_lnet.ln_dc_expired);
	INIT_LIST_HEAD(&the_lnet.ln_mt_localNIRecovq);
	INIT_LIST_HEAD(&the_lnet.ln_mt_peerNIRecovq);
	INIT_LIST_HEAD(&the_lnet.ln_udsp_list);
	init_waitqueue_head(&the_lnet.ln_dc_waitq);
	the_lnet.ln_mt_handler = NULL;
	init_completion(&the_lnet.ln_started);

	rc = lnet_slab_setup();
	if (rc != 0)
		goto failed;

	rc = lnet_create_remote_nets_table();
	if (rc)
		goto failed;
	/*
	 * NB the interface cookie in wire handles guards against delayed
	 * replies and ACKs appearing valid after reboot.
	 */
	the_lnet.ln_interface_cookie = ktime_get_real_ns();

	the_lnet.ln_counters = cfs_percpt_alloc(lnet_cpt_table(),
						sizeof(*the_lnet.ln_counters[0]));
	if (!the_lnet.ln_counters) {
		CERROR("Failed to allocate counters for LNet\n");
		rc = -ENOMEM;
		goto failed;
	}

	rc = lnet_peer_tables_create();
	if (rc)
		goto failed;

	rc = lnet_msg_containers_create();
	if (rc)
		goto failed;

	rc = lnet_res_container_setup(&the_lnet.ln_eq_container, 0,
				      LNET_COOKIE_TYPE_EQ);
	if (rc)
		goto failed;

	recs = lnet_res_containers_create(LNET_COOKIE_TYPE_MD);
	if (!recs) {
		rc = -ENOMEM;
		goto failed;
	}

	the_lnet.ln_md_containers = recs;

	rc = lnet_portals_create();
	if (rc) {
		CERROR("Failed to create portals for LNet: %d\n", rc);
		goto failed;
	}

	the_lnet.ln_mt_zombie_rstqs = lnet_create_array_of_queues();
	if (!the_lnet.ln_mt_zombie_rstqs) {
		rc = -ENOMEM;
		goto failed;
	}

	return 0;

failed:
	lnet_unprepare();
	return rc;
}

static int
lnet_unprepare(void)
{
	/*
	 * NB no LNET_LOCK since this is the last reference.  All LND instances
	 * have shut down already, so it is safe to unlink and free all
	 * descriptors, even those that appear committed to a network op (eg MD
	 * with non-zero pending count)
	 */
	lnet_fail_nid(LNET_NID_ANY, 0);

	LASSERT(!the_lnet.ln_refcount);
	LASSERT(list_empty(&the_lnet.ln_test_peers));
	LASSERT(list_empty(&the_lnet.ln_nets));

	if (the_lnet.ln_mt_zombie_rstqs) {
		lnet_clean_zombie_rstqs();
		the_lnet.ln_mt_zombie_rstqs = NULL;
	}

	lnet_assert_handler_unused(the_lnet.ln_mt_handler);
	the_lnet.ln_mt_handler = NULL;

	lnet_portals_destroy();

	if (the_lnet.ln_md_containers) {
		lnet_res_containers_destroy(the_lnet.ln_md_containers);
		the_lnet.ln_md_containers = NULL;
	}

	lnet_res_container_cleanup(&the_lnet.ln_eq_container);

	lnet_msg_containers_destroy();
	lnet_peer_uninit();
	lnet_rtrpools_free(0);

	if (the_lnet.ln_counters) {
		cfs_percpt_free(the_lnet.ln_counters);
		the_lnet.ln_counters = NULL;
	}
	lnet_destroy_remote_nets_table();
	lnet_udsp_destroy(true);
	lnet_slab_cleanup();

	return 0;
}

struct lnet_ni  *
lnet_net2ni_locked(u32 net_id, int cpt)
{
	struct lnet_ni *ni;
	struct lnet_net *net;

	LASSERT(cpt != LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		if (net->net_id == net_id) {
			ni = list_first_entry(&net->net_ni_list, struct lnet_ni,
					      ni_netlist);
			return ni;
		}
	}

	return NULL;
}

struct lnet_ni *
lnet_net2ni_addref(u32 net)
{
	struct lnet_ni *ni;

	lnet_net_lock(0);
	ni = lnet_net2ni_locked(net, 0);
	if (ni)
		lnet_ni_addref_locked(ni, 0);
	lnet_net_unlock(0);

	return ni;
}
EXPORT_SYMBOL(lnet_net2ni_addref);

struct lnet_net *
lnet_get_net_locked(u32 net_id)
{
	struct lnet_net *net;

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		if (net->net_id == net_id)
			return net;
	}

	return NULL;
}

void
lnet_net_clr_pref_rtrs(struct lnet_net *net)
{
	struct list_head zombies;
	struct lnet_nid_list *ne;
	struct lnet_nid_list *tmp;

	INIT_LIST_HEAD(&zombies);

	lnet_net_lock(LNET_LOCK_EX);
	list_splice_init(&net->net_rtr_pref_nids, &zombies);
	lnet_net_unlock(LNET_LOCK_EX);

	list_for_each_entry_safe(ne, tmp, &zombies, nl_list) {
		list_del_init(&ne->nl_list);
		kfree(ne);
	}
}

int
lnet_net_add_pref_rtr(struct lnet_net *net,
		      struct lnet_nid *gw_nid)
__must_hold(&the_lnet.ln_api_mutex)
{
	struct lnet_nid_list *ne;

	/* This function is called with api_mutex held. When the api_mutex
	 * is held the list can not be modified, as it is only modified as
	 * a result of applying a UDSP and that happens under api_mutex
	 * lock.
	 */
	list_for_each_entry(ne, &net->net_rtr_pref_nids, nl_list) {
		if (nid_same(&ne->nl_nid, gw_nid))
			return -EEXIST;
	}

	ne = kzalloc(sizeof(*ne), GFP_KERNEL);
	if (!ne)
		return -ENOMEM;

	ne->nl_nid = *gw_nid;

	/* Lock the cpt to protect against addition and checks in the
	 * selection algorithm
	 */
	lnet_net_lock(LNET_LOCK_EX);
	list_add(&ne->nl_list, &net->net_rtr_pref_nids);
	lnet_net_unlock(LNET_LOCK_EX);

	return 0;
}

bool
lnet_net_is_pref_rtr_locked(struct lnet_net *net, struct lnet_nid *rtr_nid)
{
	struct lnet_nid_list *ne;

	CDEBUG(D_NET, "%s: rtr pref empty: %d\n",
	       libcfs_net2str(net->net_id),
	       list_empty(&net->net_rtr_pref_nids));

	if (list_empty(&net->net_rtr_pref_nids))
		return false;

	list_for_each_entry(ne, &net->net_rtr_pref_nids, nl_list) {
		CDEBUG(D_NET, "Comparing pref %s with gw %s\n",
		       libcfs_nidstr(&ne->nl_nid),
		       libcfs_nidstr(rtr_nid));
		if (nid_same(rtr_nid, &ne->nl_nid))
			return true;
	}

	return false;
}

static unsigned int
lnet_nid4_cpt_hash(lnet_nid_t nid, unsigned int number)
{
	u64 key = nid;
	u64 pair_bits = 0x0001000100010001LLU;
	u64 mask = pair_bits * 0xFF;
	u64 pair_sum;

	/* Use (sum-by-multiplication of nid bytes) mod (number of CPTs)
	 * to match nid to a CPT.
	 */
	pair_sum = (key & mask) + ((key >> 8) & mask);
	pair_sum = (pair_sum * pair_bits) >> 48;

	CDEBUG(D_NET, "Match nid %s to cpt %u\n",
	       libcfs_nid2str(nid), (unsigned int)(pair_sum) % number);

	return (unsigned int)(pair_sum) % number;
}

unsigned int
lnet_nid_cpt_hash(struct lnet_nid *nid, unsigned int number)
{
	unsigned int val;
	u32 h = 0;
	int i;

	LASSERT(number >= 1 && number <= LNET_CPT_NUMBER);

	if (number == 1)
		return 0;

	if (nid_is_nid4(nid))
		return lnet_nid4_cpt_hash(lnet_nid_to_nid4(nid), number);

	for (i = 0; i < 4; i++)
		h = hash_32(nid->nid_addr[i] ^ h, 32);
	val = hash_32(LNET_NID_NET(nid) ^ h, LNET_CPT_BITS);
	if (val < number)
		return val;
	return (unsigned int)(h + val + (val >> 1)) % number;
}

int
lnet_cpt_of_nid_locked(struct lnet_nid *nid, struct lnet_ni *ni)
{
	struct lnet_net *net;

	/* must called with hold of lnet_net_lock */
	if (LNET_CPT_NUMBER == 1)
		return 0; /* the only one */

	/*
	 * If NI is provided then use the CPT identified in the NI cpt
	 * list if one exists. If one doesn't exist, then that NI is
	 * associated with all CPTs and it follows that the net it belongs
	 * to is implicitly associated with all CPTs, so just hash the nid
	 * and return that.
	 */
	if (ni) {
		if (ni->ni_cpts)
			return ni->ni_cpts[lnet_nid_cpt_hash(nid,
							     ni->ni_ncpts)];
		else
			return lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);
	}

	/* no NI provided so look at the net */
	net = lnet_get_net_locked(LNET_NID_NET(nid));

	if (net && net->net_cpts)
		return net->net_cpts[lnet_nid_cpt_hash(nid, net->net_ncpts)];

	return lnet_nid_cpt_hash(nid, LNET_CPT_NUMBER);
}

int
lnet_nid2cpt(struct lnet_nid *nid, struct lnet_ni *ni)
{
	int cpt;
	int cpt2;

	if (LNET_CPT_NUMBER == 1)
		return 0; /* the only one */

	cpt = lnet_net_lock_current();

	cpt2 = lnet_cpt_of_nid_locked(nid, ni);

	lnet_net_unlock(cpt);

	return cpt2;
}
EXPORT_SYMBOL(lnet_nid2cpt);

int
lnet_cpt_of_nid(lnet_nid_t nid4, struct lnet_ni *ni)
{
	struct lnet_nid nid;

	if (LNET_CPT_NUMBER == 1)
		return 0; /* the only one */

	lnet_nid4_to_nid(nid4, &nid);
	return lnet_nid2cpt(&nid, ni);
}
EXPORT_SYMBOL(lnet_cpt_of_nid);

int
lnet_islocalnet_locked(u32 net_id)
{
	struct lnet_net *net;

	net = lnet_get_net_locked(net_id);

	return !!net;
}

int
lnet_islocalnet(u32 net_id)
{
	int cpt;
	bool local;

	cpt = lnet_net_lock_current();

	local = lnet_islocalnet_locked(net_id);

	lnet_net_unlock(cpt);

	return local;
}

struct lnet_ni *
lnet_nid_to_ni_locked(struct lnet_nid *nid, int cpt)
{
	struct lnet_net *net;
	struct lnet_ni *ni;

	LASSERT(cpt != LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (nid_same(&ni->ni_nid, nid))
				return ni;
		}
	}

	return NULL;
}

struct lnet_ni  *
lnet_nid2ni_locked(lnet_nid_t nid4, int cpt)
{
	struct lnet_nid nid;

	lnet_nid4_to_nid(nid4, &nid);
	return lnet_nid_to_ni_locked(&nid, cpt);
}

struct lnet_ni *
lnet_nid2ni_addref(lnet_nid_t nid4)
{
	struct lnet_ni *ni;
	struct lnet_nid nid;

	lnet_nid4_to_nid(nid4, &nid);

	lnet_net_lock(0);
	ni = lnet_nid_to_ni_locked(&nid, 0);
	if (ni)
		lnet_ni_addref_locked(ni, 0);
	lnet_net_unlock(0);

	return ni;
}
EXPORT_SYMBOL(lnet_nid2ni_addref);

struct lnet_ni *
lnet_nid_to_ni_addref(struct lnet_nid *nid)
{
	struct lnet_ni *ni;

	lnet_net_lock(0);
	ni = lnet_nid_to_ni_locked(nid, 0);
	if (ni)
		lnet_ni_addref_locked(ni, 0);
	lnet_net_unlock(0);

	return ni;
}
EXPORT_SYMBOL(lnet_nid_to_ni_addref);

int
lnet_islocalnid(struct lnet_nid *nid)
{
	struct lnet_ni	*ni;
	int		cpt;

	cpt = lnet_net_lock_current();
	ni = lnet_nid_to_ni_locked(nid, cpt);
	lnet_net_unlock(cpt);

	return ni != NULL;
}

int
lnet_count_acceptor_nets(void)
{
	/* Return the # of NIs that need the acceptor. */
	int count = 0;
	struct lnet_net *net;
	int cpt;

	cpt = lnet_net_lock_current();
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		/* all socklnd type networks should have the acceptor
		 * thread started */
		if (net->net_lnd->lnd_accept)
			count++;
	}

	lnet_net_unlock(cpt);

	return count;
}

struct lnet_ping_buffer *
lnet_ping_buffer_alloc(int nbytes, gfp_t gfp)
{
	struct lnet_ping_buffer *pbuf;

	pbuf = kmalloc(LNET_PING_BUFFER_SIZE(nbytes), gfp);
	if (pbuf) {
		pbuf->pb_nbytes = nbytes;	/* sizeof of pb_info */
		pbuf->pb_needs_post = false;
		atomic_set(&pbuf->pb_refcnt, 1);
	}

	return pbuf;
}

void
lnet_ping_buffer_free(struct lnet_ping_buffer *pbuf)
{
	LASSERT(atomic_read(&pbuf->pb_refcnt) == 0);
	kfree(pbuf);
}

static struct lnet_ping_buffer *
lnet_ping_target_create(int nbytes)
{
	struct lnet_ping_buffer *pbuf;

	pbuf = lnet_ping_buffer_alloc(nbytes, GFP_KERNEL);
	if (!pbuf) {
		CERROR("Can't allocate ping source [%d]\n", nbytes);
		return NULL;
	}

	pbuf->pb_info.pi_nnis = 0;
	pbuf->pb_info.pi_pid = the_lnet.ln_pid;
	pbuf->pb_info.pi_magic = LNET_PROTO_PING_MAGIC;
	pbuf->pb_info.pi_features =
		LNET_PING_FEAT_NI_STATUS | LNET_PING_FEAT_MULTI_RAIL;

	return pbuf;
}

static inline int
lnet_get_net_ni_bytes_locked(struct lnet_net *net)
{
	struct lnet_ni *ni;
	int bytes = 0;

	list_for_each_entry(ni, &net->net_ni_list, ni_netlist)
		bytes += lnet_ping_sts_size(&ni->ni_nid);

	return bytes;
}

static inline int
lnet_get_ni_bytes(void)
{
	struct lnet_ni *ni;
	struct lnet_net *net;
	int bytes = 0;

	lnet_net_lock(0);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist)
			bytes += lnet_ping_sts_size(&ni->ni_nid);
	}

	lnet_net_unlock(0);

	return bytes;
}

void
lnet_swap_pinginfo(struct lnet_ping_buffer *pbuf)
{
	struct lnet_ni_large_status *lstat, *lend;
	struct lnet_ni_status *stat, *end;
	int nnis;
	int i;

	__swab32s(&pbuf->pb_info.pi_magic);
	__swab32s(&pbuf->pb_info.pi_features);
	__swab32s(&pbuf->pb_info.pi_pid);
	__swab32s(&pbuf->pb_info.pi_nnis);
	nnis = pbuf->pb_info.pi_nnis;
	stat = &pbuf->pb_info.pi_ni[0];
	end = (void *)&pbuf->pb_info + pbuf->pb_nbytes;
	for (i = 0; i < nnis && stat + 1 <= end; i++, stat++) {
		__swab64s(&stat->ns_nid);
		__swab32s(&stat->ns_status);
		if (i == 0)
			/* Might be total size */
			__swab32s(&stat->ns_msg_size);
	}
	if (!(pbuf->pb_info.pi_features & LNET_PING_FEAT_LARGE_ADDR))
		return;

	lstat = (struct lnet_ni_large_status *)stat;
	lend = (void *)end;
	while (lstat + 1 <= lend) {
		__swab32s(&lstat->ns_status);
		/* struct lnet_nid never needs to be swabed */
		lstat = lnet_ping_sts_next(lstat);
	}
}

int
lnet_ping_info_validate(struct lnet_ping_info *pinfo)
{
	if (!pinfo)
		return -EINVAL;
	if (pinfo->pi_magic != LNET_PROTO_PING_MAGIC)
		return -EPROTO;
	if (!(pinfo->pi_features & LNET_PING_FEAT_NI_STATUS))
		return -EPROTO;
	/* Loopback is guaranteed to be present */
	if (pinfo->pi_nnis < 1 || pinfo->pi_nnis > lnet_interfaces_max)
		return -ERANGE;
	if (LNET_PING_INFO_LONI(pinfo) != LNET_NID_LO_0)
		return -EPROTO;
	return 0;
}

static void
lnet_ping_target_destroy(void)
{
	struct lnet_net *net;
	struct lnet_ni *ni;

	lnet_net_lock(LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			lnet_ni_lock(ni);
			ni->ni_status = NULL;
			lnet_ni_unlock(ni);
		}
	}

	lnet_ping_buffer_decref(the_lnet.ln_ping_target);
	the_lnet.ln_ping_target = NULL;

	lnet_net_unlock(LNET_LOCK_EX);
}

static void
lnet_ping_target_event_handler(struct lnet_event *event)
{
	struct lnet_ping_buffer *pbuf = event->md_user_ptr;

	if (event->unlinked)
		lnet_ping_buffer_decref(pbuf);
}

static int
lnet_ping_target_setup(struct lnet_ping_buffer **ppbuf,
		       struct lnet_handle_md *ping_mdh,
		       int ni_bytes, bool set_eq)
{
	struct lnet_processid id = {
		.nid = LNET_ANY_NID,
		.pid = LNET_PID_ANY
	};
	struct lnet_me *me;
	struct lnet_md md = { NULL };
	int rc;

	if (set_eq)
		the_lnet.ln_ping_target_handler =
			lnet_ping_target_event_handler;

	*ppbuf = lnet_ping_target_create(ni_bytes);
	if (!*ppbuf) {
		rc = -ENOMEM;
		goto fail_free_eq;
	}

	/* Ping target ME/MD */
	me = LNetMEAttach(LNET_RESERVED_PORTAL, &id,
			  LNET_PROTO_PING_MATCHBITS, 0,
			  LNET_UNLINK, LNET_INS_AFTER);
	if (IS_ERR(me)) {
		rc = PTR_ERR(me);
		CERROR("Can't create ping target ME: %d\n", rc);
		goto fail_decref_ping_buffer;
	}

	/* initialize md content */
	md.start = &(*ppbuf)->pb_info;
	md.length = (*ppbuf)->pb_nbytes;
	md.threshold = LNET_MD_THRESH_INF;
	md.max_size = 0;
	md.options = LNET_MD_OP_GET | LNET_MD_TRUNCATE |
		     LNET_MD_MANAGE_REMOTE;
	md.handler = the_lnet.ln_ping_target_handler;
	md.user_ptr = *ppbuf;

	rc = LNetMDAttach(me, &md, LNET_RETAIN, ping_mdh);
	if (rc) {
		CERROR("Can't attach ping target MD: %d\n", rc);
		goto fail_decref_ping_buffer;
	}
	lnet_ping_buffer_addref(*ppbuf);

	return 0;

fail_decref_ping_buffer:
	LASSERT(atomic_read(&(*ppbuf)->pb_refcnt) == 1);
	lnet_ping_buffer_decref(*ppbuf);
	*ppbuf = NULL;
fail_free_eq:
	return rc;
}

static void
lnet_ping_md_unlink(struct lnet_ping_buffer *pbuf,
		    struct lnet_handle_md *ping_mdh)
{
	LNetMDUnlink(*ping_mdh);
	LNetInvalidateMDHandle(ping_mdh);

	/* NB the MD could be busy; this just starts the unlink */
	wait_var_event_warning(&pbuf->pb_refcnt,
			       atomic_read(&pbuf->pb_refcnt) <= 1,
			       "Still waiting for ping data MD to unlink\n");
}

static void
lnet_ping_target_install_locked(struct lnet_ping_buffer *pbuf)
{
	struct lnet_ni_large_status *lns, *lend;
	struct lnet_ni_status *ns, *end;
	struct lnet_ni *ni;
	struct lnet_net *net;
	int rc;

	pbuf->pb_info.pi_nnis = 0;
	ns = &pbuf->pb_info.pi_ni[0];
	end = (void *)&pbuf->pb_info + pbuf->pb_nbytes;
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (!nid_is_nid4(&ni->ni_nid)) {
				if (ns == &pbuf->pb_info.pi_ni[1]) {
					/* This is primary, and it is long */
					pbuf->pb_info.pi_features |=
						LNET_PING_FEAT_PRIMARY_LARGE;
				}
				continue;
			}
			LASSERT(ns + 1 <= end);
			ns->ns_nid = lnet_nid_to_nid4(&ni->ni_nid);

			lnet_ni_lock(ni);
			ns->ns_status = lnet_ni_get_status_locked(ni);
			ni->ni_status = &ns->ns_status;
			lnet_ni_unlock(ni);

			pbuf->pb_info.pi_nnis++;
			ns++;
		}
	}

	lns = (void *)ns;
	lend = (void *)end;
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (nid_is_nid4(&ni->ni_nid))
				continue;
			LASSERT(lns + 1 <= lend);

			lns->ns_nid = ni->ni_nid;

			lnet_ni_lock(ni);
			ns->ns_status = lnet_ni_get_status_locked(ni);
			ni->ni_status = &lns->ns_status;
			lnet_ni_unlock(ni);

			lns = lnet_ping_sts_next(lns);
		}
	}
	if ((void *)lns > (void *)ns) {
		/* Record total info size */
		pbuf->pb_info.pi_ni[0].ns_msg_size =
			(void *)lns - (void *)&pbuf->pb_info;
		pbuf->pb_info.pi_features |= LNET_PING_FEAT_LARGE_ADDR;
	}

	/* We (ab)use the ns_status of the loopback interface to
	 * transmit the sequence number. The first interface listed
	 * must be the loopback interface.
	 */
	rc = lnet_ping_info_validate(&pbuf->pb_info);
	if (rc) {
		LCONSOLE_EMERG("Invalid ping target: %d\n", rc);
		LBUG();
	}
	LNET_PING_BUFFER_SEQNO(pbuf) =
		atomic_inc_return(&the_lnet.ln_ping_target_seqno);
}

static void
lnet_ping_target_update(struct lnet_ping_buffer *pbuf,
			struct lnet_handle_md ping_mdh)
{
	struct lnet_ping_buffer *old_pbuf = NULL;
	struct lnet_handle_md old_ping_md;

	/* switch the NIs to point to the new ping info created */
	lnet_net_lock(LNET_LOCK_EX);

	if (!the_lnet.ln_routing)
		pbuf->pb_info.pi_features |= LNET_PING_FEAT_RTE_DISABLED;
	if (!lnet_peer_discovery_disabled)
		pbuf->pb_info.pi_features |= LNET_PING_FEAT_DISCOVERY;

	/* Ensure only known feature bits have been set. */
	LASSERT(pbuf->pb_info.pi_features & LNET_PING_FEAT_BITS);
	LASSERT(!(pbuf->pb_info.pi_features & ~LNET_PING_FEAT_BITS));

	lnet_ping_target_install_locked(pbuf);

	if (the_lnet.ln_ping_target) {
		old_pbuf = the_lnet.ln_ping_target;
		old_ping_md = the_lnet.ln_ping_target_md;
	}
	the_lnet.ln_ping_target_md = ping_mdh;
	the_lnet.ln_ping_target = pbuf;

	lnet_net_unlock(LNET_LOCK_EX);

	if (old_pbuf) {
		/* unlink and free the old ping info */
		lnet_ping_md_unlink(old_pbuf, &old_ping_md);
		lnet_ping_buffer_decref(old_pbuf);
	}

	lnet_push_update_to_peers(0);
}

static void
lnet_ping_target_fini(void)
{
	lnet_ping_md_unlink(the_lnet.ln_ping_target,
			    &the_lnet.ln_ping_target_md);

	lnet_assert_handler_unused(the_lnet.ln_ping_target_handler);
	lnet_ping_target_destroy();
}

/* Resize the push target. */
int lnet_push_target_resize(void)
{
	struct lnet_handle_md mdh;
	struct lnet_handle_md old_mdh;
	struct lnet_ping_buffer *pbuf;
	struct lnet_ping_buffer *old_pbuf;
	int nbytes;
	int rc;

again:
	nbytes = the_lnet.ln_push_target_nbytes;
	if (nbytes <= 0) {
		CDEBUG(D_NET, "Invalid nbytes %d\n", nbytes);
		return -EINVAL;
	}

	/* NB: lnet_ping_buffer_alloc() sets pbuf refcount to 1. That ref is
	 * dropped when we need to resize again (see "old_pbuf" below) or when
	 * LNet is shutdown (see lnet_push_target_fini())
	 */
	pbuf = lnet_ping_buffer_alloc(nbytes, GFP_NOFS);
	if (!pbuf) {
		CDEBUG(D_NET, "Can't allocate pbuf for nbytes %d\n", nbytes);
		return  -ENOMEM;
	}

	rc = lnet_push_target_post(pbuf, &mdh);
	if (rc) {
		CDEBUG(D_NET, "Failed to post push target: %d\n", rc);
		lnet_ping_buffer_decref(pbuf);
		return rc;
	}

	lnet_net_lock(LNET_LOCK_EX);
	old_pbuf = the_lnet.ln_push_target;
	old_mdh = the_lnet.ln_push_target_md;
	the_lnet.ln_push_target = pbuf;
	the_lnet.ln_push_target_md = mdh;
	lnet_net_unlock(LNET_LOCK_EX);

	if (old_pbuf) {
		LNetMDUnlink(old_mdh);
		/* Drop ref set by lnet_ping_buffer_alloc() */
		lnet_ping_buffer_decref(old_pbuf);
	}

	/* Received another push or reply that requires a larger buffer */
	if (nbytes < the_lnet.ln_push_target_nbytes)
		goto again;

	CDEBUG(D_NET, "nbytes %d success\n", nbytes);
	return 0;
}

int lnet_push_target_post(struct lnet_ping_buffer *pbuf,
			  struct lnet_handle_md *mdhp)
{
	struct lnet_processid id = {
		.nid	= LNET_ANY_NID,
		.pid	= LNET_PID_ANY
	};
	struct lnet_md md = { NULL };
	struct lnet_me *me;
	int rc;

	me = LNetMEAttach(LNET_RESERVED_PORTAL, &id,
			  LNET_PROTO_PING_MATCHBITS, 0,
			  LNET_UNLINK, LNET_INS_AFTER);
	if (IS_ERR(me)) {
		rc = PTR_ERR(me);
		CERROR("Can't create push target ME: %d\n", rc);
		return rc;
	}

	pbuf->pb_needs_post = false;

	/* This reference is dropped by lnet_push_target_event_handler() */
	lnet_ping_buffer_addref(pbuf);

	/* initialize md content */
	md.start = &pbuf->pb_info;
	md.length = pbuf->pb_nbytes;
	md.threshold = 1;
	md.max_size = 0;
	md.options = LNET_MD_OP_PUT | LNET_MD_TRUNCATE;
	md.user_ptr = pbuf;
	md.handler = the_lnet.ln_push_target_handler;

	rc = LNetMDAttach(me, &md, LNET_UNLINK, mdhp);
	if (rc) {
		CERROR("Can't attach push MD: %d\n", rc);
		lnet_ping_buffer_decref(pbuf);
		pbuf->pb_needs_post = true;
		return rc;
	}

	CDEBUG(D_NET, "posted push target %p\n", pbuf);

	return 0;
}

static void lnet_push_target_event_handler(struct lnet_event *ev)
{
	struct lnet_ping_buffer *pbuf = ev->md_user_ptr;

	CDEBUG(D_NET, "type %d status %d unlinked %d\n", ev->type, ev->status,
	       ev->unlinked);

	if (pbuf->pb_info.pi_magic == __swab32(LNET_PROTO_PING_MAGIC))
		lnet_swap_pinginfo(pbuf);

	if (ev->type == LNET_EVENT_UNLINK) {
		/* Drop ref added by lnet_push_target_post() */
		lnet_ping_buffer_decref(pbuf);
		return;
	}

	lnet_peer_push_event(ev);
	if (ev->unlinked)
		/* Drop ref added by lnet_push_target_post */
		lnet_ping_buffer_decref(pbuf);
}

/* Initialize the push target. */
static int lnet_push_target_init(void)
{
	int rc;

	if (the_lnet.ln_push_target)
		return -EALREADY;

	the_lnet.ln_push_target_handler =
		lnet_push_target_event_handler;

	rc = LNetSetLazyPortal(LNET_RESERVED_PORTAL);
	LASSERT(rc == 0);

	/* Start at the required minimum, we'll enlarge if required. */
	the_lnet.ln_push_target_nbytes = LNET_PING_INFO_MIN_SIZE;

	rc = lnet_push_target_resize();
	if (rc) {
		LNetClearLazyPortal(LNET_RESERVED_PORTAL);
		the_lnet.ln_push_target_handler = NULL;
	}

	return rc;
}

/* Clean up the push target. */
static void lnet_push_target_fini(void)
{
	if (!the_lnet.ln_push_target)
		return;

	/* Unlink and invalidate to prevent new references. */
	LNetMDUnlink(the_lnet.ln_push_target_md);
	LNetInvalidateMDHandle(&the_lnet.ln_push_target_md);

	/* Wait for the unlink to complete. */
	wait_var_event_warning(&the_lnet.ln_push_target->pb_refcnt,
			       atomic_read(&the_lnet.ln_push_target->pb_refcnt) <= 1,
			       "Still waiting for ping data MD to unlink\n");

	/* Drop ref set by lnet_ping_buffer_alloc() */
	lnet_ping_buffer_decref(the_lnet.ln_push_target);
	the_lnet.ln_push_target = NULL;
	the_lnet.ln_push_target_nbytes = 0;

	LNetClearLazyPortal(LNET_RESERVED_PORTAL);
	lnet_assert_handler_unused(the_lnet.ln_push_target_handler);
	the_lnet.ln_push_target_handler = NULL;
}

static int
lnet_ni_tq_credits(struct lnet_ni *ni)
{
	int credits;

	LASSERT(ni->ni_ncpts >= 1);

	if (ni->ni_ncpts == 1)
		return ni->ni_net->net_tunables.lct_max_tx_credits;

	credits = ni->ni_net->net_tunables.lct_max_tx_credits / ni->ni_ncpts;
	credits = max(credits, 8 * ni->ni_net->net_tunables.lct_peer_tx_credits);
	credits = min(credits, ni->ni_net->net_tunables.lct_max_tx_credits);

	return credits;
}

static void
lnet_ni_unlink_locked(struct lnet_ni *ni)
{
	/* move it to zombie list and nobody can find it anymore */
	LASSERT(!list_empty(&ni->ni_netlist));
	list_move(&ni->ni_netlist, &ni->ni_net->net_ni_zombie);
	lnet_ni_decref_locked(ni, 0);
}

static void
lnet_clear_zombies_nis_locked(struct lnet_net *net)
{
	int i;
	int islo;
	struct lnet_ni *ni;
	struct list_head *zombie_list = &net->net_ni_zombie;

	/*
	 * Now wait for the NIs I just nuked to show up on the zombie
	 * list and shut them down in guaranteed thread context
	 */
	i = 2;
	while ((ni = list_first_entry_or_null(zombie_list,
					      struct lnet_ni,
					      ni_netlist)) != NULL) {
		int *ref;
		int j;

		list_del_init(&ni->ni_netlist);
		/* the ni should be in deleting state. If it's not it's
		 * a bug */
		LASSERT(ni->ni_state == LNET_NI_STATE_DELETING);
		cfs_percpt_for_each(ref, j, ni->ni_refs) {
			if (!*ref)
				continue;
			/* still busy, add it back to zombie list */
			list_add(&ni->ni_netlist, zombie_list);
			break;
		}

		if (!list_empty(&ni->ni_netlist)) {
			/* Unlock mutex while waiting to allow other
			 * threads to read the LNet state and fall through
			 * to avoid deadlock
			 */
			lnet_net_unlock(LNET_LOCK_EX);
			mutex_unlock(&the_lnet.ln_api_mutex);

			++i;
			if ((i & (-i)) == i) {
				CDEBUG(D_WARNING, "Waiting for zombie LNI %s\n",
				       libcfs_nidstr(&ni->ni_nid));
			}
			schedule_timeout_uninterruptible(HZ);

			mutex_lock(&the_lnet.ln_api_mutex);
			lnet_net_lock(LNET_LOCK_EX);
			continue;
		}

		lnet_net_unlock(LNET_LOCK_EX);

		islo = ni->ni_net->net_lnd->lnd_type == LOLND;

		LASSERT(!in_interrupt());
		/* Holding the LND mutex makes it safe for lnd_shutdown
		 * to call module_put(). Module unload cannot finish
		 * until lnet_unregister_lnd() completes, and that
		 * requires the LND mutex.
		 */
		mutex_unlock(&the_lnet.ln_api_mutex);
		mutex_lock(&the_lnet.ln_lnd_mutex);
		net->net_lnd->lnd_shutdown(ni);
		mutex_unlock(&the_lnet.ln_lnd_mutex);
		mutex_lock(&the_lnet.ln_api_mutex);

		if (!islo)
			CDEBUG(D_LNI, "Removed LNI %s\n",
			       libcfs_nidstr(&ni->ni_nid));

		lnet_ni_free(ni);
		i = 2;

		lnet_net_lock(LNET_LOCK_EX);
	}
}

/* shutdown down the NI and release refcount */
static void
lnet_shutdown_lndni(struct lnet_ni *ni)
{
	int i;
	struct lnet_net *net = ni->ni_net;

	lnet_net_lock(LNET_LOCK_EX);
	lnet_ni_lock(ni);
	ni->ni_state = LNET_NI_STATE_DELETING;
	lnet_ni_unlock(ni);
	lnet_ni_unlink_locked(ni);
	lnet_incr_dlc_seq();
	lnet_net_unlock(LNET_LOCK_EX);

	/* clear messages for this NI on the lazy portal */
	for (i = 0; i < the_lnet.ln_nportals; i++)
		lnet_clear_lazy_portal(ni, i, "Shutting down NI");

	lnet_net_lock(LNET_LOCK_EX);
	lnet_clear_zombies_nis_locked(net);
	lnet_net_unlock(LNET_LOCK_EX);
}

static void
lnet_shutdown_lndnet(struct lnet_net *net)
{
	struct lnet_ni *ni;

	lnet_net_lock(LNET_LOCK_EX);

	list_del_init(&net->net_list);

	while ((ni = list_first_entry_or_null(&net->net_ni_list,
					      struct lnet_ni,
					      ni_netlist)) != NULL) {
		lnet_net_unlock(LNET_LOCK_EX);
		lnet_shutdown_lndni(ni);
		lnet_net_lock(LNET_LOCK_EX);
	}

	lnet_net_unlock(LNET_LOCK_EX);

	/* Do peer table cleanup for this net */
	lnet_peer_tables_cleanup(net);

	lnet_net_free(net);
}

static void
lnet_shutdown_lndnets(void)
{
	struct lnet_net *net;
	LIST_HEAD(resend);
	struct lnet_msg *msg, *tmp;

	/* NB called holding the global mutex */

	/* All quiet on the API front */
	LASSERT(the_lnet.ln_state == LNET_STATE_RUNNING ||
		the_lnet.ln_state == LNET_STATE_STOPPING);
	LASSERT(!the_lnet.ln_refcount);

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_state = LNET_STATE_STOPPING;

	/*
	 * move the nets to the zombie list to avoid them being
	 * picked up for new work. LONET is also included in the
	 * Nets that will be moved to the zombie list
	 */
	list_splice_init(&the_lnet.ln_nets, &the_lnet.ln_net_zombie);

	/* Drop the cached loopback Net. */
	if (the_lnet.ln_loni) {
		lnet_ni_decref_locked(the_lnet.ln_loni, 0);
		the_lnet.ln_loni = NULL;
	}
	lnet_net_unlock(LNET_LOCK_EX);

	/* iterate through the net zombie list and delete each net */
	while ((net = list_first_entry_or_null(&the_lnet.ln_net_zombie,
					       struct lnet_net,
					       net_list)) != NULL)
		lnet_shutdown_lndnet(net);

	spin_lock(&the_lnet.ln_msg_resend_lock);
	list_splice(&the_lnet.ln_msg_resend, &resend);
	spin_unlock(&the_lnet.ln_msg_resend_lock);

	list_for_each_entry_safe(msg, tmp, &resend, msg_list) {
		list_del_init(&msg->msg_list);
		msg->msg_no_resend = true;
		lnet_finalize(msg, -ECANCELED);
	}

	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_state = LNET_STATE_SHUTDOWN;
	lnet_net_unlock(LNET_LOCK_EX);
}

static int
lnet_startup_lndni(struct lnet_ni *ni, struct lnet_lnd_tunables *tun)
{
	int rc = -EINVAL;
	struct lnet_tx_queue *tq;
	int i;
	struct lnet_net *net = ni->ni_net;

	mutex_lock(&the_lnet.ln_lnd_mutex);

	if (tun) {
		memcpy(&ni->ni_lnd_tunables, tun,
		       sizeof(*tun));
		ni->ni_lnd_tunables_set = true;
	}

	rc = net->net_lnd->lnd_startup(ni);

	mutex_unlock(&the_lnet.ln_lnd_mutex);

	if (rc) {
		LCONSOLE_ERROR_MSG(0x105, "Error %d starting up LNI %s\n",
				   rc, libcfs_lnd2str(net->net_lnd->lnd_type));
		goto failed0;
	}

	lnet_ni_lock(ni);
	ni->ni_state = LNET_NI_STATE_ACTIVE;
	lnet_ni_unlock(ni);

	/* We keep a reference on the loopback net through the loopback NI */
	if (net->net_lnd->lnd_type == LOLND) {
		lnet_ni_addref(ni);
		LASSERT(!the_lnet.ln_loni);
		the_lnet.ln_loni = ni;
		ni->ni_net->net_tunables.lct_peer_tx_credits = 0;
		ni->ni_net->net_tunables.lct_peer_rtr_credits = 0;
		ni->ni_net->net_tunables.lct_max_tx_credits = 0;
		ni->ni_net->net_tunables.lct_peer_timeout = 0;
		return 0;
	}

	if (!ni->ni_net->net_tunables.lct_peer_tx_credits ||
	    !ni->ni_net->net_tunables.lct_max_tx_credits) {
		LCONSOLE_ERROR_MSG(0x107, "LNI %s has no %scredits\n",
				   libcfs_lnd2str(net->net_lnd->lnd_type),
				   !ni->ni_net->net_tunables.lct_peer_tx_credits ?
				   "" : "per-peer ");
		/*
		 * shutdown the NI since if we get here then it must've already
		 * been started
		 */
		lnet_shutdown_lndni(ni);
		return -EINVAL;
	}

	cfs_percpt_for_each(tq, i, ni->ni_tx_queues) {
		tq->tq_credits_min =
		tq->tq_credits_max =
		tq->tq_credits = lnet_ni_tq_credits(ni);
	}

	atomic_set(&ni->ni_tx_credits,
		   lnet_ni_tq_credits(ni) * ni->ni_ncpts);
	atomic_set(&ni->ni_healthv, LNET_MAX_HEALTH_VALUE);

	CDEBUG(D_LNI, "Added LNI %s [%d/%d/%d/%d]\n",
	       libcfs_nidstr(&ni->ni_nid),
	       ni->ni_net->net_tunables.lct_peer_tx_credits,
	       lnet_ni_tq_credits(ni) * LNET_CPT_NUMBER,
	       ni->ni_net->net_tunables.lct_peer_rtr_credits,
	       ni->ni_net->net_tunables.lct_peer_timeout);

	return 0;
failed0:
	lnet_ni_free(ni);
	return rc;
}

static struct lnet_lnd *lnet_load_lnd(u32 lnd_type)
{
	struct lnet_lnd *lnd;
	int rc = 0;

	mutex_lock(&the_lnet.ln_lnd_mutex);
	lnd = lnet_find_lnd_by_type(lnd_type);
	if (!lnd) {
		mutex_unlock(&the_lnet.ln_lnd_mutex);
		rc = request_module("%s", libcfs_lnd2modname(lnd_type));
		mutex_lock(&the_lnet.ln_lnd_mutex);

		lnd = lnet_find_lnd_by_type(lnd_type);
		if (!lnd) {
			mutex_unlock(&the_lnet.ln_lnd_mutex);
			CERROR("Can't load LND %s, module %s, rc=%d\n",
			       libcfs_lnd2str(lnd_type),
			       libcfs_lnd2modname(lnd_type), rc);
#ifndef HAVE_MODULE_LOADING_SUPPORT
			LCONSOLE_ERROR_MSG(0x104,
					   "Your kernel must be compiled with kernel module loading support.");
#endif
			return ERR_PTR(-EINVAL);
		}
	}
	mutex_unlock(&the_lnet.ln_lnd_mutex);

	return lnd;
}

static int
lnet_startup_lndnet(struct lnet_net *net, struct lnet_lnd_tunables *tun)
{
	struct lnet_ni *ni;
	struct lnet_net *net_l = NULL;
	LIST_HEAD(local_ni_list);
	int ni_count = 0;
	u32 lnd_type;
	struct lnet_lnd *lnd;
	int rc;
	int peer_timeout =
		net->net_tunables.lct_peer_timeout;
	int maxtxcredits =
		net->net_tunables.lct_max_tx_credits;
	int peerrtrcredits =
		net->net_tunables.lct_peer_rtr_credits;

	/*
	 * make sure that this net is unique. If it isn't then
	 * we are adding interfaces to an already existing network, and
	 * 'net' is just a convenient way to pass in the list.
	 * if it is unique we need to find the LND and load it if
	 * necessary.
	 */
	if (lnet_net_unique(net->net_id, &the_lnet.ln_nets, &net_l)) {
		lnd_type = LNET_NETTYP(net->net_id);

		lnd = lnet_load_lnd(lnd_type);
		if (IS_ERR(lnd)) {
			rc = PTR_ERR(lnd);
			goto failed0;
		}

		mutex_lock(&the_lnet.ln_lnd_mutex);
		net->net_lnd = lnd;
		mutex_unlock(&the_lnet.ln_lnd_mutex);

		net_l = net;
	}

	/*
	 * net_l: if the network being added is unique then net_l
	 *        will point to that network
	 *        if the network being added is not unique then
	 *        net_l points to the existing network.
	 *
	 * When we enter the loop below, we'll pick NIs off he
	 * network beign added and start them up, then add them to
	 * a local ni list. Once we've successfully started all
	 * the NIs then we join the local NI list (of started up
	 * networks) with the net_l->net_ni_list, which should
	 * point to the correct network to add the new ni list to
	 *
	 * If any of the new NIs fail to start up, then we want to
	 * iterate through the local ni list, which should include
	 * any NIs which were successfully started up, and shut
	 * them down.
	 *
	 * After than we want to delete the network being added,
	 * to avoid a memory leak.
	 */
	while ((ni = list_first_entry_or_null(&net->net_ni_added,
					      struct lnet_ni,
					      ni_netlist)) != NULL) {
		list_del_init(&ni->ni_netlist);

		/* make sure that the the NI we're about to start
		 * up is actually unique. if it's not fail. */
		if (!lnet_ni_unique_net(&net_l->net_ni_list,
					ni->ni_interface)) {
			rc = -EEXIST;
			goto failed1;
		}

		/* adjust the pointer the parent network, just in case it
		 * the net is a duplicate */
		ni->ni_net = net_l;

		rc = lnet_startup_lndni(ni, tun);

		if (rc < 0)
			goto failed1;

		lnet_ni_addref(ni);
		list_add_tail(&ni->ni_netlist, &local_ni_list);

		ni_count++;
	}

	lnet_net_lock(LNET_LOCK_EX);
	list_splice_tail(&local_ni_list, &net_l->net_ni_list);
	lnet_incr_dlc_seq();
	lnet_net_unlock(LNET_LOCK_EX);

	/* if the network is not unique then we don't want to keep
	 * it around after we're done. Free it. Otherwise add that
	 * net to the global the_lnet.ln_nets */
	if (net_l && net_l != net) {
		/*
		 * TODO - note. currently the tunables can not be updated
		 * once added
		 */
		lnet_net_free(net);
	} else {
		/*
		 * restore tunables after it has been overwitten by the
		 * lnd
		 */
		if (peer_timeout != -1)
			net->net_tunables.lct_peer_timeout = peer_timeout;
		if (maxtxcredits != -1)
			net->net_tunables.lct_max_tx_credits = maxtxcredits;
		if (peerrtrcredits != -1)
			net->net_tunables.lct_peer_rtr_credits = peerrtrcredits;

		lnet_net_lock(LNET_LOCK_EX);
		list_add_tail(&net->net_list, &the_lnet.ln_nets);
		lnet_net_unlock(LNET_LOCK_EX);
	}

	return ni_count;

failed1:
	/*
	 * shutdown the new NIs that are being started up
	 * free the NET being started
	 */
	while ((ni = list_first_entry_or_null(&local_ni_list,
					      struct lnet_ni,
					      ni_netlist)) != NULL)
		lnet_shutdown_lndni(ni);

failed0:
	lnet_net_free(net);

	return rc;
}

static int
lnet_startup_lndnets(struct list_head *netlist)
{
	struct lnet_net *net;
	int rc;
	int ni_count = 0;

	/*
	 * Change to running state before bringing up the LNDs. This
	 * allows lnet_shutdown_lndnets() to assert that we've passed
	 * through here.
	 */
	lnet_net_lock(LNET_LOCK_EX);
	the_lnet.ln_state = LNET_STATE_RUNNING;
	lnet_net_unlock(LNET_LOCK_EX);

	while ((net = list_first_entry_or_null(netlist,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);

		rc = lnet_startup_lndnet(net, NULL);
		if (rc < 0)
			goto failed;

		ni_count += rc;
	}

	return ni_count;
failed:
	lnet_shutdown_lndnets();

	return rc;
}

static int lnet_genl_parse_list(struct sk_buff *msg,
				const struct ln_key_list *data[], u16 idx)
{
	const struct ln_key_list *list = data[idx];
	const struct ln_key_props *props;
	struct nlattr *node;
	u16 count;

	if (!list)
		return 0;

	if (!list->lkl_maxattr)
		return -ERANGE;

	props = list->lkl_list;
	if (!props)
		return -EINVAL;

	node = nla_nest_start(msg, LN_SCALAR_ATTR_LIST);
	if (!node)
		return -ENOBUFS;

	for (count = 1; count <= list->lkl_maxattr; count++) {
		struct nlattr *key = nla_nest_start(msg, count);

		if (count == 1)
			nla_put_u16(msg, LN_SCALAR_ATTR_LIST_SIZE,
				    list->lkl_maxattr);

		nla_put_u16(msg, LN_SCALAR_ATTR_INDEX, count);
		if (props[count].lkp_value)
			nla_put_string(msg, LN_SCALAR_ATTR_VALUE,
				       props[count].lkp_value);
		if (props[count].lkp_key_format)
			nla_put_u16(msg, LN_SCALAR_ATTR_KEY_FORMAT,
				    props[count].lkp_key_format);
		nla_put_u16(msg, LN_SCALAR_ATTR_NLA_TYPE,
			    props[count].lkp_data_type);
		if (props[count].lkp_data_type == NLA_NESTED) {
			int rc;

			rc = lnet_genl_parse_list(msg, data, ++idx);
			if (rc < 0)
				return rc;
			idx = rc;
		}

		nla_nest_end(msg, key);
	}

	nla_nest_end(msg, node);
	return idx;
}

int lnet_genl_send_scalar_list(struct sk_buff *msg, u32 portid, u32 seq,
			       const struct genl_family *family, int flags,
			       u8 cmd, const struct ln_key_list *data[])
{
	int rc = 0;
	void *hdr;

	if (!data[0])
		return -EINVAL;

	hdr = genlmsg_put(msg, portid, seq, family, flags, cmd);
	if (!hdr) {
		rc = -EMSGSIZE;
		goto canceled;
	}

	rc = lnet_genl_parse_list(msg, data, 0);
	if (rc < 0)
		goto canceled;

	genlmsg_end(msg, hdr);
canceled:
	if (rc < 0)
		genlmsg_cancel(msg, hdr);
	return rc > 0 ? 0 : rc;
}
EXPORT_SYMBOL(lnet_genl_send_scalar_list);

static struct genl_family lnet_family;

/**
 * Initialize LNet library.
 *
 * Automatically called at module loading time. Caller has to call
 * lnet_lib_exit() after a call to lnet_lib_init(), if and only if the
 * latter returned 0. It must be called exactly once.
 *
 * Return:	0 on success
 *		-ve on failures.
 */
int lnet_lib_init(void)
{
	int rc;

	lnet_assert_wire_constants();

	/* refer to global cfs_cpt_tab for now */
	the_lnet.ln_cpt_table = cfs_cpt_tab;
	the_lnet.ln_cpt_number = cfs_cpt_number(cfs_cpt_tab);

	LASSERT(the_lnet.ln_cpt_number > 0);
	if (the_lnet.ln_cpt_number > LNET_CPT_MAX) {
		/* we are under risk of consuming all lh_cookie */
		CERROR("Can't have %d CPTs for LNet (max allowed is %d), please change setting of CPT-table and retry\n",
		       the_lnet.ln_cpt_number, LNET_CPT_MAX);
		return -E2BIG;
	}

	while ((1 << the_lnet.ln_cpt_bits) < the_lnet.ln_cpt_number)
		the_lnet.ln_cpt_bits++;

	rc = lnet_create_locks();
	if (rc) {
		CERROR("Can't create LNet global locks: %d\n", rc);
		return rc;
	}

	rc = genl_register_family(&lnet_family);
	if (rc != 0) {
		lnet_destroy_locks();
		CERROR("Can't register LNet netlink family: %d\n", rc);
		return rc;
	}

	the_lnet.ln_refcount = 0;
	INIT_LIST_HEAD(&the_lnet.ln_net_zombie);
	INIT_LIST_HEAD(&the_lnet.ln_msg_resend);

	/*
	 * The hash table size is the number of bits it takes to express the set
	 * ln_num_routes, minus 1 (better to under estimate than over so we
	 * don't waste memory).
	 */
	if (rnet_htable_size <= 0)
		rnet_htable_size = LNET_REMOTE_NETS_HASH_DEFAULT;
	else if (rnet_htable_size > LNET_REMOTE_NETS_HASH_MAX)
		rnet_htable_size = LNET_REMOTE_NETS_HASH_MAX;
	the_lnet.ln_remote_nets_hbits = max_t(int, 1,
					   order_base_2(rnet_htable_size) - 1);

	/*
	 * All LNDs apart from the LOLND are in separate modules.  They
	 * register themselves when their module loads, and unregister
	 * themselves when their module is unloaded.
	 */
	lnet_register_lnd(&the_lolnd);
	return 0;
}

/**
 * Finalize LNet library.
 *
 * \pre lnet_lib_init() called with success.
 * \pre All LNet users called LNetNIFini() for matching LNetNIInit() calls.
 *
 * As this happens at module-unload, all lnds must already be unloaded,
 * so they must already be unregistered.
 */
void lnet_lib_exit(void)
{
	int i;

	LASSERT(!the_lnet.ln_refcount);
	lnet_unregister_lnd(&the_lolnd);
	for (i = 0; i < NUM_LNDS; i++)
		LASSERT(!the_lnet.ln_lnds[i]);
	lnet_destroy_locks();
	genl_unregister_family(&lnet_family);
}

/**
 * Set LNet PID and start LNet interfaces, routing, and forwarding.
 *
 * Users must call this function at least once before any other functions.
 * For each successful call there must be a corresponding call to
 * LNetNIFini(). For subsequent calls to LNetNIInit(), @requested_pid is
 * ignored.
 *
 * The PID used by LNet may be different from the one requested.
 * See LNetGetId().
 *
 * @requested_pid	PID requested by the caller.
 *
 * Return:		>= 0 on success, and < 0 error code on failures.
 */
int
LNetNIInit(lnet_pid_t requested_pid)
{
	int im_a_router = 0;
	int rc;
	int ni_bytes;
	struct lnet_ping_buffer *pbuf;
	struct lnet_handle_md ping_mdh;
	LIST_HEAD(net_head);
	struct lnet_net *net;

	mutex_lock(&the_lnet.ln_api_mutex);

	CDEBUG(D_OTHER, "refs %d\n", the_lnet.ln_refcount);

	if (the_lnet.ln_state == LNET_STATE_STOPPING) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return -ESHUTDOWN;
	}

	if (the_lnet.ln_refcount > 0) {
		rc = the_lnet.ln_refcount++;
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	rc = lnet_prepare(requested_pid);
	if (rc) {
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	/* create a network for Loopback network */
	net = lnet_net_alloc(LNET_MKNET(LOLND, 0), &net_head);
	if (!net) {
		rc = -ENOMEM;
		goto err_empty_list;
	}

	/* Add in the loopback NI */
	if (!lnet_ni_alloc(net, NULL, NULL)) {
		rc = -ENOMEM;
		goto err_empty_list;
	}

	if (use_tcp_bonding)
		CWARN("use_tcp_bonding has been removed. Use Multi-Rail and Dynamic Discovery instead, see LU-13641\n");

	/* If LNet is being initialized via DLC it is possible
	 * that the user requests not to load module parameters (ones which
	 * are supported by DLC) on initialization.  Therefore, make sure not
	 * to load networks, routes and forwarding from module parameters
	 * in this case. On cleanup in case of failure only clean up
	 * routes if it has been loaded
	 */
	if (!the_lnet.ln_nis_from_mod_params) {
		rc = lnet_parse_networks(&net_head, lnet_get_networks());
		if (rc < 0)
			goto err_empty_list;
	}

	rc = lnet_startup_lndnets(&net_head);
	if (rc < 0)
		goto err_empty_list;

	if (!the_lnet.ln_nis_from_mod_params) {
		rc = lnet_parse_routes(lnet_get_routes(), &im_a_router);
		if (rc)
			goto err_shutdown_lndnis;

		rc = lnet_rtrpools_alloc(im_a_router);
		if (rc)
			goto err_destroy_routes;
	}

	rc = lnet_acceptor_start();
	if (rc)
		goto err_destroy_routes;

	the_lnet.ln_refcount = 1;
	/* Now I may use my own API functions... */

	ni_bytes = LNET_PING_INFO_HDR_SIZE;
	list_for_each_entry(net, &the_lnet.ln_nets, net_list)
		ni_bytes += lnet_get_net_ni_bytes_locked(net);

	rc = lnet_ping_target_setup(&pbuf, &ping_mdh, ni_bytes, true);
	if (rc)
		goto err_acceptor_stop;

	lnet_ping_target_update(pbuf, ping_mdh);

	the_lnet.ln_mt_handler = lnet_mt_event_handler;

	rc = lnet_push_target_init();
	if (rc)
		goto err_stop_ping;

	rc = lnet_peer_discovery_start();
	if (rc != 0)
		goto err_destroy_push_target;

	rc = lnet_monitor_thr_start();
	if (rc != 0)
		goto err_stop_discovery_thr;

	lnet_fault_init();
	lnet_router_debugfs_init();

	mutex_unlock(&the_lnet.ln_api_mutex);

	complete_all(&the_lnet.ln_started);

	/* wait for all routers to start */
	lnet_wait_router_start();

	return 0;

err_stop_discovery_thr:
	lnet_peer_discovery_stop();
err_destroy_push_target:
	lnet_push_target_fini();
err_stop_ping:
	lnet_ping_target_fini();
err_acceptor_stop:
	the_lnet.ln_refcount = 0;
	lnet_acceptor_stop();
err_destroy_routes:
	if (!the_lnet.ln_nis_from_mod_params)
		lnet_destroy_routes();
err_shutdown_lndnis:
	lnet_shutdown_lndnets();
err_empty_list:
	lnet_unprepare();
	LASSERT(rc < 0);
	mutex_unlock(&the_lnet.ln_api_mutex);
	while ((net = list_first_entry_or_null(&net_head,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);
		lnet_net_free(net);
	}
	return rc;
}
EXPORT_SYMBOL(LNetNIInit);

/**
 * Stop LNet interfaces, routing, and forwarding.
 *
 * Users must call this function once for each successful call to LNetNIInit().
 * Once the LNetNIFini() operation has been started, the results of pending
 * API operations are undefined.
 *
 * Return:	always 0 for current implementation.
 */
int
LNetNIFini(void)
{
	mutex_lock(&the_lnet.ln_api_mutex);

	LASSERT(the_lnet.ln_refcount > 0);

	if (the_lnet.ln_refcount != 1) {
		the_lnet.ln_refcount--;
	} else {
		LASSERT(!the_lnet.ln_niinit_self);

		lnet_net_lock(LNET_LOCK_EX);
		the_lnet.ln_state = LNET_STATE_STOPPING;
		lnet_net_unlock(LNET_LOCK_EX);

		lnet_fault_fini();
		lnet_router_debugfs_fini();
		lnet_monitor_thr_stop();
		lnet_peer_discovery_stop();
		lnet_push_target_fini();
		lnet_ping_target_fini();

		/* Teardown fns that use my own API functions BEFORE here */
		the_lnet.ln_refcount = 0;

		lnet_acceptor_stop();
		lnet_destroy_routes();
		lnet_shutdown_lndnets();
		lnet_unprepare();
	}

	mutex_unlock(&the_lnet.ln_api_mutex);
	return 0;
}
EXPORT_SYMBOL(LNetNIFini);

/**
 * Grabs the ni data from the ni structure and fills the out
 * parameters
 *
 * @ni		network	interface structure
 * @cfg_ni	NI config information
 * @tun		network and LND tunables
 */
static void
lnet_fill_ni_info(struct lnet_ni *ni, struct lnet_ioctl_config_ni *cfg_ni,
		  struct lnet_ioctl_config_lnd_tunables *tun,
		  struct lnet_ioctl_element_stats *stats,
		  u32 tun_size)
{
	size_t min_size = 0;
	int i;

	if (!ni || !cfg_ni || !tun || !nid_is_nid4(&ni->ni_nid))
		return;

	if (ni->ni_interface) {
		strncpy(cfg_ni->lic_ni_intf,
			ni->ni_interface,
			sizeof(cfg_ni->lic_ni_intf));
	}

	cfg_ni->lic_nid = lnet_nid_to_nid4(&ni->ni_nid);
	cfg_ni->lic_status = lnet_ni_get_status_locked(ni);
	cfg_ni->lic_dev_cpt = ni->ni_dev_cpt;

	memcpy(&tun->lt_cmn, &ni->ni_net->net_tunables, sizeof(tun->lt_cmn));

	if (stats) {
		stats->iel_send_count = lnet_sum_stats(&ni->ni_stats,
						       LNET_STATS_TYPE_SEND);
		stats->iel_recv_count = lnet_sum_stats(&ni->ni_stats,
						       LNET_STATS_TYPE_RECV);
		stats->iel_drop_count = lnet_sum_stats(&ni->ni_stats,
						       LNET_STATS_TYPE_DROP);
	}

	/*
	 * tun->lt_tun will always be present, but in order to be
	 * backwards compatible, we need to deal with the cases when
	 * tun->lt_tun is smaller than what the kernel has, because it
	 * comes from an older version of a userspace program, then we'll
	 * need to copy as much information as we have available space.
	 */
	min_size = tun_size - sizeof(tun->lt_cmn);
	memcpy(&tun->lt_tun, &ni->ni_lnd_tunables, min_size);

	/* copy over the cpts */
	if (ni->ni_ncpts == LNET_CPT_NUMBER &&
	    !ni->ni_cpts) {
		for (i = 0; i < ni->ni_ncpts; i++)
			cfg_ni->lic_cpts[i] = i;
	} else {
		for (i = 0;
		     ni->ni_cpts && i < ni->ni_ncpts &&
		     i < LNET_MAX_SHOW_NUM_CPT;
		     i++)
			cfg_ni->lic_cpts[i] = ni->ni_cpts[i];
	}
	cfg_ni->lic_ncpts = ni->ni_ncpts;
}

/**
 * NOTE: This is a legacy function left in the code to be backwards
 * compatible with older userspace programs. It should eventually be
 * removed.
 *
 * Grabs the ni data from the ni structure and fills the out
 * parameters
 *
 * @ni		network	interface structure
 * @config	config information
 */
static void
lnet_fill_ni_info_legacy(struct lnet_ni *ni,
			 struct lnet_ioctl_config_data *config)
{
	struct lnet_ioctl_config_lnd_tunables *lnd_cfg = NULL;
	struct lnet_ioctl_net_config *net_config;
	size_t min_size, tunable_size = 0;
	int i;

	if (!ni || !config || !nid_is_nid4(&ni->ni_nid))
		return;

	net_config = (struct lnet_ioctl_net_config *)config->cfg_bulk;
	if (!net_config)
		return;

	if (!ni->ni_interface)
		return;

	strncpy(net_config->ni_interface,
		ni->ni_interface,
		sizeof(net_config->ni_interface));

	config->cfg_nid = lnet_nid_to_nid4(&ni->ni_nid);
	config->cfg_config_u.cfg_net.net_peer_timeout =
		ni->ni_net->net_tunables.lct_peer_timeout;
	config->cfg_config_u.cfg_net.net_max_tx_credits =
		ni->ni_net->net_tunables.lct_max_tx_credits;
	config->cfg_config_u.cfg_net.net_peer_tx_credits =
		ni->ni_net->net_tunables.lct_peer_tx_credits;
	config->cfg_config_u.cfg_net.net_peer_rtr_credits =
		ni->ni_net->net_tunables.lct_peer_rtr_credits;

	net_config->ni_status = lnet_ni_get_status_locked(ni);

	if (ni->ni_cpts) {
		int num_cpts = min(ni->ni_ncpts, LNET_MAX_SHOW_NUM_CPT);

		for (i = 0; i < num_cpts; i++)
			net_config->ni_cpts[i] = ni->ni_cpts[i];

		config->cfg_ncpts = num_cpts;
	}

	/*
	 * See if user land tools sent in a newer and larger version
	 * of struct lnet_tunables than what the kernel uses.
	 */
	min_size = sizeof(*config) + sizeof(*net_config);

	if (config->cfg_hdr.ioc_len > min_size)
		tunable_size = config->cfg_hdr.ioc_len - min_size;

	/* Don't copy too much data to user space */
	min_size = min(tunable_size, sizeof(ni->ni_lnd_tunables));
	lnd_cfg = (struct lnet_ioctl_config_lnd_tunables *)net_config->cfg_bulk;

	if (lnd_cfg && min_size) {
		memcpy(&lnd_cfg->lt_tun, &ni->ni_lnd_tunables, min_size);
		config->cfg_config_u.cfg_net.net_interface_count = 1;

		/* Tell user land that kernel side has less data */
		if (tunable_size > sizeof(ni->ni_lnd_tunables)) {
			min_size = tunable_size - sizeof(ni->ni_lnd_tunables);
			config->cfg_hdr.ioc_len -= min_size;
		}
	}
}

struct lnet_ni *
lnet_get_ni_idx_locked(int idx)
{
	struct lnet_ni *ni;
	struct lnet_net *net;

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (idx-- == 0)
				return ni;
		}
	}

	return NULL;
}

int lnet_get_net_healthv_locked(struct lnet_net *net)
{
	struct lnet_ni *ni;
	int best_healthv = 0;
	int healthv, ni_fatal;

	list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
		healthv = atomic_read(&ni->ni_healthv);
		ni_fatal = atomic_read(&ni->ni_fatal_error_on);
		if (!ni_fatal && healthv > best_healthv)
			best_healthv = healthv;
	}

	return best_healthv;
}

struct lnet_ni *
lnet_get_next_ni_locked(struct lnet_net *mynet, struct lnet_ni *prev)
{
	struct lnet_ni *ni;
	struct lnet_net *net = mynet;

	/* It is possible that the net has been cleaned out while there is
	 * a message being sent. This function accessed the net without
	 * checking if the list is empty
	 */
	if (!prev) {
		if (!net)
			net = list_first_entry(&the_lnet.ln_nets,
					       struct lnet_net,
					       net_list);
		if (list_empty(&net->net_ni_list))
			return NULL;
		ni = list_first_entry(&net->net_ni_list, struct lnet_ni,
				      ni_netlist);

		return ni;
	}

	if (prev->ni_netlist.next == &prev->ni_net->net_ni_list) {
		/* if you reached the end of the ni list and the net is
		 * specified, then there are no more nis in that net */
		if (net)
			return NULL;

		/* we reached the end of this net ni list. move to the
		 * next net */
		if (prev->ni_net->net_list.next == &the_lnet.ln_nets)
			/* no more nets and no more NIs. */
			return NULL;

		/* get the next net */
		net = list_first_entry(&prev->ni_net->net_list, struct lnet_net,
				       net_list);
		if (list_empty(&net->net_ni_list))
			return NULL;
		/* get the ni on it */
		ni = list_first_entry(&net->net_ni_list, struct lnet_ni,
				      ni_netlist);

		return ni;
	}

	if (list_empty(&prev->ni_netlist))
		return NULL;

	/* there are more nis left */
	ni = list_first_entry(&prev->ni_netlist, struct lnet_ni, ni_netlist);

	return ni;
}

static int
lnet_get_net_config(struct lnet_ioctl_config_data *config)
{
	struct lnet_ni *ni;
	int idx = config->cfg_count;
	int cpt;
	int rc = -ENOENT;

	cpt = lnet_net_lock_current();

	ni = lnet_get_ni_idx_locked(idx);
	if (ni) {
		rc = 0;
		lnet_ni_lock(ni);
		lnet_fill_ni_info_legacy(ni, config);
		lnet_ni_unlock(ni);
	}

	lnet_net_unlock(cpt);
	return rc;
}

int
lnet_get_ni_config(struct lnet_ioctl_config_ni *cfg_ni,
		   struct lnet_ioctl_config_lnd_tunables *tun,
		   struct lnet_ioctl_element_stats *stats,
		   u32 tun_size)
{
	struct lnet_ni *ni;
	int cpt;
	int rc = -ENOENT;

	if (!cfg_ni || !tun || !stats)
		return -EINVAL;

	cpt = lnet_net_lock_current();

	ni = lnet_get_ni_idx_locked(cfg_ni->lic_idx);
	if (ni) {
		rc = 0;
		lnet_ni_lock(ni);
		lnet_fill_ni_info(ni, cfg_ni, tun, stats, tun_size);
		lnet_ni_unlock(ni);
	}

	lnet_net_unlock(cpt);
	return rc;
}

int lnet_get_ni_stats(struct lnet_ioctl_element_msg_stats *msg_stats)
{
	struct lnet_ni *ni;
	int cpt;
	int rc = -ENOENT;

	if (!msg_stats)
		return -EINVAL;

	cpt = lnet_net_lock_current();

	ni = lnet_get_ni_idx_locked(msg_stats->im_idx);

	if (ni) {
		lnet_usr_translate_stats(msg_stats, &ni->ni_stats);
		rc = 0;
	}

	lnet_net_unlock(cpt);

	return rc;
}

static int lnet_add_net_common(struct lnet_net *net,
			       struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct lnet_handle_md ping_mdh;
	struct lnet_ping_buffer *pbuf;
	struct lnet_remotenet *rnet;
	struct lnet_ni *ni;
	u32 net_id;
	int rc;

	lnet_net_lock(LNET_LOCK_EX);
	rnet = lnet_find_rnet_locked(net->net_id);
	lnet_net_unlock(LNET_LOCK_EX);
	/*
	 * make sure that the net added doesn't invalidate the current
	 * configuration LNet is keeping
	 */
	if (rnet) {
		CERROR("Adding net %s will invalidate routing configuration\n",
		       libcfs_net2str(net->net_id));
		lnet_net_free(net);
		return -EUSERS;
	}

	if (tun)
		memcpy(&net->net_tunables,
		       &tun->lt_cmn, sizeof(net->net_tunables));
	else
		memset(&net->net_tunables, -1, sizeof(net->net_tunables));

	net_id = net->net_id;

	rc = lnet_startup_lndnet(net, (tun ? &tun->lt_tun : NULL));
	if (rc < 0)
		return rc;

	/* make sure you calculate the correct number of slots in the ping
	 * buffer. Since the ping info is a flattened list of all the NIs,
	 * we should allocate enough slots to accomodate the number of NIs
	 * which will be added.
	 */
	rc = lnet_ping_target_setup(&pbuf, &ping_mdh,
				    LNET_PING_INFO_HDR_SIZE +
				    lnet_get_ni_bytes(),
				    false);
	if (rc < 0) {
		lnet_shutdown_lndnet(net);
		return rc;
	}

	lnet_net_lock(LNET_LOCK_EX);
	net = lnet_get_net_locked(net_id);
	LASSERT(net);

	/* apply the UDSPs */
	rc = lnet_udsp_apply_policies_on_net(net);
	if (rc)
		CERROR("Failed to apply UDSPs on local net %s\n",
		       libcfs_net2str(net->net_id));

	/* At this point we lost track of which NI was just added, so we
	 * just re-apply the policies on all of the NIs on this net
	 */
	list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
		rc = lnet_udsp_apply_policies_on_ni(ni);
		if (rc)
			CERROR("Failed to apply UDSPs on ni %s\n",
			       libcfs_nidstr(&ni->ni_nid));
	}
	lnet_net_unlock(LNET_LOCK_EX);

	/*
	 * Start the acceptor thread if this is the first network
	 * being added that requires the thread.
	 */
	if (net->net_lnd->lnd_accept) {
		rc = lnet_acceptor_start();
		if (rc < 0) {
			/* shutdown the net that we just started */
			CERROR("Failed to start up acceptor thread\n");
			lnet_shutdown_lndnet(net);
			goto failed;
		}
	}

	lnet_net_lock(LNET_LOCK_EX);
	lnet_peer_net_added(net);
	lnet_net_unlock(LNET_LOCK_EX);

	lnet_ping_target_update(pbuf, ping_mdh);

	return 0;

failed:
	lnet_ping_md_unlink(pbuf, &ping_mdh);
	lnet_ping_buffer_decref(pbuf);
	return rc;
}

static void
lnet_set_tune_defaults(struct lnet_ioctl_config_lnd_tunables *tun)
{
	if (tun) {
		if (tun->lt_cmn.lct_peer_timeout < 0)
			tun->lt_cmn.lct_peer_timeout = DEFAULT_PEER_TIMEOUT;
		if (!tun->lt_cmn.lct_peer_tx_credits)
			tun->lt_cmn.lct_peer_tx_credits = DEFAULT_PEER_CREDITS;
		if (!tun->lt_cmn.lct_max_tx_credits)
			tun->lt_cmn.lct_max_tx_credits = DEFAULT_CREDITS;
	}
}

static int lnet_handle_legacy_ip2nets(char *ip2nets,
				      struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct lnet_net *net;
	const char *nets;
	int rc;
	LIST_HEAD(net_head);

	rc = lnet_parse_ip2nets(&nets, ip2nets);
	if (rc < 0)
		return rc;

	rc = lnet_parse_networks(&net_head, nets);
	if (rc < 0)
		return rc;

	lnet_set_tune_defaults(tun);

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto out;
	}
	while ((net = list_first_entry_or_null(&net_head,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);
		rc = lnet_add_net_common(net, tun);
		if (rc < 0)
			goto out;
	}

out:
	mutex_unlock(&the_lnet.ln_api_mutex);

	while ((net = list_first_entry_or_null(&net_head,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);
		lnet_net_free(net);
	}
	return rc;
}

int lnet_dyn_add_ni(struct lnet_ioctl_config_ni *conf, u32 net_id,
		    struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct lnet_net *net;
	struct lnet_ni *ni;
	int rc, i;
	u32 lnd_type;

	/* handle legacy ip2nets from DLC */
	if (conf->lic_legacy_ip2nets[0] != '\0')
		return lnet_handle_legacy_ip2nets(conf->lic_legacy_ip2nets,
						  tun);

	lnd_type = LNET_NETTYP(net_id);

	if (!libcfs_isknown_lnd(lnd_type)) {
		CERROR("No valid net and lnd information provided\n");
		return -ENOENT;
	}

	net = lnet_net_alloc(net_id, NULL);
	if (!net)
		return -ENOMEM;

	for (i = 0; i < conf->lic_ncpts; i++) {
		if (conf->lic_cpts[i] >= LNET_CPT_NUMBER) {
			lnet_net_free(net);
			return -ERANGE;
		}
	}

	ni = lnet_ni_alloc_w_cpt_array(net, conf->lic_cpts, conf->lic_ncpts,
				       conf->lic_ni_intf);
	if (!ni) {
		lnet_net_free(net);
		return -ENOMEM;
	}

	lnet_set_tune_defaults(tun);

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		lnet_net_free(net);
		rc = -ESHUTDOWN;
	} else {
		rc = lnet_add_net_common(net, tun);
	}

	mutex_unlock(&the_lnet.ln_api_mutex);

	if (rc)
		lnet_ni_free(ni);

	return rc;
}

int lnet_dyn_del_ni(struct lnet_nid *nid)
{
	struct lnet_net *net;
	struct lnet_ni *ni;
	u32 net_id = LNET_NID_NET(nid);
	struct lnet_ping_buffer *pbuf;
	struct lnet_handle_md ping_mdh;
	int net_bytes, rc;
	bool net_empty;

	/* don't allow userspace to shutdown the LOLND */
	if (LNET_NETTYP(net_id) == LOLND)
		return -EINVAL;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto unlock_api_mutex;
	}

	lnet_net_lock(0);

	net = lnet_get_net_locked(net_id);
	if (!net) {
		CERROR("net %s not found\n",
		       libcfs_net2str(net_id));
		rc = -ENOENT;
		goto unlock_net;
	}

	if (!nid_addr_is_set(nid)) {
		/* remove the entire net */
		net_bytes = lnet_get_net_ni_bytes_locked(net);

		lnet_net_unlock(0);

		/* create and link a new ping info, before removing the old one */
		rc = lnet_ping_target_setup(&pbuf, &ping_mdh,
					    lnet_get_ni_bytes() - net_bytes,
					    false);
		if (rc != 0)
			goto unlock_api_mutex;

		lnet_shutdown_lndnet(net);

		lnet_acceptor_stop();

		lnet_ping_target_update(pbuf, ping_mdh);

		goto unlock_api_mutex;
	}

	ni = lnet_nid_to_ni_locked(nid, 0);
	if (!ni) {
		CERROR("nid %s not found\n", libcfs_nidstr(nid));
		rc = -ENOENT;
		goto unlock_net;
	}

	net_bytes = lnet_get_net_ni_bytes_locked(net);
	net_empty = list_is_singular(&net->net_ni_list);

	lnet_net_unlock(0);

	/* create and link a new ping info, before removing the old one */
	rc = lnet_ping_target_setup(&pbuf, &ping_mdh,
				    (LNET_PING_INFO_HDR_SIZE +
				     lnet_get_ni_bytes() -
				     lnet_ping_sts_size(&ni->ni_nid)),
				    false);
	if (rc != 0)
		goto unlock_api_mutex;

	lnet_shutdown_lndni(ni);

	lnet_acceptor_stop();

	lnet_ping_target_update(pbuf, ping_mdh);

	/* check if the net is empty and remove it if it is */
	if (net_empty)
		lnet_shutdown_lndnet(net);

	goto unlock_api_mutex;

unlock_net:
	lnet_net_unlock(0);
unlock_api_mutex:
	mutex_unlock(&the_lnet.ln_api_mutex);

	return rc;
}

/*
 * lnet_dyn_add_net and lnet_dyn_del_net are now deprecated.
 * They are only expected to be called for unique networks.
 * That can be as a result of older DLC library
 * calls. Multi-Rail DLC and beyond no longer uses these APIs.
 */
int
lnet_dyn_add_net(struct lnet_ioctl_config_data *conf)
{
	struct lnet_net *net;
	LIST_HEAD(net_head);
	int rc;
	struct lnet_ioctl_config_lnd_tunables tun;
	const char *nets = conf->cfg_config_u.cfg_net.net_intf;

	/* Create a net/ni structures for the network string */
	rc = lnet_parse_networks(&net_head, nets);
	if (rc <= 0)
		return rc == 0 ? -EINVAL : rc;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto out_unlock_clean;
	}

	if (rc > 1) {
		rc = -EINVAL; /* only add one network per call */
		goto out_unlock_clean;
	}

	net = list_first_entry(&net_head, struct lnet_net, net_list);
	list_del_init(&net->net_list);

	LASSERT(lnet_net_unique(net->net_id, &the_lnet.ln_nets, NULL));

	memset(&tun, 0, sizeof(tun));

	tun.lt_cmn.lct_peer_timeout =
	 (!conf->cfg_config_u.cfg_net.net_peer_timeout) ? DEFAULT_PEER_TIMEOUT :
	  conf->cfg_config_u.cfg_net.net_peer_timeout;
	tun.lt_cmn.lct_peer_tx_credits =
	 (!conf->cfg_config_u.cfg_net.net_peer_tx_credits) ? DEFAULT_PEER_CREDITS :
	  conf->cfg_config_u.cfg_net.net_peer_tx_credits;
	tun.lt_cmn.lct_peer_rtr_credits =
		conf->cfg_config_u.cfg_net.net_peer_rtr_credits;
	tun.lt_cmn.lct_max_tx_credits =
	 (!conf->cfg_config_u.cfg_net.net_max_tx_credits) ? DEFAULT_CREDITS :
	  conf->cfg_config_u.cfg_net.net_max_tx_credits;

	rc = lnet_add_net_common(net, &tun);

out_unlock_clean:
	mutex_unlock(&the_lnet.ln_api_mutex);
	/* net_head list is empty in success case */
	while ((net = list_first_entry_or_null(&net_head,
					       struct lnet_net,
					       net_list)) != NULL) {
		list_del_init(&net->net_list);
		lnet_net_free(net);
	}
	return rc;
}

int
lnet_dyn_del_net(u32 net_id)
{
	struct lnet_net *net;
	struct lnet_ping_buffer *pbuf;
	struct lnet_handle_md ping_mdh;
	int net_ni_bytes, rc;

	/* don't allow userspace to shutdown the LOLND */
	if (LNET_NETTYP(net_id) == LOLND)
		return -EINVAL;

	mutex_lock(&the_lnet.ln_api_mutex);
	if (the_lnet.ln_state != LNET_STATE_RUNNING) {
		rc = -ESHUTDOWN;
		goto out;
	}

	lnet_net_lock(0);

	net = lnet_get_net_locked(net_id);
	if (!net) {
		lnet_net_unlock(0);
		rc = -EINVAL;
		goto out;
	}

	net_ni_bytes = lnet_get_net_ni_bytes_locked(net);

	lnet_net_unlock(0);

	/* create and link a new ping info, before removing the old one */
	rc = lnet_ping_target_setup(&pbuf, &ping_mdh,
				     LNET_PING_INFO_HDR_SIZE +
				     lnet_get_ni_bytes() - net_ni_bytes,
				     false);
	if (rc)
		goto out;

	lnet_shutdown_lndnet(net);

	lnet_acceptor_stop();

	lnet_ping_target_update(pbuf, ping_mdh);

out:
	mutex_unlock(&the_lnet.ln_api_mutex);

	return rc;
}

void lnet_incr_dlc_seq(void)
{
	atomic_inc(&lnet_dlc_seq_no);
}

u32 lnet_get_dlc_seq_locked(void)
{
	return atomic_read(&lnet_dlc_seq_no);
}

static void
lnet_ni_set_healthv(lnet_nid_t nid, int value, bool all)
{
	struct lnet_net *net;
	struct lnet_ni *ni;

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (all || (nid_is_nid4(&ni->ni_nid) &&
				    lnet_nid_to_nid4(&ni->ni_nid) == nid)) {
				atomic_set(&ni->ni_healthv, value);
				if (list_empty(&ni->ni_recovery) &&
				    value < LNET_MAX_HEALTH_VALUE) {
					CERROR("manually adding local NI %s to recovery\n",
					       libcfs_nidstr(&ni->ni_nid));
					list_add_tail(&ni->ni_recovery,
						      &the_lnet.ln_mt_localNIRecovq);
					lnet_ni_addref_locked(ni, 0);
				}
				if (!all) {
					lnet_net_unlock(LNET_LOCK_EX);
					return;
				}
			}
		}
	}
	lnet_net_unlock(LNET_LOCK_EX);
}

static void
lnet_ni_set_conns_per_peer(lnet_nid_t nid, int value, bool all)
{
	struct lnet_net *net;
	struct lnet_ni *ni;

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (lnet_nid_to_nid4(&ni->ni_nid) != nid && !all)
				continue;
			if (LNET_NETTYP(net->net_id) == SOCKLND)
				ni->ni_lnd_tunables.lnd_tun_u.lnd_sock.lnd_conns_per_peer = value;
			else if (LNET_NETTYP(net->net_id) == O2IBLND)
				ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib.lnd_conns_per_peer = value;
			if (!all) {
				lnet_net_unlock(LNET_LOCK_EX);
				return;
			}
		}
	}
	lnet_net_unlock(LNET_LOCK_EX);
}

static int
lnet_get_local_ni_hstats(struct lnet_ioctl_local_ni_hstats *stats)
{
	int cpt, rc = 0;
	struct lnet_ni *ni;
	lnet_nid_t nid = stats->hlni_nid;

	cpt = lnet_net_lock_current();
	ni = lnet_nid2ni_locked(nid, cpt);

	if (!ni) {
		rc = -ENOENT;
		goto unlock;
	}

	stats->hlni_local_interrupt =
		atomic_read(&ni->ni_hstats.hlt_local_interrupt);
	stats->hlni_local_dropped =
		atomic_read(&ni->ni_hstats.hlt_local_dropped);
	stats->hlni_local_aborted =
		atomic_read(&ni->ni_hstats.hlt_local_aborted);
	stats->hlni_local_no_route =
		atomic_read(&ni->ni_hstats.hlt_local_no_route);
	stats->hlni_local_timeout =
		atomic_read(&ni->ni_hstats.hlt_local_timeout);
	stats->hlni_local_error =
		atomic_read(&ni->ni_hstats.hlt_local_error);
	stats->hlni_fatal_error =
		atomic_read(&ni->ni_fatal_error_on);
	stats->hlni_health_value =
		atomic_read(&ni->ni_healthv);
	stats->hlni_ping_count = ni->ni_ping_count;
	stats->hlni_next_ping = ni->ni_next_ping;

unlock:
	lnet_net_unlock(cpt);

	return rc;
}

static int
lnet_get_local_ni_recovery_list(struct lnet_ioctl_recovery_list *list)
{
	struct lnet_ni *ni;
	int i = 0;

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(ni, &the_lnet.ln_mt_localNIRecovq, ni_recovery) {
		if (!nid_is_nid4(&ni->ni_nid))
			continue;
		list->rlst_nid_array[i] = lnet_nid_to_nid4(&ni->ni_nid);
		i++;
		if (i >= LNET_MAX_SHOW_NUM_NID)
			break;
	}
	lnet_net_unlock(LNET_LOCK_EX);
	list->rlst_num_nids = i;

	return 0;
}

static int
lnet_get_peer_ni_recovery_list(struct lnet_ioctl_recovery_list *list)
{
	struct lnet_peer_ni *lpni;
	int i = 0;

	lnet_net_lock(LNET_LOCK_EX);
	list_for_each_entry(lpni, &the_lnet.ln_mt_peerNIRecovq, lpni_recovery) {
		list->rlst_nid_array[i] = lnet_nid_to_nid4(&lpni->lpni_nid);
		i++;
		if (i >= LNET_MAX_SHOW_NUM_NID)
			break;
	}
	lnet_net_unlock(LNET_LOCK_EX);
	list->rlst_num_nids = i;

	return 0;
}

/**
 * LNet ioctl handler.
 *
 */
int
LNetCtl(unsigned int cmd, void *arg)
{
	struct libcfs_ioctl_data *data = arg;
	struct lnet_ioctl_config_data *config;
	struct lnet_ni *ni;
	struct lnet_nid nid;
	int rc;

	BUILD_BUG_ON(LIBCFS_IOC_DATA_MAX <
		     sizeof(struct lnet_ioctl_net_config) +
		     sizeof(struct lnet_ioctl_config_data));

	switch (cmd) {
	case IOC_LIBCFS_FAIL_NID:
		return lnet_fail_nid(data->ioc_nid, data->ioc_count);

	case IOC_LIBCFS_ADD_ROUTE: {
		/* default router sensitivity to 1 */
		unsigned int sensitivity = 1;
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		if (config->cfg_config_u.cfg_route.rtr_sensitivity) {
			sensitivity =
			  config->cfg_config_u.cfg_route.rtr_sensitivity;
		}

		lnet_nid4_to_nid(config->cfg_nid, &nid);
		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_add_route(config->cfg_net,
				    config->cfg_config_u.cfg_route.rtr_hop,
				    &nid,
				    config->cfg_config_u.cfg_route.rtr_priority,
				    sensitivity);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_DEL_ROUTE:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		lnet_nid4_to_nid(config->cfg_nid, &nid);
		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_del_route(config->cfg_net, &nid);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;

	case IOC_LIBCFS_GET_ROUTE:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_route(config->cfg_count,
				    &config->cfg_net,
				    &config->cfg_config_u.cfg_route.rtr_hop,
				    &config->cfg_nid,
				    &config->cfg_config_u.cfg_route.rtr_flags,
				    &config->cfg_config_u.cfg_route.rtr_priority,
				    &config->cfg_config_u.cfg_route.rtr_sensitivity);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;

	case IOC_LIBCFS_GET_LOCAL_NI: {
		struct lnet_ioctl_config_ni *cfg_ni;
		struct lnet_ioctl_config_lnd_tunables *tun = NULL;
		struct lnet_ioctl_element_stats *stats;
		u32 tun_size;

		cfg_ni = arg;

		/* get the tunables if they are available */
		if (cfg_ni->lic_cfg_hdr.ioc_len <
		    sizeof(*cfg_ni) + sizeof(*stats) + sizeof(*tun))
			return -EINVAL;

		stats = (struct lnet_ioctl_element_stats *)
			cfg_ni->lic_bulk;
		tun = (struct lnet_ioctl_config_lnd_tunables *)
				(cfg_ni->lic_bulk + sizeof(*stats));

		tun_size = cfg_ni->lic_cfg_hdr.ioc_len - sizeof(*cfg_ni) -
			sizeof(*stats);

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_ni_config(cfg_ni, tun, stats, tun_size);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_LOCAL_NI_MSG_STATS: {
		struct lnet_ioctl_element_msg_stats *msg_stats = arg;

		if (msg_stats->im_hdr.ioc_len != sizeof(*msg_stats))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_ni_stats(msg_stats);
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_NET: {
		size_t total = sizeof(*config) +
			       sizeof(struct lnet_ioctl_net_config);
		config = arg;

		if (config->cfg_hdr.ioc_len < total)
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_net_config(config);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_LNET_STATS: {
		struct lnet_ioctl_lnet_stats *lnet_stats = arg;

		if (lnet_stats->st_hdr.ioc_len < sizeof(*lnet_stats))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_counters_get(&lnet_stats->st_cntrs);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_RESET_LNET_STATS:
	{
		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_counters_reset();
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	case IOC_LIBCFS_CONFIG_RTR:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		if (config->cfg_config_u.cfg_buffers.buf_enable) {
			rc = lnet_rtrpools_enable();
			mutex_unlock(&the_lnet.ln_api_mutex);
			return rc;
		}
		lnet_rtrpools_disable();
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;

	case IOC_LIBCFS_ADD_BUF:
		config = arg;

		if (config->cfg_hdr.ioc_len < sizeof(*config))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_rtrpools_adjust(config->cfg_config_u.cfg_buffers.buf_tiny,
					  config->cfg_config_u.cfg_buffers.buf_small,
					  config->cfg_config_u.cfg_buffers.buf_large);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;

	case IOC_LIBCFS_SET_NUMA_RANGE: {
		struct lnet_ioctl_set_value *numa;

		numa = arg;
		if (numa->sv_hdr.ioc_len != sizeof(*numa))
			return -EINVAL;
		lnet_net_lock(LNET_LOCK_EX);
		lnet_numa_range = numa->sv_value;
		lnet_net_unlock(LNET_LOCK_EX);
		return 0;
	}

	case IOC_LIBCFS_GET_NUMA_RANGE: {
		struct lnet_ioctl_set_value *numa;

		numa = arg;
		if (numa->sv_hdr.ioc_len != sizeof(*numa))
			return -EINVAL;
		numa->sv_value = lnet_numa_range;
		return 0;
	}

	case IOC_LIBCFS_GET_BUF: {
		struct lnet_ioctl_pool_cfg *pool_cfg;
		size_t total = sizeof(*config) + sizeof(*pool_cfg);

		config = arg;

		if (config->cfg_hdr.ioc_len < total)
			return -EINVAL;

		pool_cfg = (struct lnet_ioctl_pool_cfg *)config->cfg_bulk;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_rtr_pool_cfg(config->cfg_count, pool_cfg);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_LOCAL_HSTATS: {
		struct lnet_ioctl_local_ni_hstats *stats = arg;

		if (stats->hlni_hdr.ioc_len < sizeof(*stats))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_local_ni_hstats(stats);
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_RECOVERY_QUEUE: {
		struct lnet_ioctl_recovery_list *list = arg;

		if (list->rlst_hdr.ioc_len < sizeof(*list))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		if (list->rlst_type == LNET_HEALTH_TYPE_LOCAL_NI)
			rc = lnet_get_local_ni_recovery_list(list);
		else
			rc = lnet_get_peer_ni_recovery_list(list);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_ADD_PEER_NI: {
		struct lnet_ioctl_peer_cfg *cfg = arg;
		struct lnet_nid prim_nid;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_nid4_to_nid(cfg->prcfg_prim_nid, &prim_nid);
		lnet_nid4_to_nid(cfg->prcfg_cfg_nid, &nid);
		rc = lnet_add_peer_ni(&prim_nid, &nid, cfg->prcfg_mr, false);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_DEL_PEER_NI: {
		struct lnet_ioctl_peer_cfg *cfg = arg;
		struct lnet_nid prim_nid;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_nid4_to_nid(cfg->prcfg_prim_nid, &prim_nid);
		lnet_nid4_to_nid(cfg->prcfg_cfg_nid, &nid);
		rc = lnet_del_peer_ni(&prim_nid,
				      &nid);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_PEER_INFO: {
		struct lnet_ioctl_peer *peer_info = arg;

		if (peer_info->pr_hdr.ioc_len < sizeof(*peer_info))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_peer_ni_info(
			peer_info->pr_count,
			&peer_info->pr_nid,
			peer_info->pr_lnd_u.pr_peer_credits.cr_aliveness,
			&peer_info->pr_lnd_u.pr_peer_credits.cr_ncpt,
			&peer_info->pr_lnd_u.pr_peer_credits.cr_refcount,
			&peer_info->pr_lnd_u.pr_peer_credits.cr_ni_peer_tx_credits,
			&peer_info->pr_lnd_u.pr_peer_credits.cr_peer_tx_credits,
			&peer_info->pr_lnd_u.pr_peer_credits.cr_peer_rtr_credits,
			&peer_info->pr_lnd_u.pr_peer_credits.cr_peer_min_tx_credits,
			&peer_info->pr_lnd_u.pr_peer_credits.cr_peer_tx_qnob);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_PEER_NI: {
		struct lnet_ioctl_peer_cfg *cfg = arg;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_peer_info(cfg,
					(void __user *)cfg->prcfg_bulk);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_GET_PEER_LIST: {
		struct lnet_ioctl_peer_cfg *cfg = arg;

		if (cfg->prcfg_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_get_peer_list(&cfg->prcfg_count, &cfg->prcfg_size,
					(struct lnet_process_id __user *)
					cfg->prcfg_bulk);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return rc;
	}

	case IOC_LIBCFS_SET_HEALHV: {
		struct lnet_ioctl_reset_health_cfg *cfg = arg;
		int value;

		if (cfg->rh_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;
		if (cfg->rh_value < 0 ||
		    cfg->rh_value > LNET_MAX_HEALTH_VALUE)
			value = LNET_MAX_HEALTH_VALUE;
		else
			value = cfg->rh_value;
		CDEBUG(D_NET,
		       "Manually setting healthv to %d for %s:%s. all = %d\n",
		       value,
		       (cfg->rh_type == LNET_HEALTH_TYPE_LOCAL_NI) ?
		       "local" : "peer",
		       libcfs_nid2str(cfg->rh_nid), cfg->rh_all);
		mutex_lock(&the_lnet.ln_api_mutex);
		if (cfg->rh_type == LNET_HEALTH_TYPE_LOCAL_NI)
			lnet_ni_set_healthv(cfg->rh_nid, value,
					    cfg->rh_all);
		else
			lnet_peer_ni_set_healthv(cfg->rh_nid, value,
						 cfg->rh_all);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	case IOC_LIBCFS_SET_CONNS_PER_PEER: {
		struct lnet_ioctl_reset_conns_per_peer_cfg *cfg = arg;
		int value;

		if (cfg->rcpp_hdr.ioc_len < sizeof(*cfg))
			return -EINVAL;
		if (cfg->rcpp_value < 0)
			value = 1;
		else
			value = cfg->rcpp_value;
		CDEBUG(D_NET,
		       "Setting conns_per_peer to %d for %s. all = %d\n",
		       value, libcfs_nid2str(cfg->rcpp_nid), cfg->rcpp_all);
		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_ni_set_conns_per_peer(cfg->rcpp_nid, value, cfg->rcpp_all);
		mutex_unlock(&the_lnet.ln_api_mutex);
		return 0;
	}

	case IOC_LIBCFS_NOTIFY_ROUTER: {
		time64_t deadline = ktime_get_real_seconds() - data->ioc_u64[0];

		/* The deadline passed in by the user should be some time in
		 * seconds in the future since the UNIX epoch. We have to map
		 * that deadline to the wall clock.
		 */
		deadline += ktime_get_seconds();
		return lnet_notify(NULL, data->ioc_nid, data->ioc_flags, false,
				   deadline);
	}

	case IOC_LIBCFS_LNET_DIST:
		lnet_nid4_to_nid(data->ioc_nid, &nid);
		rc = LNetDist(&nid, &nid, &data->ioc_u32[1]);
		if (rc < 0 && rc != -EHOSTUNREACH)
			return rc;

		data->ioc_nid = lnet_nid_to_nid4(&nid);
		data->ioc_u32[0] = rc;
		return 0;

	case IOC_LIBCFS_TESTPROTOCOMPAT:
		the_lnet.ln_testprotocompat = data->ioc_flags;
		return 0;

	case IOC_LIBCFS_LNET_FAULT:
		return lnet_fault_ctl(data->ioc_flags, data);

	case IOC_LIBCFS_PING: {
		struct lnet_process_id id4;
		signed long timeout;

		id4.nid = data->ioc_nid;
		id4.pid = data->ioc_u32[0];

		/* If timeout is negative then set default of 3 minutes */
		if (((s32)data->ioc_u32[1] <= 0) ||
		    data->ioc_u32[1] > (DEFAULT_PEER_TIMEOUT * MSEC_PER_SEC))
			timeout = DEFAULT_PEER_TIMEOUT * HZ;
		else
			timeout = msecs_to_jiffies(data->ioc_u32[1]);

		rc = lnet_ping(id4, &LNET_ANY_NID, timeout, data->ioc_pbuf1,
			       data->ioc_plen1 / sizeof(struct lnet_process_id));

		if (rc < 0)
			return rc;

		data->ioc_count = rc;
		return 0;
	}

	case IOC_LIBCFS_PING_PEER: {
		struct lnet_ioctl_ping_data *ping = arg;
		struct lnet_nid src_nid = LNET_ANY_NID;
		struct lnet_peer *lp;
		signed long timeout;

		/* Check if the supplied ping data supports source nid
		 * NB: This check is sufficient if lnet_ioctl_ping_data has
		 * additional fields added, but if they are re-ordered or
		 * fields removed then this will break. It is expected that
		 * these ioctls will be replaced with netlink implementation, so
		 * it is probably not worth coming up with a more robust version
		 * compatibility scheme.
		 */
		if (ping->ping_hdr.ioc_len >=
		    sizeof(struct lnet_ioctl_ping_data))
			lnet_nid4_to_nid(ping->ping_src, &src_nid);

		/* If timeout is negative then set default of 3 minutes */
		if (((s32)ping->op_param) <= 0 ||
		    ping->op_param > (DEFAULT_PEER_TIMEOUT * MSEC_PER_SEC))
			timeout = DEFAULT_PEER_TIMEOUT * HZ;
		else
			timeout = msecs_to_jiffies(ping->op_param);

		rc = lnet_ping(ping->ping_id, &src_nid, timeout,
			       ping->ping_buf,
			       ping->ping_count);
		if (rc < 0)
			return rc;

		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_nid4_to_nid(ping->ping_id.nid, &nid);
		lp = lnet_find_peer(&nid);
		if (lp) {
			ping->ping_id.nid =
				lnet_nid_to_nid4(&lp->lp_primary_nid);
			ping->mr_info = lnet_peer_is_multi_rail(lp);
			lnet_peer_decref_locked(lp);
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		ping->ping_count = rc;
		return 0;
	}

	case IOC_LIBCFS_DISCOVER: {
		struct lnet_ioctl_ping_data *discover = arg;
		struct lnet_peer *lp;

		rc = lnet_discover(discover->ping_id, discover->op_param,
				   discover->ping_buf,
				   discover->ping_count);
		if (rc < 0)
			return rc;

		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_nid4_to_nid(discover->ping_id.nid, &nid);
		lp = lnet_find_peer(&nid);
		if (lp) {
			discover->ping_id.nid =
				lnet_nid_to_nid4(&lp->lp_primary_nid);
			discover->mr_info = lnet_peer_is_multi_rail(lp);
			lnet_peer_decref_locked(lp);
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		discover->ping_count = rc;
		return 0;
	}

	case IOC_LIBCFS_ADD_UDSP: {
		struct lnet_ioctl_udsp *ioc_udsp = arg;
		u32 bulk_size = ioc_udsp->iou_hdr.ioc_len;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_udsp_demarshal_add(arg, bulk_size);
		if (!rc) {
			rc = lnet_udsp_apply_policies(NULL, false);
			CDEBUG(D_NET, "policy application returned %d\n", rc);
			rc = 0;
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_DEL_UDSP: {
		struct lnet_ioctl_udsp *ioc_udsp = arg;
		int idx = ioc_udsp->iou_idx;

		if (ioc_udsp->iou_hdr.ioc_len < sizeof(*ioc_udsp))
			return -EINVAL;

		mutex_lock(&the_lnet.ln_api_mutex);
		rc = lnet_udsp_del_policy(idx);
		if (!rc) {
			rc = lnet_udsp_apply_policies(NULL, false);
			CDEBUG(D_NET, "policy re-application returned %d\n",
			       rc);
			rc = 0;
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_UDSP_SIZE: {
		struct lnet_ioctl_udsp *ioc_udsp = arg;
		struct lnet_udsp *udsp;

		if (ioc_udsp->iou_hdr.ioc_len < sizeof(*ioc_udsp))
			return -EINVAL;

		rc = 0;

		mutex_lock(&the_lnet.ln_api_mutex);
		udsp = lnet_udsp_get_policy(ioc_udsp->iou_idx);
		if (!udsp) {
			rc = -ENOENT;
		} else {
			/* coming in iou_idx will hold the idx of the udsp
			 * to get the size of. going out the iou_idx will
			 * hold the size of the UDSP found at the passed
			 * in index.
			 */
			ioc_udsp->iou_idx = lnet_get_udsp_size(udsp);
			if (ioc_udsp->iou_idx < 0)
				rc = -EINVAL;
		}
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_UDSP: {
		struct lnet_ioctl_udsp *ioc_udsp = arg;
		struct lnet_udsp *udsp;

		if (ioc_udsp->iou_hdr.ioc_len < sizeof(*ioc_udsp))
			return -EINVAL;

		rc = 0;

		mutex_lock(&the_lnet.ln_api_mutex);
		udsp = lnet_udsp_get_policy(ioc_udsp->iou_idx);
		if (!udsp)
			rc = -ENOENT;
		else
			rc = lnet_udsp_marshal(udsp, ioc_udsp);
		mutex_unlock(&the_lnet.ln_api_mutex);

		return rc;
	}

	case IOC_LIBCFS_GET_CONST_UDSP_INFO: {
		struct lnet_ioctl_construct_udsp_info *info = arg;

		if (info->cud_hdr.ioc_len < sizeof(*info))
			return -EINVAL;

		CDEBUG(D_NET, "GET_UDSP_INFO for %s\n",
		       libcfs_nid2str(info->cud_nid));

		mutex_lock(&the_lnet.ln_api_mutex);
		lnet_udsp_get_construct_info(info);
		mutex_unlock(&the_lnet.ln_api_mutex);

		return 0;
	}

	default:
		ni = lnet_net2ni_addref(data->ioc_net);
		if (!ni)
			return -EINVAL;

		if (!ni->ni_net->net_lnd->lnd_ctl)
			rc = -EINVAL;
		else
			rc = ni->ni_net->net_lnd->lnd_ctl(ni, cmd, arg);

		lnet_ni_decref(ni);
		return rc;
	}
	/* not reached */
}
EXPORT_SYMBOL(LNetCtl);

static const struct ln_key_list net_props_list = {
	.lkl_maxattr			= LNET_NET_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_ATTR_HDR]		= {
			.lkp_value		= "net",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_NET_ATTR_TYPE]		= {
			.lkp_value		= "net type",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_NET_ATTR_LOCAL]           = {
			.lkp_value		= "local NI(s)",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
	},
};

static struct ln_key_list local_ni_list = {
	.lkl_maxattr			= LNET_NET_LOCAL_NI_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_LOCAL_NI_ATTR_NID]	= {
			.lkp_value		= "nid",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_NET_LOCAL_NI_ATTR_STATUS] = {
			.lkp_value		= "status",
			.lkp_data_type		= NLA_STRING
		},
		[LNET_NET_LOCAL_NI_ATTR_INTERFACE] = {
			.lkp_value		= "interfaces",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED
		},
	},
};

static const struct ln_key_list local_ni_interfaces_list = {
	.lkl_maxattr			= LNET_NET_LOCAL_NI_INTF_ATTR_MAX,
	.lkl_list			= {
		[LNET_NET_LOCAL_NI_INTF_ATTR_TYPE] = {
			.lkp_value	= "0",
			.lkp_data_type	= NLA_STRING
		},
	},
};

/* Use an index since the traversal is across LNet nets and ni collections */
struct lnet_genl_net_list {
	unsigned int	lngl_net_id;
	unsigned int	lngl_idx;
};

static inline struct lnet_genl_net_list *
lnet_net_dump_ctx(struct netlink_callback *cb)
{
	return (struct lnet_genl_net_list *)cb->args[0];
}

static int lnet_net_show_done(struct netlink_callback *cb)
{
	struct lnet_genl_net_list *nlist = lnet_net_dump_ctx(cb);

	kfree(nlist);
	cb->args[0] = 0;

	return 0;
}

/* LNet net ->start() handler for GET requests */
static int lnet_net_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
	struct netlink_ext_ack *extack = cb->extack;
	struct lnet_genl_net_list *nlist;
	int msg_len = genlmsg_len(gnlh);
	struct nlattr *params, *top;
	int rem, rc = 0;

	if (the_lnet.ln_refcount == 0) {
		NL_SET_ERR_MSG(extack, "LNet stack down");
		return -ENETDOWN;
	}

	nlist = kmalloc(sizeof(*nlist), GFP_KERNEL);
	if (!nlist)
		return -ENOMEM;

	nlist->lngl_net_id = LNET_NET_ANY;
	nlist->lngl_idx = 0;
	cb->args[0] = (long)nlist;

	if (!msg_len)
		return 0;

	params = genlmsg_data(gnlh);
	nla_for_each_attr(top, params, msg_len, rem) {
		struct nlattr *net;
		int rem2;

		nla_for_each_nested(net, top, rem2) {
			char filter[LNET_NIDSTR_SIZE];

			if (nla_type(net) != LN_SCALAR_ATTR_VALUE ||
			    nla_strcmp(net, "name") != 0)
				continue;

			net = nla_next(net, &rem2);
			if (nla_type(net) != LN_SCALAR_ATTR_VALUE) {
				NL_SET_ERR_MSG(extack, "invalid config param");
				rc = -EINVAL;
				goto report_err;
			}

			rc = nla_strlcpy(filter, net, sizeof(filter));
			if (rc < 0) {
				NL_SET_ERR_MSG(extack, "failed to get param");
				goto report_err;
			}
			rc = 0;

			nlist->lngl_net_id = libcfs_str2net(filter);
			if (nlist->lngl_net_id == LNET_NET_ANY) {
				NL_SET_ERR_MSG(extack, "cannot parse net");
				rc = -ENOENT;
				goto report_err;
			}
		}
	}
report_err:
	if (rc < 0)
		lnet_net_show_done(cb);

	return rc;
}

static int lnet_net_show_dump(struct sk_buff *msg,
			      struct netlink_callback *cb)
{
	struct lnet_genl_net_list *nlist = lnet_net_dump_ctx(cb);
	struct netlink_ext_ack *extack = cb->extack;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	struct lnet_net *net;
	int idx = 0, rc = 0;
	bool found = false;
	void *hdr = NULL;

	if (!nlist->lngl_idx) {
		const struct ln_key_list *all[] = {
			&net_props_list, &local_ni_list,
			&local_ni_interfaces_list,
			NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lnet_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_CMD_NETS, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			goto send_error;
		}
	}

	lnet_net_lock(LNET_LOCK_EX);

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		struct lnet_ni *ni;

		if (nlist->lngl_net_id != LNET_NET_ANY &&
		    nlist->lngl_net_id != net->net_id)
			continue;

		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			struct nlattr *local_ni, *ni_attr;
			char *status = "up";

			if (idx++ < nlist->lngl_idx)
				continue;

			hdr = genlmsg_put(msg, portid, seq, &lnet_family,
					  NLM_F_MULTI, LNET_CMD_NETS);
			if (!hdr) {
				NL_SET_ERR_MSG(extack, "failed to send values");
				rc = -EMSGSIZE;
				goto net_unlock;
			}

			if (idx == 1)
				nla_put_string(msg, LNET_NET_ATTR_HDR, "");

			nla_put_string(msg, LNET_NET_ATTR_TYPE,
				       libcfs_net2str(net->net_id));
			found = true;

			local_ni = nla_nest_start(msg, LNET_NET_ATTR_LOCAL);
			ni_attr = nla_nest_start(msg, idx - 1);

			lnet_ni_lock(ni);
			nla_put_string(msg, LNET_NET_LOCAL_NI_ATTR_NID,
				       libcfs_nidstr(&ni->ni_nid));
			if (nid_is_lo0(&ni->ni_nid) &&
			    *ni->ni_status != LNET_NI_STATUS_UP)
				status = "down";
			nla_put_string(msg, LNET_NET_LOCAL_NI_ATTR_STATUS, "up");

			if (!nid_is_lo0(&ni->ni_nid) && ni->ni_interface) {
				struct nlattr *intf_nest, *intf_attr;

				intf_nest = nla_nest_start(msg,
							   LNET_NET_LOCAL_NI_ATTR_INTERFACE);
				intf_attr = nla_nest_start(msg, 0);
				nla_put_string(msg,
					       LNET_NET_LOCAL_NI_INTF_ATTR_TYPE,
					       ni->ni_interface);
				nla_nest_end(msg, intf_attr);
				nla_nest_end(msg, intf_nest);
			}

			lnet_ni_unlock(ni);
			nla_nest_end(msg, ni_attr);
			nla_nest_end(msg, local_ni);

			genlmsg_end(msg, hdr);
		}
	}

	if (!found) {
		struct nlmsghdr *nlh = nlmsg_hdr(msg);

		nlmsg_cancel(msg, nlh);
		NL_SET_ERR_MSG(extack, "Network is down");
		rc = -ESRCH;
	}
net_unlock:
	lnet_net_unlock(LNET_LOCK_EX);
send_error:
	nlist->lngl_idx = idx;

	return rc;
}

static int lnet_genl_parse_tunables(struct nlattr *settings,
				    struct lnet_ioctl_config_lnd_tunables *tun)
{
	struct nlattr *param;
	int rem, rc = 0;

	nla_for_each_nested(param, settings, rem) {
		int type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_UNSPEC;
		s64 num;

		if (nla_type(param) != LN_SCALAR_ATTR_VALUE)
			continue;

		if (nla_strcmp(param, "peer_timeout") == 0)
			type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_TIMEOUT;
		else if (nla_strcmp(param, "peer_credits") == 0)
			type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_CREDITS;
		else if (nla_strcmp(param, "peer_buffer_credits") == 0)
			type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_BUFFER_CREDITS;
		else if (nla_strcmp(param, "credits") == 0)
			type = LNET_NET_LOCAL_NI_TUNABLES_ATTR_CREDITS;

		param = nla_next(param, &rem);
		if (nla_type(param) != LN_SCALAR_ATTR_INT_VALUE)
			return -EINVAL;

		num = nla_get_s64(param);
		switch (type) {
		case LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_TIMEOUT:
			tun->lt_cmn.lct_peer_timeout = num;
			break;
		case LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_CREDITS:
			tun->lt_cmn.lct_peer_tx_credits = num;
			break;
		case LNET_NET_LOCAL_NI_TUNABLES_ATTR_PEER_BUFFER_CREDITS:
			tun->lt_cmn.lct_peer_rtr_credits = num;
			break;
		case LNET_NET_LOCAL_NI_TUNABLES_ATTR_CREDITS:
			tun->lt_cmn.lct_max_tx_credits = num;
			break;
		default:
			rc = -EINVAL;
			break;
		}
	}
	return rc;
}

static int
lnet_genl_parse_lnd_tunables(struct nlattr *settings,
			     struct lnet_ioctl_config_lnd_tunables *tun,
			     const struct lnet_lnd *lnd)
{
	const struct ln_key_list *list = lnd->lnd_keys;
	struct nlattr *param;
	int rem, rc = 0;
	int i = 1;

	if (!list)
		return 0;

	if (!lnd->lnd_nl_set)
		return -EOPNOTSUPP;

	if (!list->lkl_maxattr)
		return -ERANGE;

	nla_for_each_nested(param, settings, rem) {
		if (nla_type(param) != LN_SCALAR_ATTR_VALUE)
			continue;

		for (i = 1; i <= list->lkl_maxattr; i++) {
			if (!list->lkl_list[i].lkp_value ||
			    nla_strcmp(param, list->lkl_list[i].lkp_value) != 0)
				continue;

			param = nla_next(param, &rem);
			rc = lnd->lnd_nl_set(LNET_CMD_NETS, param, i, tun);
			if (rc < 0)
				return rc;
		}
	}

	return rc;
}

static int
lnet_genl_parse_local_ni(struct nlattr *entry, struct genl_info *info,
			 int net_id, struct lnet_ioctl_config_ni *conf,
			 struct lnet_ioctl_config_lnd_tunables *tun,
			 bool *ni_list)
{
	struct nlattr *settings;
	int rem3, rc = 0;

	nla_for_each_nested(settings, entry, rem3) {
		if (nla_type(settings) != LN_SCALAR_ATTR_VALUE)
			continue;

		if (nla_strcmp(settings, "interfaces") == 0) {
			struct nlattr *intf;
			int rem4;

			settings = nla_next(settings, &rem3);
			if (nla_type(settings) !=
			    LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "invalid interfaces");
				rc = -EINVAL;
				goto out;
			}

			nla_for_each_nested(intf, settings, rem4) {
				intf = nla_next(intf, &rem4);
				if (nla_type(intf) !=
				    LN_SCALAR_ATTR_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "0 key is invalid");
					rc = -EINVAL;
					goto out;
				}

				rc = nla_strlcpy(conf->lic_ni_intf, intf,
						 sizeof(conf->lic_ni_intf));
				if (rc < 0) {
					GENL_SET_ERR_MSG(info,
							 "failed to parse interfaces");
					goto out;
				}
			}
			*ni_list = true;
		} else if (nla_strcmp(settings, "tunables") == 0) {
			settings = nla_next(settings, &rem3);
			if (nla_type(settings) !=
			    LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "invalid tunables");
				rc = -EINVAL;
				goto out;
			}

			rc = lnet_genl_parse_tunables(settings, tun);
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "failed to parse tunables");
				goto out;
			}
		} else if ((nla_strcmp(settings, "lnd tunables") == 0)) {
			const struct lnet_lnd *lnd;

			lnd = lnet_load_lnd(LNET_NETTYP(net_id));
			if (IS_ERR(lnd)) {
				GENL_SET_ERR_MSG(info,
						 "LND type not supported");
				rc = PTR_ERR(lnd);
				goto out;
			}

			settings = nla_next(settings, &rem3);
			if (nla_type(settings) !=
			    LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "lnd tunables should be list\n");
				rc = -EINVAL;
				goto out;
			}

			rc = lnet_genl_parse_lnd_tunables(settings,
							  tun, lnd);
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "failed to parse lnd tunables");
				goto out;
			}
		} else if (nla_strcmp(settings, "CPT") == 0) {
			struct nlattr *cpt;
			int rem4;

			settings = nla_next(settings, &rem3);
			if (nla_type(settings) != LN_SCALAR_ATTR_LIST) {
				GENL_SET_ERR_MSG(info,
						 "CPT should be list");
				rc = -EINVAL;
				goto out;
			}

			nla_for_each_nested(cpt, settings, rem4) {
				s64 core;

				if (nla_type(cpt) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					GENL_SET_ERR_MSG(info,
							 "invalid CPT config");
					rc = -EINVAL;
					goto out;
				}

				core = nla_get_s64(cpt);
				if (core >= LNET_CPT_NUMBER) {
					GENL_SET_ERR_MSG(info,
							 "invalid CPT value");
					rc = -ERANGE;
					goto out;
				}

				conf->lic_cpts[conf->lic_ncpts] = core;
				conf->lic_ncpts++;
			}
		}
	}
out:
	return rc;
}

static int lnet_net_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *params = genlmsg_data(gnlh);
	int msg_len, rem, rc = 0;
	struct nlattr *attr;

	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		GENL_SET_ERR_MSG(info, "no configuration");
		return -ENOMSG;
	}

	nla_for_each_attr(attr, params, msg_len, rem) {
		struct lnet_ioctl_config_ni conf;
		u32 net_id = LNET_NET_ANY;
		struct nlattr *entry;
		bool ni_list = false;
		int rem2;

		if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
			continue;

		nla_for_each_nested(entry, attr, rem2) {
			switch (nla_type(entry)) {
			case LN_SCALAR_ATTR_VALUE: {
				ssize_t len;

				memset(&conf, 0, sizeof(conf));
				if (nla_strcmp(entry, "ip2net") == 0) {
					entry = nla_next(entry, &rem2);
					if (nla_type(entry) !=
					    LN_SCALAR_ATTR_VALUE) {
						GENL_SET_ERR_MSG(info,
								 "ip2net has invalid key");
						rc = -EINVAL;
						goto out;
					}

					len = nla_strlcpy(conf.lic_legacy_ip2nets,
							  entry,
							  sizeof(conf.lic_legacy_ip2nets));
					if (len < 0) {
						GENL_SET_ERR_MSG(info,
								 "ip2net key string is invalid");
						rc = len;
						goto out;
					}
					ni_list = true;
				} else if (nla_strcmp(entry, "net type") == 0) {
					char tmp[LNET_NIDSTR_SIZE];

					entry = nla_next(entry, &rem2);
					if (nla_type(entry) !=
					    LN_SCALAR_ATTR_VALUE) {
						GENL_SET_ERR_MSG(info,
								 "net type has invalid key");
						rc = -EINVAL;
						goto out;
					}

					len = nla_strlcpy(tmp, entry,
							  sizeof(tmp));
					if (len < 0) {
						GENL_SET_ERR_MSG(info,
								 "net type key string is invalid");
						rc = len;
						goto out;
					}

					net_id = libcfs_str2net(tmp);
					if (!net_id) {
						GENL_SET_ERR_MSG(info,
								 "cannot parse net");
						rc = -ENODEV;
						goto out;
					}
					if (LNET_NETTYP(net_id) == LOLND) {
						GENL_SET_ERR_MSG(info,
								 "setting @lo not allowed");
						rc = -ENODEV;
						goto out;
					}
					conf.lic_legacy_ip2nets[0] = '\0';
					conf.lic_ni_intf[0] = '\0';
					ni_list = false;
				}
				if (rc < 0)
					goto out;
				break;
			}
			case LN_SCALAR_ATTR_LIST: {
				bool create = info->nlhdr->nlmsg_flags &
					      NLM_F_CREATE;
				struct lnet_ioctl_config_lnd_tunables tun;

				memset(&tun, 0, sizeof(tun));
				tun.lt_cmn.lct_peer_timeout = -1;
				conf.lic_ncpts = 0;

				rc = lnet_genl_parse_local_ni(entry, info,
							      net_id, &conf,
							      &tun, &ni_list);
				if (rc < 0)
					goto out;

				if (!create) {
					struct lnet_net *net;
					struct lnet_ni *ni;

					rc = -ENODEV;
					if (!strlen(conf.lic_ni_intf)) {
						GENL_SET_ERR_MSG(info,
								 "interface is missing");
						goto out;
					}

					lnet_net_lock(LNET_LOCK_EX);
					net = lnet_get_net_locked(net_id);
					if (!net) {
						GENL_SET_ERR_MSG(info,
								 "LNet net doesn't exist");
						goto out;
					}
					list_for_each_entry(ni, &net->net_ni_list,
							    ni_netlist) {
						if (!ni->ni_interface ||
						    strncmp(ni->ni_interface,
							    conf.lic_ni_intf,
							    strlen(conf.lic_ni_intf)) != 0) {
							ni = NULL;
							continue;
						}

						lnet_net_unlock(LNET_LOCK_EX);
						rc = lnet_dyn_del_ni(&ni->ni_nid);
						lnet_net_lock(LNET_LOCK_EX);
						if (rc < 0) {
							GENL_SET_ERR_MSG(info,
									 "cannot del LNet NI");
							goto out;
						}
						break;
					}

					lnet_net_unlock(LNET_LOCK_EX);
				} else {
					rc = lnet_dyn_add_ni(&conf, net_id, &tun);
					switch (rc) {
					case -ENOENT:
						GENL_SET_ERR_MSG(info,
								 "cannot parse net");
						break;
					case -ERANGE:
						GENL_SET_ERR_MSG(info,
								 "invalid CPT set");
					fallthrough;
					default:
						GENL_SET_ERR_MSG(info,
								 "cannot add LNet NI");
					case 0:
						break;
					}
					if (rc < 0)
						goto out;
				}
				break;
			}
			/* it is possible a newer version of the user land send
			 * values older kernels doesn't handle. So silently
			 * ignore these values
			 */
			default:
				break;
			}
		}

		/* Handle case of just sent NET with no list of NIDs */
		if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE) && !ni_list) {
			rc = lnet_dyn_del_net(net_id);
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "cannot del network");
			}
		}
	}
out:
	return rc;
}

static const struct genl_multicast_group lnet_mcast_grps[] = {
	{ .name	=	"ip2net",	},
	{ .name =	"net",		},
};

static const struct genl_ops lnet_genl_ops[] = {
	{
		.cmd		= LNET_CMD_NETS,
		.start		= lnet_net_show_start,
		.dumpit		= lnet_net_show_dump,
		.done		= lnet_net_show_done,
		.doit		= lnet_net_cmd,
	},
};

static struct genl_family lnet_family = {
	.name		= LNET_GENL_NAME,
	.version	= LNET_GENL_VERSION,
	.module		= THIS_MODULE,
	.netnsok	= true,
	.ops		= lnet_genl_ops,
	.n_ops		= ARRAY_SIZE(lnet_genl_ops),
	.mcgrps		= lnet_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(lnet_mcast_grps),
};

void LNetDebugPeer(struct lnet_processid *id)
{
	lnet_debug_peer(lnet_nid_to_nid4(&id->nid));
}
EXPORT_SYMBOL(LNetDebugPeer);

/**
 * Retrieve the lnet_process_id ID of LNet interface at @index. Note that
 * all interfaces share a same PID, as requested by LNetNIInit().
 *
 * @index	Index of the interface to look up.
 * @id		On successful return, this location will hold the
 *		lnet_process_id ID of the interface.
 *
 * Return:	0 If an interface exists at @index.
 *		-ENOENT If no interface has been found.
 */
int
LNetGetId(unsigned int index, struct lnet_processid *id)
{
	struct lnet_ni *ni;
	struct lnet_net *net;
	int cpt;
	int rc = -ENOENT;

	LASSERT(the_lnet.ln_refcount > 0);

	cpt = lnet_net_lock_current();

	list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
		list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
			if (!nid_is_nid4(&ni->ni_nid))
				/* FIXME this needs to be handled */
				continue;
			if (index-- != 0)
				continue;

			id->nid = ni->ni_nid;
			id->pid = the_lnet.ln_pid;
			rc = 0;
			break;
		}
	}

	lnet_net_unlock(cpt);
	return rc;
}
EXPORT_SYMBOL(LNetGetId);

struct ping_data {
	int rc;
	int replied;
	int pd_unlinked;
	struct lnet_handle_md mdh;
	struct completion completion;
};

static void
lnet_ping_event_handler(struct lnet_event *event)
{
	struct ping_data *pd = event->md_user_ptr;

	CDEBUG(D_NET, "ping event (%d %d)%s\n",
	       event->type, event->status,
	       event->unlinked ? " unlinked" : "");

	if (event->status) {
		if (!pd->rc)
			pd->rc = event->status;
	} else if (event->type == LNET_EVENT_REPLY) {
		pd->replied = 1;
		pd->rc = event->mlength;
	}

	if (event->unlinked)
		pd->pd_unlinked = 1;

	if (event->unlinked ||
	    (event->type == LNET_EVENT_SEND && event->status))
		complete(&pd->completion);
}

/* lnet_ping() only works with nid4 nids, so we can calculate
 * size from number of nids
 */
#define LNET_PING_INFO_SIZE(NNIDS) \
	offsetof(struct lnet_ping_info, pi_ni[NNIDS])

static int lnet_ping(struct lnet_process_id id4, struct lnet_nid *src_nid,
		     signed long timeout, struct lnet_process_id __user *ids,
		     int n_ids)
{
	struct lnet_md md = { NULL };
	struct ping_data pd = { 0 };
	struct lnet_ping_buffer *pbuf;
	struct lnet_process_id tmpid;
	struct lnet_processid id;
	int id_bytes;
	int i;
	int nob;
	int rc;
	int rc2;

	/* n_ids limit is arbitrary */
	if (n_ids <= 0 || id4.nid == LNET_NID_ANY)
		return -EINVAL;

	/* if the user buffer has more space than the lnet_interfaces_max
	 * then only fill it up to lnet_interfaces_max
	 */
	if (n_ids > lnet_interfaces_max)
		n_ids = lnet_interfaces_max;

	if (id4.pid == LNET_PID_ANY)
		id4.pid = LNET_PID_LUSTRE;

	id_bytes = LNET_PING_INFO_SIZE(n_ids);
	pbuf = lnet_ping_buffer_alloc(id_bytes, GFP_NOFS);
	if (!pbuf)
		return -ENOMEM;

	/* initialize md content */
	md.start = &pbuf->pb_info;
	md.length = id_bytes;
	md.threshold = 2; /* GET/REPLY */
	md.max_size = 0;
	md.options = LNET_MD_TRUNCATE;
	md.user_ptr = &pd;
	md.handler = lnet_ping_event_handler;

	init_completion(&pd.completion);

	rc = LNetMDBind(&md, LNET_UNLINK, &pd.mdh);
	if (rc) {
		CERROR("Can't bind MD: %d\n", rc);
		goto fail_ping_buffer_decref;
	}

	lnet_pid4_to_pid(id4, &id);
	rc = LNetGet(src_nid, pd.mdh, &id, LNET_RESERVED_PORTAL,
		     LNET_PROTO_PING_MATCHBITS, 0, false);
	if (rc) {
		/* Don't CERROR; this could be deliberate! */
		rc2 = LNetMDUnlink(pd.mdh);
		LASSERT(!rc2);

		/* NB must wait for the UNLINK event below... */
	}

	/* Ensure completion in finite time... */
	wait_for_completion_timeout(&pd.completion, timeout);
	if (!pd.pd_unlinked) {
		LNetMDUnlink(pd.mdh);
		wait_for_completion(&pd.completion);
	}
	if (!pd.replied) {
		rc = pd.rc ?: -EIO;
		goto fail_ping_buffer_decref;
	}

	nob = pd.rc;
	LASSERT(nob >= 0 && nob <= id_bytes);

	rc = -EPROTO;		/* if I can't parse... */

	if (nob < 8) {
		CERROR("%s: ping info too short %d\n",
		       libcfs_idstr(&id), nob);
		goto fail_ping_buffer_decref;
	}

	if (pbuf->pb_info.pi_magic == __swab32(LNET_PROTO_PING_MAGIC)) {
		lnet_swap_pinginfo(pbuf);
	} else if (pbuf->pb_info.pi_magic != LNET_PROTO_PING_MAGIC) {
		CERROR("%s: Unexpected magic %08x\n",
		       libcfs_idstr(&id), pbuf->pb_info.pi_magic);
		goto fail_ping_buffer_decref;
	}

	if (!(pbuf->pb_info.pi_features & LNET_PING_FEAT_NI_STATUS)) {
		CERROR("%s: ping w/o NI status: 0x%x\n",
		       libcfs_idstr(&id), pbuf->pb_info.pi_features);
		goto fail_ping_buffer_decref;
	}

	/* Test if smaller than lnet_pinginfo with just one pi_ni status info.
	 * That one might contain size when large nids are used.
	 */
	if (nob < LNET_PING_INFO_SIZE(1)) {
		CERROR("%s: Short reply %d(%lu min)\n",
		       libcfs_idstr(&id), nob, LNET_PING_INFO_SIZE(1));
		goto fail_ping_buffer_decref;
	}

	if (pbuf->pb_info.pi_nnis < n_ids) {
		n_ids = pbuf->pb_info.pi_nnis;
		id_bytes = lnet_ping_info_size(&pbuf->pb_info);
	}

	if (nob < id_bytes) {
		CERROR("%s: Short reply %d(%d expected)\n",
		       libcfs_idstr(&id), nob, id_bytes);
		goto fail_ping_buffer_decref;
	}

	rc = -EFAULT;		/* if I segv in copy_to_user()... */

	memset(&tmpid, 0, sizeof(tmpid));
	for (i = 0; i < n_ids; i++) {
		tmpid.pid = pbuf->pb_info.pi_pid;
		tmpid.nid = pbuf->pb_info.pi_ni[i].ns_nid;
		if (copy_to_user(&ids[i], &tmpid, sizeof(tmpid)))
			goto fail_ping_buffer_decref;
	}
	rc = pbuf->pb_info.pi_nnis;

fail_ping_buffer_decref:
	lnet_ping_buffer_decref(pbuf);
	return rc;
}

#undef LNET_PING_INFO_SIZE

static int
lnet_discover(struct lnet_process_id id4, u32 force,
	      struct lnet_process_id __user *ids,
	      int n_ids)
{
	struct lnet_peer_ni *lpni;
	struct lnet_peer_ni *p;
	struct lnet_peer *lp;
	struct lnet_process_id *buf;
	struct lnet_processid id;
	int cpt;
	int i;
	int rc;

	if (n_ids <= 0 ||
	    id4.nid == LNET_NID_ANY)
		return -EINVAL;

	lnet_pid4_to_pid(id4, &id);
	if (id.pid == LNET_PID_ANY)
		id.pid = LNET_PID_LUSTRE;

	/* If the user buffer has more space than the lnet_interfaces_max,
	 * then only fill it up to lnet_interfaces_max.
	 */
	if (n_ids > lnet_interfaces_max)
		n_ids = lnet_interfaces_max;

	buf = kcalloc(n_ids, sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	cpt = lnet_net_lock_current();
	lpni = lnet_peerni_by_nid_locked(&id.nid, NULL, cpt);
	if (IS_ERR(lpni)) {
		rc = PTR_ERR(lpni);
		goto out;
	}

	/*
	 * Clearing the NIDS_UPTODATE flag ensures the peer will
	 * be discovered, provided discovery has not been disabled.
	 */
	lp = lpni->lpni_peer_net->lpn_peer;
	spin_lock(&lp->lp_lock);
	lp->lp_state &= ~LNET_PEER_NIDS_UPTODATE;
	/* If the force flag is set, force a PING and PUSH as well. */
	if (force)
		lp->lp_state |= LNET_PEER_FORCE_PING | LNET_PEER_FORCE_PUSH;
	spin_unlock(&lp->lp_lock);
	rc = lnet_discover_peer_locked(lpni, cpt, true);
	if (rc)
		goto out_decref;

	/* The lpni (or lp) for this NID may have changed and our ref is
	 * the only thing keeping the old one around. Release the ref
	 * and lookup the lpni again
	 */
	lnet_peer_ni_decref_locked(lpni);
	lpni = lnet_peer_ni_find_locked(&id.nid);
	if (!lpni) {
		rc = -ENOENT;
		goto out;
	}
	lp = lpni->lpni_peer_net->lpn_peer;

	i = 0;
	p = NULL;
	while ((p = lnet_get_next_peer_ni_locked(lp, NULL, p)) != NULL) {
		buf[i].pid = id.pid;
		buf[i].nid = lnet_nid_to_nid4(&p->lpni_nid);
		if (++i >= n_ids)
			break;
	}
	rc = i;

out_decref:
	lnet_peer_ni_decref_locked(lpni);
out:
	lnet_net_unlock(cpt);

	if (rc >= 0)
		if (copy_to_user(ids, buf, rc * sizeof(*buf)))
			rc = -EFAULT;
	kfree(buf);

	return rc;
}

/**
 * Retrieve peer discovery status.
 *
 * Return	1 if lnet_peer_discovery_disabled is 0
 *		0 if lnet_peer_discovery_disabled is 1
 */
int
LNetGetPeerDiscoveryStatus(void)
{
	return !lnet_peer_discovery_disabled;
}
EXPORT_SYMBOL(LNetGetPeerDiscoveryStatus);

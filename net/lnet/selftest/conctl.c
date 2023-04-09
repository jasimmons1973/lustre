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
 *
 * lnet/selftest/conctl.c
 *
 * IOC handle in kernel
 *
 * Author: Liang Zhen <liangzhen@clusterfs.com>
 */
#include <linux/generic-radix-tree.h>
#include <linux/lnet/lib-lnet.h>
#include "console.h"

static int
lst_debug_ioctl(struct lstio_debug_args *args)
{
	char name[LST_NAME_SIZE + 1];
	int client = 1;
	int rc;

	if (args->lstio_dbg_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_dbg_resultp)
		return -EINVAL;

	if (args->lstio_dbg_namep &&	/* name of batch/group */
	    (args->lstio_dbg_nmlen <= 0 ||
	     args->lstio_dbg_nmlen > LST_NAME_SIZE))
		return -EINVAL;

	if (args->lstio_dbg_namep) {
		if (copy_from_user(name, args->lstio_dbg_namep,
				   args->lstio_dbg_nmlen))
			return -EFAULT;

		name[args->lstio_dbg_nmlen] = 0;
	}

	rc = -EINVAL;

	switch (args->lstio_dbg_type) {
	case LST_OPC_SESSION:
		rc = lstcon_session_debug(args->lstio_dbg_timeout,
					  args->lstio_dbg_resultp);
		break;

	case LST_OPC_BATCHSRV:
		client = 0;
		fallthrough;
	case LST_OPC_BATCHCLI:
		if (!args->lstio_dbg_namep)
			goto out;

		rc = lstcon_batch_debug(args->lstio_dbg_timeout,
					name, client, args->lstio_dbg_resultp);
		break;

	case LST_OPC_GROUP:
		if (!args->lstio_dbg_namep)
			goto out;

		rc = lstcon_group_debug(args->lstio_dbg_timeout,
					name, args->lstio_dbg_resultp);
		break;

	case LST_OPC_NODES:
		if (args->lstio_dbg_count <= 0 ||
		    !args->lstio_dbg_idsp)
			goto out;

		rc = lstcon_nodes_debug(args->lstio_dbg_timeout,
					args->lstio_dbg_count,
					args->lstio_dbg_idsp,
					args->lstio_dbg_resultp);
		break;

	default:
		break;
	}

out:
	return rc;
}

static int
lst_group_add_ioctl(struct lstio_group_add_args *args)
{
	char name[LST_NAME_SIZE + 1];
	int rc;

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_grp_namep ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen))
		return -EFAULT;

	name[args->lstio_grp_nmlen] = 0;

	rc = lstcon_group_add(name);

	return rc;
}

static int
lst_group_del_ioctl(struct lstio_group_del_args *args)
{
	int rc;
	char name[LST_NAME_SIZE + 1];

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_grp_namep ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen))
		return -EFAULT;

	name[args->lstio_grp_nmlen] = 0;

	rc = lstcon_group_del(name);

	return rc;
}

static int
lst_group_update_ioctl(struct lstio_group_update_args *args)
{
	int rc;
	char name[LST_NAME_SIZE + 1];

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_grp_resultp ||
	    !args->lstio_grp_namep ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen))
		return -EFAULT;

	name[args->lstio_grp_nmlen] = 0;

	switch (args->lstio_grp_opc) {
	case LST_GROUP_CLEAN:
		rc = lstcon_group_clean(name, args->lstio_grp_args);
		break;

	case LST_GROUP_REFRESH:
		rc = lstcon_group_refresh(name, args->lstio_grp_resultp);
		break;

	case LST_GROUP_RMND:
		if (args->lstio_grp_count <= 0 ||
		    !args->lstio_grp_idsp) {
			rc = -EINVAL;
			break;
		}
		rc = lstcon_nodes_remove(name, args->lstio_grp_count,
					 args->lstio_grp_idsp,
					 args->lstio_grp_resultp);
		break;

	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int
lst_nodes_add_ioctl(struct lstio_group_nodes_args *args)
{
	unsigned int feats;
	int rc;
	char name[LST_NAME_SIZE + 1];

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_grp_idsp ||	/* array of ids */
	    args->lstio_grp_count <= 0 ||
	    !args->lstio_grp_resultp ||
	    !args->lstio_grp_featp ||
	    !args->lstio_grp_namep ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen))
		return -EFAULT;

	name[args->lstio_grp_nmlen] = 0;

	rc = lstcon_nodes_add(name, args->lstio_grp_count,
			      args->lstio_grp_idsp, &feats,
			      args->lstio_grp_resultp);

	if (!rc &&
	    copy_to_user(args->lstio_grp_featp, &feats, sizeof(feats))) {
		return -EINVAL;
	}

	return rc;
}

static int
lst_batch_add_ioctl(struct lstio_batch_add_args *args)
{
	int rc;
	char name[LST_NAME_SIZE + 1];

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_bat_namep ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen))
		return -EFAULT;

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_batch_add(name);

	return rc;
}

static int
lst_batch_run_ioctl(struct lstio_batch_run_args *args)
{
	int rc;
	char name[LST_NAME_SIZE + 1];

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_bat_namep ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen))
		return -EFAULT;

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_batch_run(name, args->lstio_bat_timeout,
			      args->lstio_bat_resultp);

	return rc;
}

static int
lst_batch_stop_ioctl(struct lstio_batch_stop_args *args)
{
	int rc;
	char name[LST_NAME_SIZE + 1];

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_bat_resultp ||
	    !args->lstio_bat_namep ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen))
		return -EFAULT;

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_batch_stop(name, args->lstio_bat_force,
			       args->lstio_bat_resultp);

	return rc;
}

static int
lst_batch_query_ioctl(struct lstio_batch_query_args *args)
{
	char name[LST_NAME_SIZE + 1];
	int rc;

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_bat_resultp ||
	    !args->lstio_bat_namep ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (args->lstio_bat_testidx < 0)
		return -EINVAL;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen))
		return -EFAULT;

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_test_batch_query(name,
				     args->lstio_bat_testidx,
				     args->lstio_bat_client,
				     args->lstio_bat_timeout,
				     args->lstio_bat_resultp);

	return rc;
}

static int
lst_batch_list_ioctl(struct lstio_batch_list_args *args)
{
	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_bat_idx < 0 ||
	    !args->lstio_bat_namep ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	return lstcon_batch_list(args->lstio_bat_idx,
			      args->lstio_bat_nmlen,
			      args->lstio_bat_namep);
}

static int
lst_batch_info_ioctl(struct lstio_batch_info_args *args)
{
	char name[LST_NAME_SIZE + 1];
	int rc;
	int index;
	int ndent;

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_bat_namep ||	/* batch name */
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (!args->lstio_bat_entp &&	/* output: batch entry */
	    !args->lstio_bat_dentsp)	/* output: node entry */
		return -EINVAL;

	if (args->lstio_bat_dentsp) {		/* have node entry */
		if (!args->lstio_bat_idxp ||	/* node index */
		    !args->lstio_bat_ndentp)	/* # of node entry */
			return -EINVAL;

		if (copy_from_user(&index, args->lstio_bat_idxp,
				   sizeof(index)) ||
		    copy_from_user(&ndent, args->lstio_bat_ndentp,
				   sizeof(ndent)))
			return -EFAULT;

		if (ndent <= 0 || index < 0)
			return -EINVAL;
	}

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen))
		return -EFAULT;

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_batch_info(name, args->lstio_bat_entp,
			       args->lstio_bat_server, args->lstio_bat_testidx,
			       &index, &ndent, args->lstio_bat_dentsp);

	if (rc)
		return rc;

	if (args->lstio_bat_dentsp &&
	    (copy_to_user(args->lstio_bat_idxp, &index, sizeof(index)) ||
	     copy_to_user(args->lstio_bat_ndentp, &ndent, sizeof(ndent))))
		rc = -EFAULT;

	return rc;
}

static int
lst_stat_query_ioctl(struct lstio_stat_args *args)
{
	int rc;
	char name[LST_NAME_SIZE + 1];

	/* TODO: not finished */
	if (args->lstio_sta_key != console_session.ses_key)
		return -EACCES;

	if (!args->lstio_sta_resultp)
		return -EINVAL;

	if (args->lstio_sta_idsp) {
		if (args->lstio_sta_count <= 0)
			return -EINVAL;

		rc = lstcon_nodes_stat(args->lstio_sta_count,
				       args->lstio_sta_idsp,
				       args->lstio_sta_timeout,
				       args->lstio_sta_resultp);
	} else if (args->lstio_sta_namep) {
		if (args->lstio_sta_nmlen <= 0 ||
		    args->lstio_sta_nmlen > LST_NAME_SIZE)
			return -EINVAL;

		rc = copy_from_user(name, args->lstio_sta_namep,
				    args->lstio_sta_nmlen);
		if (!rc)
			rc = lstcon_group_stat(name, args->lstio_sta_timeout,
					       args->lstio_sta_resultp);
		else
			rc = -EFAULT;
	} else {
		rc = -EINVAL;
	}

	return rc;
}

static int lst_test_add_ioctl(struct lstio_test_args *args)
{
	char batch_name[LST_NAME_SIZE + 1];
	char src_name[LST_NAME_SIZE + 1];
	char dst_name[LST_NAME_SIZE + 1];
	void *param = NULL;
	int ret = 0;
	int rc = -ENOMEM;

	if (!args->lstio_tes_resultp ||
	    !args->lstio_tes_retp ||
	    !args->lstio_tes_bat_name ||	/* no specified batch */
	    args->lstio_tes_bat_nmlen <= 0 ||
	    args->lstio_tes_bat_nmlen > LST_NAME_SIZE ||
	    !args->lstio_tes_sgrp_name ||	/* no source group */
	    args->lstio_tes_sgrp_nmlen <= 0 ||
	    args->lstio_tes_sgrp_nmlen > LST_NAME_SIZE ||
	    !args->lstio_tes_dgrp_name ||	/* no target group */
	    args->lstio_tes_dgrp_nmlen <= 0 ||
	    args->lstio_tes_dgrp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (!args->lstio_tes_loop ||		/* negative is infinite */
	    args->lstio_tes_concur <= 0 ||
	    args->lstio_tes_dist <= 0 ||
	    args->lstio_tes_span <= 0)
		return -EINVAL;

	/* have parameter, check if parameter length is valid */
	if (args->lstio_tes_param &&
	    (args->lstio_tes_param_len <= 0 ||
	     args->lstio_tes_param_len >
	     PAGE_SIZE - sizeof(struct lstcon_test)))
		return -EINVAL;

	/* Enforce zero parameter length if there's no parameter */
	if (!args->lstio_tes_param && args->lstio_tes_param_len)
		return -EINVAL;

	if (args->lstio_tes_param) {
		param = memdup_user(args->lstio_tes_param,
				    args->lstio_tes_param_len);
		if (IS_ERR(param))
			return PTR_ERR(param);
	}

	rc = -EFAULT;
	if (copy_from_user(batch_name, args->lstio_tes_bat_name,
			   args->lstio_tes_bat_nmlen) ||
	    copy_from_user(src_name, args->lstio_tes_sgrp_name,
			   args->lstio_tes_sgrp_nmlen) ||
	    copy_from_user(dst_name, args->lstio_tes_dgrp_name,
			   args->lstio_tes_dgrp_nmlen))
		goto out;

	rc = lstcon_test_add(batch_name, args->lstio_tes_type,
			     args->lstio_tes_loop, args->lstio_tes_concur,
			     args->lstio_tes_dist, args->lstio_tes_span,
			     src_name, dst_name, param,
			     args->lstio_tes_param_len,
			     &ret, args->lstio_tes_resultp);

	if (!rc && ret)
		rc = (copy_to_user(args->lstio_tes_retp, &ret,
				   sizeof(ret))) ? -EFAULT : 0;
out:
	kfree(param);

	return rc;
}

int
lstcon_ioctl_entry(struct notifier_block *nb,
		   unsigned long cmd, void *vdata)
{
	struct libcfs_ioctl_hdr *hdr = vdata;
	char *buf = NULL;
	struct libcfs_ioctl_data *data;
	int opc;
	int rc = -EINVAL;

	if (cmd != IOC_LIBCFS_LNETST)
		goto err;

	data = container_of(hdr, struct libcfs_ioctl_data, ioc_hdr);

	opc = data->ioc_u32[0];

	if (data->ioc_plen1 > PAGE_SIZE)
		goto err;

	buf = kmalloc(data->ioc_plen1, GFP_KERNEL);
	rc = -ENOMEM;
	if (!buf)
		goto err;

	/* copy in parameter */
	rc = -EFAULT;
	if (copy_from_user(buf, data->ioc_pbuf1, data->ioc_plen1))
		goto err;

	mutex_lock(&console_session.ses_mutex);

	console_session.ses_laststamp = ktime_get_real_seconds();

	if (console_session.ses_shutdown) {
		rc = -ESHUTDOWN;
		goto out;
	}

	if (console_session.ses_expired)
		lstcon_session_end();

	if (opc != LSTIO_SESSION_NEW &&
	    console_session.ses_state == LST_SESSION_NONE) {
		CDEBUG(D_NET, "LST no active session\n");
		rc = -ESRCH;
		goto out;
	}

	memset(&console_session.ses_trans_stat,
	       0, sizeof(struct lstcon_trans_stat));

	switch (opc) {
	case LSTIO_SESSION_NEW:
		fallthrough;
	case LSTIO_SESSION_END:
		fallthrough;
	case LSTIO_SESSION_INFO:
		rc = -EOPNOTSUPP;
		break;
	case LSTIO_DEBUG:
		rc = lst_debug_ioctl((struct lstio_debug_args *)buf);
		break;
	case LSTIO_GROUP_ADD:
		rc = lst_group_add_ioctl((struct lstio_group_add_args *)buf);
		break;
	case LSTIO_GROUP_DEL:
		rc = lst_group_del_ioctl((struct lstio_group_del_args *)buf);
		break;
	case LSTIO_GROUP_UPDATE:
		rc = lst_group_update_ioctl((struct lstio_group_update_args *)buf);
		break;
	case LSTIO_NODES_ADD:
		rc = lst_nodes_add_ioctl((struct lstio_group_nodes_args *)buf);
		break;
	case LSTIO_GROUP_LIST:
		fallthrough;
	case LSTIO_GROUP_INFO:
		rc = -EOPNOTSUPP;
		break;
	case LSTIO_BATCH_ADD:
		rc = lst_batch_add_ioctl((struct lstio_batch_add_args *)buf);
		break;
	case LSTIO_BATCH_START:
		rc = lst_batch_run_ioctl((struct lstio_batch_run_args *)buf);
		break;
	case LSTIO_BATCH_STOP:
		rc = lst_batch_stop_ioctl((struct lstio_batch_stop_args *)buf);
		break;
	case LSTIO_BATCH_QUERY:
		rc = lst_batch_query_ioctl((struct lstio_batch_query_args *)buf);
		break;
	case LSTIO_BATCH_LIST:
		rc = lst_batch_list_ioctl((struct lstio_batch_list_args *)buf);
		break;
	case LSTIO_BATCH_INFO:
		rc = lst_batch_info_ioctl((struct lstio_batch_info_args *)buf);
		break;
	case LSTIO_TEST_ADD:
		rc = lst_test_add_ioctl((struct lstio_test_args *)buf);
		break;
	case LSTIO_STAT_QUERY:
		rc = lst_stat_query_ioctl((struct lstio_stat_args *)buf);
		break;
	default:
		rc = -EINVAL;
		goto out;
	}

	if (copy_to_user(data->ioc_pbuf2, &console_session.ses_trans_stat,
			 sizeof(struct lstcon_trans_stat)))
		rc = -EFAULT;
out:
	mutex_unlock(&console_session.ses_mutex);
err:
	kfree(buf);

	return notifier_from_ioctl_errno(rc);
}

static struct genl_family lst_family;

static const struct ln_key_list lst_session_keys = {
	.lkl_maxattr			= LNET_SELFTEST_SESSION_MAX,
	.lkl_list			= {
		[LNET_SELFTEST_SESSION_HDR]	= {
			.lkp_value		= "session",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_SELFTEST_SESSION_NAME]	= {
			.lkp_value		= "name",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_SELFTEST_SESSION_KEY]	= {
			.lkp_value		= "key",
			.lkp_data_type		= NLA_U32,
		},
		[LNET_SELFTEST_SESSION_TIMESTAMP] = {
			.lkp_value		= "timestamp",
			.lkp_data_type		= NLA_S64,
		},
		[LNET_SELFTEST_SESSION_NID]	= {
			.lkp_value		= "nid",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_SELFTEST_SESSION_NODE_COUNT] = {
			.lkp_value		= "nodes",
			.lkp_data_type		= NLA_U16,
		},
	},
};

static int lst_sessions_show_dump(struct sk_buff *msg,
				  struct netlink_callback *cb)
{
	const struct ln_key_list *all[] = {
		&lst_session_keys, NULL
	};
	struct netlink_ext_ack *extack = cb->extack;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	unsigned int node_count = 0;
	struct lstcon_ndlink *ndl;
	int flag = NLM_F_MULTI;
	int rc = 0;
	void *hdr;

	if (console_session.ses_state != LST_SESSION_ACTIVE) {
		NL_SET_ERR_MSG(extack, "session is not active");
		rc = -ESRCH;
		goto out_unlock;
	}

	list_for_each_entry(ndl, &console_session.ses_ndl_list, ndl_link)
		node_count++;

	rc = lnet_genl_send_scalar_list(msg, portid, seq, &lst_family,
					NLM_F_CREATE | NLM_F_MULTI,
					LNET_SELFTEST_CMD_SESSIONS, all);
	if (rc < 0) {
		NL_SET_ERR_MSG(extack, "failed to send key table");
		goto out_unlock;
	}

	if (console_session.ses_force)
		flag |= NLM_F_REPLACE;

	hdr = genlmsg_put(msg, portid, seq, &lst_family, flag,
			  LNET_SELFTEST_CMD_SESSIONS);
	if (!hdr) {
		NL_SET_ERR_MSG(extack, "failed to send values");
		genlmsg_cancel(msg, hdr);
		rc = -EMSGSIZE;
		goto out_unlock;
	}

	nla_put_string(msg, LNET_SELFTEST_SESSION_NAME,
		       console_session.ses_name);
	nla_put_u32(msg, LNET_SELFTEST_SESSION_KEY,
		    console_session.ses_key);
	nla_put_u64_64bit(msg, LNET_SELFTEST_SESSION_TIMESTAMP,
			  console_session.ses_id.ses_stamp,
			  LNET_SELFTEST_SESSION_PAD);
	nla_put_string(msg, LNET_SELFTEST_SESSION_NID,
		       libcfs_nidstr(&console_session.ses_id.ses_nid));
	nla_put_u16(msg, LNET_SELFTEST_SESSION_NODE_COUNT,
		    node_count);
	genlmsg_end(msg, hdr);
out_unlock:
	return rc;
}

static int lst_sessions_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg = NULL;
	int rc = 0;

	mutex_lock(&console_session.ses_mutex);

	console_session.ses_laststamp = ktime_get_real_seconds();

	if (console_session.ses_shutdown) {
		GENL_SET_ERR_MSG(info, "session is shutdown");
		rc = -ESHUTDOWN;
		goto out_unlock;
	}

	if (console_session.ses_expired)
		lstcon_session_end();

	if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE) &&
	    console_session.ses_state == LST_SESSION_NONE) {
		GENL_SET_ERR_MSG(info, "session is not active");
		rc = -ESRCH;
		goto out_unlock;
	}

	memset(&console_session.ses_trans_stat, 0,
	       sizeof(struct lstcon_trans_stat));

	if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE)) {
		lstcon_session_end();
		goto out_unlock;
	}

	if (info->attrs[LN_SCALAR_ATTR_LIST]) {
		struct genlmsghdr *gnlh = nlmsg_data(info->nlhdr);
		const struct ln_key_list *all[] = {
			&lst_session_keys, NULL
		};
		char name[LST_NAME_SIZE];
		struct nlmsghdr *nlh;
		struct nlattr *item;
		bool force = false;
		s64 timeout = 300;
		void *hdr;
		int rem;

		if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE)
			force = true;

		nla_for_each_nested(item, info->attrs[LN_SCALAR_ATTR_LIST],
				    rem) {
			if (nla_type(item) != LN_SCALAR_ATTR_VALUE)
				continue;

			if (nla_strcmp(item, "name") == 0) {
				ssize_t len;

				item = nla_next(item, &rem);
				if (nla_type(item) != LN_SCALAR_ATTR_VALUE) {
					rc = -EINVAL;
					goto err_conf;
				}

				len = nla_strlcpy(name, item, sizeof(name));
				if (len < 0)
					rc = len;
			} else if (nla_strcmp(item, "timeout") == 0) {
				item = nla_next(item, &rem);
				if (nla_type(item) !=
				    LN_SCALAR_ATTR_INT_VALUE) {
					rc = -EINVAL;
					goto err_conf;
				}

				timeout = nla_get_s64(item);
				if (timeout < 0)
					rc = -ERANGE;
			}
			if (rc < 0) {
err_conf:
				GENL_SET_ERR_MSG(info,
						 "failed to get config");
				goto out_unlock;
			}
		}

		rc = lstcon_session_new(name, info->nlhdr->nlmsg_pid,
					gnlh->version, timeout,
					force);
		if (rc < 0) {
			GENL_SET_ERR_MSG(info, "new session creation failed");
			lstcon_session_end();
			goto out_unlock;
		}

		msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			GENL_SET_ERR_MSG(info, "msg allocation failed");
			rc = -ENOMEM;
			goto out_unlock;
		}

		rc = lnet_genl_send_scalar_list(msg, info->snd_portid,
						info->snd_seq, &lst_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_SELFTEST_CMD_SESSIONS,
						all);
		if (rc < 0) {
			GENL_SET_ERR_MSG(info, "failed to send key table");
			goto out_unlock;
		}

		hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
				  &lst_family, NLM_F_MULTI,
				  LNET_SELFTEST_CMD_SESSIONS);
		if (!hdr) {
			GENL_SET_ERR_MSG(info, "failed to send values");
			genlmsg_cancel(msg, hdr);
			rc = -EMSGSIZE;
			goto out_unlock;
		}

		nla_put_string(msg, LNET_SELFTEST_SESSION_NAME,
			       console_session.ses_name);
		nla_put_u32(msg, LNET_SELFTEST_SESSION_KEY,
			    console_session.ses_key);
		nla_put_u64_64bit(msg, LNET_SELFTEST_SESSION_TIMESTAMP,
				  console_session.ses_id.ses_stamp,
				  LNET_SELFTEST_SESSION_PAD);
		nla_put_string(msg, LNET_SELFTEST_SESSION_NID,
			       libcfs_nidstr(&console_session.ses_id.ses_nid));
		nla_put_u16(msg, LNET_SELFTEST_SESSION_NODE_COUNT, 0);

		genlmsg_end(msg, hdr);

		nlh = nlmsg_put(msg, info->snd_portid, info->snd_seq,
				NLMSG_DONE, 0, NLM_F_MULTI);
		if (!nlh) {
			GENL_SET_ERR_MSG(info, "failed to complete message");
			genlmsg_cancel(msg, hdr);
			rc = -ENOMEM;
			goto out_unlock;
		}
		rc = genlmsg_reply(msg, info);
		if (rc)
			GENL_SET_ERR_MSG(info, "failed to send reply");
	}
out_unlock:
	if (rc < 0 && msg)
		nlmsg_free(msg);
	mutex_unlock(&console_session.ses_mutex);
	return rc;
}

static char *lst_node_state2str(int state)
{
	if (state == LST_NODE_ACTIVE)
		return "Active";
	if (state == LST_NODE_BUSY)
		return "Busy";
	if (state == LST_NODE_DOWN)
		return "Down";

	return "Unknown";
}

int lst_node_str2state(char *str)
{
	int state = 0;

	if (strcasecmp(str, "Active") == 0)
		state = LST_NODE_ACTIVE;
	else if (strcasecmp(str, "Busy") == 0)
		state = LST_NODE_BUSY;
	else if (strcasecmp(str, "Down") == 0)
		state = LST_NODE_DOWN;
	else if (strcasecmp(str, "Unknown") == 0)
		state = LST_NODE_UNKNOWN;
	else if (strcasecmp(str, "Invalid") == 0)
		state = LST_NODE_UNKNOWN | LST_NODE_DOWN | LST_NODE_BUSY;
	return state;
}

struct lst_genl_group_prop {
	struct lstcon_group	*lggp_grp;
	int			lggp_state_filter;
};

struct lst_genl_group_list {
	GENRADIX(struct lst_genl_group_prop)	lggl_groups;
	unsigned int				lggl_count;
	unsigned int				lggl_index;
	bool					lggl_verbose;
};

static inline struct lst_genl_group_list *
lst_group_dump_ctx(struct netlink_callback *cb)
{
	return (struct lst_genl_group_list *)cb->args[0];
}

static int lst_groups_show_done(struct netlink_callback *cb)
{
	struct lst_genl_group_list *glist = lst_group_dump_ctx(cb);

	if (glist) {
		int i;

		for (i = 0; i < glist->lggl_count; i++) {
			struct lst_genl_group_prop *prop;

			prop = genradix_ptr(&glist->lggl_groups, i);
			if (!prop || !prop->lggp_grp)
				continue;
			lstcon_group_decref(prop->lggp_grp);
		}
		genradix_free(&glist->lggl_groups);
		kfree(glist);
	}
	cb->args[0] = 0;

	return 0;
}

/* LNet selftest groups ->start() handler for GET requests */
static int lst_groups_show_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
	struct netlink_ext_ack *extack = cb->extack;
	struct nlattr *params = genlmsg_data(gnlh);
	struct lst_genl_group_list *glist;
	int msg_len = genlmsg_len(gnlh);
	struct lstcon_group *grp;
	struct nlattr *groups;
	int rem, rc = 0;

	glist = kzalloc(sizeof(*glist), GFP_KERNEL);
	if (!glist)
		return -ENOMEM;

	genradix_init(&glist->lggl_groups);
	cb->args[0] = (long)glist;

	if (!msg_len) {
		list_for_each_entry(grp, &console_session.ses_grp_list,
				    grp_link) {
			struct lst_genl_group_prop *prop;

			prop = genradix_ptr_alloc(&glist->lggl_groups,
						  glist->lggl_count++,
						  GFP_ATOMIC);
			if (!prop) {
				NL_SET_ERR_MSG(extack,
					       "failed to allocate group info");
				rc = -ENOMEM;
				goto report_err;
			}
			lstcon_group_addref(grp);  /* +1 ref for caller */
			prop->lggp_grp = grp;
		}

		if (!glist->lggl_count) {
			NL_SET_ERR_MSG(extack, "No groups found");
			rc = -ENOENT;
		}
		goto report_err;
	}
	glist->lggl_verbose = true;

	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		NL_SET_ERR_MSG(extack, "no configuration");
		goto report_err;
	}

	nla_for_each_nested(groups, params, rem) {
		struct lst_genl_group_prop *prop = NULL;
		struct nlattr *group;
		int rem2;

		if (nla_type(groups) != LN_SCALAR_ATTR_LIST)
			continue;

		nla_for_each_nested(group, groups, rem2) {
			if (nla_type(group) == LN_SCALAR_ATTR_VALUE) {
				char name[LST_NAME_SIZE];

				prop = genradix_ptr_alloc(&glist->lggl_groups,
							  glist->lggl_count++,
							  GFP_ATOMIC);
				if (!prop) {
					NL_SET_ERR_MSG(extack,
						       "failed to allocate group info");
					rc = -ENOMEM;
					goto report_err;
				}

				rc = nla_strlcpy(name, group, sizeof(name));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "failed to get name");
					goto report_err;
				}
				rc = lstcon_group_find(name, &prop->lggp_grp);
				if (rc < 0) {
					/* don't stop reporting groups if one
					 * doesn't exist.
					 */
					CWARN("LNet selftest group %s does not exit\n",
					      name);
					rc = 0;
				}
			} else if (nla_type(group) == LN_SCALAR_ATTR_LIST) {
				struct nlattr *attr;
				int rem3;

				if (!prop) {
					NL_SET_ERR_MSG(extack,
						       "missing group information");
					rc = -EINVAL;
					goto report_err;
				}

				nla_for_each_nested(attr, group, rem3) {
					char tmp[16];

					if (nla_type(attr) != LN_SCALAR_ATTR_VALUE ||
					    nla_strcmp(attr, "status") != 0)
						continue;

					attr = nla_next(attr, &rem3);
					if (nla_type(attr) !=
					    LN_SCALAR_ATTR_VALUE) {
						NL_SET_ERR_MSG(extack,
							       "invalid config param");
						rc = -EINVAL;
						goto report_err;
					}

					rc = nla_strlcpy(tmp, attr, sizeof(tmp));
					if (rc < 0) {
						NL_SET_ERR_MSG(extack,
							       "failed to get prop attr");
						goto report_err;
					}
					rc = 0;
					prop->lggp_state_filter |=
						lst_node_str2state(tmp);
				}
			}
		}
	}
	if (!glist->lggl_count) {
		NL_SET_ERR_MSG(extack, "No groups found");
		rc = -ENOENT;
	}
report_err:
	if (rc < 0)
		lst_groups_show_done(cb);

	return rc;
}

static const struct ln_key_list lst_group_keys = {
	.lkl_maxattr			= LNET_SELFTEST_GROUP_MAX,
	.lkl_list			= {
		[LNET_SELFTEST_GROUP_ATTR_HDR]	= {
			.lkp_value		= "groups",
			.lkp_key_format		= LNKF_SEQUENCE,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_SELFTEST_GROUP_ATTR_NAME]	= {
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_SELFTEST_GROUP_ATTR_NODELIST] = {
			.lkp_key_format		= LNKF_MAPPING | LNKF_SEQUENCE,
			.lkp_data_type		= NLA_NESTED,
		},
	},
};

static const struct ln_key_list lst_group_nodelist_keys = {
	.lkl_maxattr			= LNET_SELFTEST_GROUP_NODELIST_PROP_MAX,
	.lkl_list			= {
		[LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_NID] = {
			.lkp_value		= "nid",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_STATUS] = {
			.lkp_value		= "status",
			.lkp_data_type		= NLA_STRING,
		},
	},
};

static int lst_groups_show_dump(struct sk_buff *msg,
				struct netlink_callback *cb)
{
	struct lst_genl_group_list *glist = lst_group_dump_ctx(cb);
	struct netlink_ext_ack *extack = cb->extack;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx = 0, rc = 0;

	if (!glist->lggl_index) {
		const struct ln_key_list *all[] = {
			&lst_group_keys, &lst_group_nodelist_keys, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq, &lst_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_SELFTEST_CMD_GROUPS, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			goto send_error;
		}
	}

	for (idx = glist->lggl_index; idx < glist->lggl_count; idx++) {
		struct lst_genl_group_prop *group;
		struct lstcon_ndlink *ndl;
		struct nlattr *nodelist;
		unsigned int count = 1;
		void *hdr;

		group = genradix_ptr(&glist->lggl_groups, idx);
		if (!group)
			continue;

		hdr = genlmsg_put(msg, portid, seq, &lst_family,
				  NLM_F_MULTI, LNET_SELFTEST_CMD_GROUPS);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			rc = -EMSGSIZE;
			goto send_error;
		}

		if (idx == 0)
			nla_put_string(msg, LNET_SELFTEST_GROUP_ATTR_HDR, "");

		nla_put_string(msg, LNET_SELFTEST_GROUP_ATTR_NAME,
			       group->lggp_grp->grp_name);

		if (!glist->lggl_verbose)
			goto skip_details;

		nodelist = nla_nest_start(msg,
					  LNET_SELFTEST_GROUP_ATTR_NODELIST);
		list_for_each_entry(ndl, &group->lggp_grp->grp_ndl_list,
				    ndl_link) {
			struct nlattr *node = nla_nest_start(msg, count);
			char *ndstate;

			if (group->lggp_state_filter &&
			    !(group->lggp_state_filter & ndl->ndl_node->nd_state))
				continue;

			nla_put_string(msg,
				       LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_NID,
				       libcfs_id2str(ndl->ndl_node->nd_id));

			ndstate = lst_node_state2str(ndl->ndl_node->nd_state);
			nla_put_string(msg,
				       LNET_SELFTEST_GROUP_NODELIST_PROP_ATTR_STATUS,
				       ndstate);
			nla_nest_end(msg, node);
		}
		nla_nest_end(msg, nodelist);
skip_details:
		genlmsg_end(msg, hdr);
	}
	glist->lggl_index = idx;
send_error:
	return rc;
}

#ifndef HAVE_NETLINK_CALLBACK_START
static int lst_old_groups_show_dump(struct sk_buff *msg,
				    struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lst_groups_show_start(cb);

		if (rc < 0)
			return rc;
	}

	return lst_groups_show_dump(msg, cb);
}
#endif

static const struct genl_multicast_group lst_mcast_grps[] = {
	{ .name = "sessions",		},
	{ .name	= "groups",		},
};

static const struct genl_ops lst_genl_ops[] = {
	{
		.cmd		= LNET_SELFTEST_CMD_SESSIONS,
		.dumpit		= lst_sessions_show_dump,
		.doit		= lst_sessions_cmd,
	},
	{
		.cmd		= LNET_SELFTEST_CMD_GROUPS,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lst_groups_show_start,
		.dumpit		= lst_groups_show_dump,
#else
		.dumpit		= lst_old_groups_show_dump,
#endif
		.done		= lst_groups_show_done,
	},
};

static struct genl_family lst_family = {
	.name		= LNET_SELFTEST_GENL_NAME,
	.version	= LNET_SELFTEST_GENL_VERSION,
	.maxattr	= LN_SCALAR_MAX,
	.module		= THIS_MODULE,
	.ops		= lst_genl_ops,
	.n_ops		= ARRAY_SIZE(lst_genl_ops),
	.mcgrps		= lst_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(lst_mcast_grps),
};

int lstcon_init_netlink(void)
{
	return genl_register_family(&lst_family);
}

void lstcon_fini_netlink(void)
{
	genl_unregister_family(&lst_family);
}

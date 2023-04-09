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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 *
 * Kernel <-> userspace communication routines.
 * Using pipes for all arches.
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/file.h>
#include <linux/glob.h>
#include <net/genetlink.h>
#include <net/sock.h>

#include <obd_class.h>
#include <obd_support.h>
#include <lustre_kernelcomm.h>

static struct genl_family lustre_family;

static struct ln_key_list device_list = {
	.lkl_maxattr			= LUSTRE_DEVICE_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_DEVICE_ATTR_HDR]	= {
			.lkp_value		= "devices",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_DEVICE_ATTR_INDEX]	= {
			.lkp_value		= "index",
			.lkp_data_type		= NLA_U16
		},
		[LUSTRE_DEVICE_ATTR_STATUS]	= {
			.lkp_value		= "status",
			.lkp_data_type		= NLA_STRING
		},
		[LUSTRE_DEVICE_ATTR_CLASS]	= {
			.lkp_value		= "type",
			.lkp_data_type		= NLA_STRING
		},
		[LUSTRE_DEVICE_ATTR_NAME]	= {
			.lkp_value		= "name",
			.lkp_data_type		= NLA_STRING
		},
		[LUSTRE_DEVICE_ATTR_UUID]	= {
			.lkp_value		= "uuid",
			.lkp_data_type		= NLA_STRING
		},
		[LUSTRE_DEVICE_ATTR_REFCOUNT]	= {
			.lkp_value		= "refcount",
			.lkp_data_type		= NLA_U32
		},
	},
};

struct genl_dev_list {
	struct obd_device	*gdl_target;
	unsigned int		gdl_start;
};

static inline struct genl_dev_list *
device_dump_ctx(struct netlink_callback *cb)
{
	return (struct genl_dev_list *)cb->args[0];
}

/* generic ->start() handler for GET requests */
static int lustre_device_list_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
	struct netlink_ext_ack *extack = cb->extack;
	struct genl_dev_list *glist;
	int msg_len, rc = 0;

	glist = kmalloc(sizeof(*glist), GFP_KERNEL);
	if (!glist)
		return -ENOMEM;

	cb->args[0] = (long)glist;
	glist->gdl_target = NULL;
	glist->gdl_start = 0;

	msg_len = genlmsg_len(gnlh);
	if (msg_len > 0) {
		struct nlattr *params = genlmsg_data(gnlh);
		struct nlattr *dev;
		int rem;

		if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
			NL_SET_ERR_MSG(extack, "no configuration");
			goto report_err;
		}

		nla_for_each_nested(dev, params, rem) {
			struct nlattr *prop;
			int rem2;

			nla_for_each_nested(prop, dev, rem2) {
				char name[MAX_OBD_NAME];
				struct obd_device *obd;

				if (nla_type(prop) != LN_SCALAR_ATTR_VALUE ||
				    nla_strcmp(prop, "name") != 0)
					continue;

				prop = nla_next(prop, &rem2);
				if (nla_type(prop) != LN_SCALAR_ATTR_VALUE) {
					rc = -EINVAL;
					goto report_err;
				}

				rc = nla_strlcpy(name, prop, sizeof(name));
				if (rc < 0)
					goto report_err;
				rc = 0;

				obd = class_name2obd(name);
				if (obd)
					glist->gdl_target = obd;
			}
		}
		if (!glist->gdl_target) {
			NL_SET_ERR_MSG(extack, "No devices found");
			rc = -ENOENT;
		}
	}
report_err:
	if (rc < 0) {
		kfree(glist);
		cb->args[0] = 0;
	}
	return rc;
}

static int lustre_device_list_dump(struct sk_buff *msg,
				   struct netlink_callback *cb)
{
	struct genl_dev_list *glist = device_dump_ctx(cb);
	struct obd_device *filter = glist->gdl_target;
	struct netlink_ext_ack *extack = cb->extack;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx, rc = 0;

	if (glist->gdl_start == 0) {
		const struct ln_key_list *all[] = {
			&device_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lustre_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LUSTRE_CMD_DEVICES, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			return rc;
		}
	}

	for (idx = glist->gdl_start; idx < class_devno_max(); idx++) {
		struct obd_device *obd;
		const char *status;
		void *hdr;

		obd = class_num2obd(idx);
		if (!obd)
			continue;

		if (filter && filter != obd)
			continue;

		hdr = genlmsg_put(msg, portid, seq, &lustre_family,
				  NLM_F_MULTI, LUSTRE_CMD_DEVICES);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			genlmsg_cancel(msg, hdr);
			rc = -EMSGSIZE;
			break;
		}

		if (idx == 0)
			nla_put_string(msg, LUSTRE_DEVICE_ATTR_HDR, "");

		nla_put_u16(msg, LUSTRE_DEVICE_ATTR_INDEX, obd->obd_minor);

		/* Collect only the index value for a single obd */
		if (filter) {
			genlmsg_end(msg, hdr);
			idx++;
			break;
		}

		if (obd->obd_stopping)
			status = "ST";
		else if (obd->obd_inactive)
			status = "IN";
		else if (obd->obd_set_up)
			status = "UP";
		else if (obd->obd_attached)
			status = "AT";
		else
			status = "--";

		nla_put_string(msg, LUSTRE_DEVICE_ATTR_STATUS, status);

		nla_put_string(msg, LUSTRE_DEVICE_ATTR_CLASS,
			       obd->obd_type->typ_name);

		nla_put_string(msg, LUSTRE_DEVICE_ATTR_NAME,
			       obd->obd_name);

		nla_put_string(msg, LUSTRE_DEVICE_ATTR_UUID,
			       obd->obd_uuid.uuid);

		nla_put_u32(msg, LUSTRE_DEVICE_ATTR_REFCOUNT,
			    atomic_read(&obd->obd_refcount));

		genlmsg_end(msg, hdr);
	}

	glist->gdl_start = idx;
	return rc < 0 ? rc : msg->len;
}

int lustre_device_done(struct netlink_callback *cb)
{
	struct genl_dev_list *glist;

	glist = device_dump_ctx(cb);
	kfree(glist);
	cb->args[0] = 0;

	return 0;
}

static const struct genl_multicast_group lustre_mcast_grps[] = {
	{ .name		= "devices",		},
};

static const struct genl_ops lustre_genl_ops[] = {
	{
		.cmd		= LUSTRE_CMD_DEVICES,
		.start		= lustre_device_list_start,
		.dumpit		= lustre_device_list_dump,
		.done		= lustre_device_done,
	},
};

static struct genl_family lustre_family = {
	.name		= LUSTRE_GENL_NAME,
	.version	= LUSTRE_GENL_VERSION,
	.module		= THIS_MODULE,
	.ops		= lustre_genl_ops,
	.n_ops		= ARRAY_SIZE(lustre_genl_ops),
	.mcgrps		= lustre_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(lustre_mcast_grps),
};

/**
 * libcfs_kkuc_msg_put - send an message from kernel to userspace
 * @param fp	to send the message to
 * @param payload Payload data. First field of payload is always
 *  struct kuc_hdr
 */
static int libcfs_kkuc_msg_put(struct file *filp, void *payload)
{
	struct kuc_hdr *kuch = (struct kuc_hdr *)payload;
	ssize_t count = kuch->kuc_msglen;
	loff_t offset = 0;
	int rc = -ENXIO;

	if (IS_ERR_OR_NULL(filp))
		return -EBADF;

	if (kuch->kuc_magic != KUC_MAGIC) {
		CERROR("KernelComm: bad magic %x\n", kuch->kuc_magic);
		return rc;
	}

	while (count > 0) {
		rc = kernel_write(filp, payload, count, &offset);
		if (rc < 0)
			break;
		count -= rc;
		payload += rc;
		rc = 0;
	}

	if (rc < 0)
		CWARN("message send failed (%d)\n", rc);
	else
		CDEBUG(D_HSM, "Sent message rc=%d, fp=%p\n", rc, filp);

	return rc;
}

/*
 * Broadcast groups are global across all mounted filesystems;
 * i.e. registering for a group on 1 fs will get messages for that
 * group from any fs
 */
/** A single group registration has a uid and a file pointer */
struct kkuc_reg {
	struct list_head	kr_chain;
	struct obd_uuid		kr_uuid;
	int			kr_uid;
	struct file	       *kr_fp;
	char			kr_data[0];
};

static struct list_head kkuc_groups[KUC_GRP_MAX + 1];
/* Protect message sending against remove and adds */
static DECLARE_RWSEM(kg_sem);

static inline bool libcfs_kkuc_group_is_valid(unsigned int group)
{
	return group < ARRAY_SIZE(kkuc_groups);
}

int libcfs_kkuc_init(void)
{
	int group;

	for (group = 0; group < ARRAY_SIZE(kkuc_groups); group++)
		INIT_LIST_HEAD(&kkuc_groups[group]);

	return genl_register_family(&lustre_family);
}

void libcfs_kkuc_fini(void)
{
	genl_unregister_family(&lustre_family);
}

/** Add a receiver to a broadcast group
 *
 * @filp:	pipe to write into
 * @uuid:	obd device UUID
 * @uid:	identifier for this receiver
 * @group:	group number
 * @data:	user data
 */
int libcfs_kkuc_group_add(struct file *filp, const struct obd_uuid *uuid,
			  int uid, int group, void *data, size_t data_len)
{
	struct kkuc_reg *reg;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	/* fput in group_rem */
	if (!filp)
		return -EBADF;

	/* freed in group_rem */
	reg = kzalloc(sizeof(*reg) + data_len, GFP_KERNEL);
	if (!reg)
		return -ENOMEM;

	reg->kr_uuid = *uuid;
	reg->kr_fp = filp;
	reg->kr_uid = uid;
	memcpy(reg->kr_data, data, data_len);

	down_write(&kg_sem);
	list_add(&reg->kr_chain, &kkuc_groups[group]);
	up_write(&kg_sem);

	CDEBUG(D_HSM, "Added uid=%d fp=%p to group %d\n", uid, filp, group);

	return 0;
}
EXPORT_SYMBOL(libcfs_kkuc_group_add);

int libcfs_kkuc_group_rem(const struct obd_uuid *uuid, int uid, int group)
{
	struct kkuc_reg *reg, *next;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	if (!uid) {
		/* Broadcast a shutdown message */
		struct kuc_hdr lh;

		lh.kuc_magic = KUC_MAGIC;
		lh.kuc_transport = KUC_TRANSPORT_GENERIC;
		lh.kuc_msgtype = KUC_MSG_SHUTDOWN;
		lh.kuc_msglen = sizeof(lh);
		libcfs_kkuc_group_put(uuid, group, &lh);
	}

	down_write(&kg_sem);
	list_for_each_entry_safe(reg, next, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) &&
		    (!uid || uid == reg->kr_uid)) {
			list_del(&reg->kr_chain);
			CDEBUG(D_HSM, "Removed uid=%d fp=%p from group %d\n",
			       reg->kr_uid, reg->kr_fp, group);
			if (reg->kr_fp)
				fput(reg->kr_fp);
			kfree(reg);
		}
	}
	up_write(&kg_sem);

	return 0;
}
EXPORT_SYMBOL(libcfs_kkuc_group_rem);

int libcfs_kkuc_group_put(const struct obd_uuid *uuid, int group, void *payload)
{
	struct kkuc_reg	*reg;
	int rc = 0;
	int one_success = 0;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	down_write(&kg_sem);

	if (unlikely(list_empty(&kkuc_groups[group])) ||
	    unlikely(OBD_FAIL_CHECK(OBD_FAIL_MDS_HSM_CT_REGISTER_NET))) {
		/* no agent have fully registered, CDT will retry */
		up_write(&kg_sem);
		return -EAGAIN;
	}

	list_for_each_entry(reg, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) && reg->kr_fp) {
			rc = libcfs_kkuc_msg_put(reg->kr_fp, payload);
			if (!rc) {
				one_success = 1;
			} else if (rc == -EPIPE) {
				fput(reg->kr_fp);
				reg->kr_fp = NULL;
			}
		}
	}
	up_write(&kg_sem);

	/*
	 * don't return an error if the message has been delivered
	 * at least to one agent
	 */
	if (one_success)
		rc = 0;

	return rc;
}
EXPORT_SYMBOL(libcfs_kkuc_group_put);

/**
 * Calls a callback function for each link of the given kuc group.
 *
 * @group:	the group to call the function on.
 * @cb_func:	the function to be called.
 * @cb_arg:	extra argument to be passed to the callback function.
 */
int libcfs_kkuc_group_foreach(const struct obd_uuid *uuid, int group,
			      libcfs_kkuc_cb_t cb_func, void *cb_arg)
{
	struct kkuc_reg *reg;
	int rc = 0;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	down_read(&kg_sem);
	list_for_each_entry(reg, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) && reg->kr_fp)
			rc = cb_func(reg->kr_data, cb_arg);
	}
	up_read(&kg_sem);

	return rc;
}
EXPORT_SYMBOL(libcfs_kkuc_group_foreach);

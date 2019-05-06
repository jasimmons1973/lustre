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
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/vfs.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "mdc_internal.h"

static ssize_t active_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%u\n", !dev->u.cli.cl_import->imp_deactive);
}

static ssize_t active_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	/* opposite senses */
	if (dev->u.cli.cl_import->imp_deactive == val) {
		rc = ptlrpc_set_import_active(dev->u.cli.cl_import, val);
		if (rc)
			count = rc;
	} else {
		CDEBUG(D_CONFIG, "activate %u: ignoring repeat request\n", val);
	}
	return count;
}
LUSTRE_RW_ATTR(active);

static ssize_t max_rpcs_in_flight_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%u\n", obd_get_max_rpcs_in_flight(&dev->u.cli));
}

static ssize_t max_rpcs_in_flight_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	rc = obd_set_max_rpcs_in_flight(&dev->u.cli, val);
	if (rc)
		count = rc;

	return count;
}
LUSTRE_RW_ATTR(max_rpcs_in_flight);

static ssize_t max_mod_rpcs_in_flight_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%hu\n", dev->u.cli.cl_max_mod_rpcs_in_flight);
}

static ssize_t max_mod_rpcs_in_flight_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buffer,
					    size_t count)
{
	struct obd_device *dev = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	u16 val;
	int rc;

	rc = kstrtou16(buffer, 10, &val);
	if (rc)
		return rc;

	rc = obd_set_max_mod_rpcs_in_flight(&dev->u.cli, val);
	if (rc)
		count = rc;

	return count;
}
LUSTRE_RW_ATTR(max_mod_rpcs_in_flight);

LUSTRE_RW_ATTR(max_pages_per_rpc);

#define mdc_conn_uuid_show conn_uuid_show
LUSTRE_RO_ATTR(mdc_conn_uuid);

static int mdc_rpc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *dev = seq->private;

	return obd_mod_rpc_stats_seq_show(&dev->u.cli, seq);
}

static ssize_t mdc_rpc_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *dev = seq->private;
	struct client_obd *cli = &dev->u.cli;

	lprocfs_oh_clear(&cli->cl_mod_rpcs_hist);

	return len;
}
LPROC_SEQ_FOPS(mdc_rpc_stats);

LPROC_SEQ_FOPS_WR_ONLY(mdc, ping);

LPROC_SEQ_FOPS_RO_TYPE(mdc, connect_flags);
LPROC_SEQ_FOPS_RO_TYPE(mdc, server_uuid);
LPROC_SEQ_FOPS_RO_TYPE(mdc, timeouts);
LPROC_SEQ_FOPS_RO_TYPE(mdc, state);

LPROC_SEQ_FOPS_RW_TYPE(mdc, import);
LPROC_SEQ_FOPS_RW_TYPE(mdc, pinger_recov);

static struct lprocfs_vars lprocfs_mdc_obd_vars[] = {
	{ .name	=	"ping",
	  .fops	=	&mdc_ping_fops			},
	{ .name	=	"connect_flags",
	  .fops	=	&mdc_connect_flags_fops		},
	{ .name	=	"mds_server_uuid",
	  .fops	=	&mdc_server_uuid_fops,		},
	{ .name	=	"timeouts",
	  .fops	=	&mdc_timeouts_fops		},
	{ .name	=	"import",
	  .fops	=	&mdc_import_fops		},
	{ .name	=	"state",
	  .fops	=	&mdc_state_fops			},
	{ .name	=	"pinger_recov",
	  .fops	=	&mdc_pinger_recov_fops		},
	{ .name =	"rpc_stats",
	  .fops =	&mdc_rpc_stats_fops		},
	{ NULL }
};

static struct attribute *mdc_attrs[] = {
	&lustre_attr_active.attr,
	&lustre_attr_max_rpcs_in_flight.attr,
	&lustre_attr_max_mod_rpcs_in_flight.attr,
	&lustre_attr_max_pages_per_rpc.attr,
	&lustre_attr_mdc_conn_uuid.attr,
	NULL,
};

int mdc_tunables_init(struct obd_device *obd)
{
	int rc;

	obd->obd_ktype.default_attrs = mdc_attrs;
	obd->obd_vars = lprocfs_mdc_obd_vars;

	rc = lprocfs_obd_setup(obd, false);
	if (rc)
		return rc;

	rc = ldebugfs_alloc_md_stats(obd, 0);
	if (rc) {
		lprocfs_obd_cleanup(obd);
		return rc;
	}

	rc = sptlrpc_lprocfs_cliobd_attach(obd);
	if (rc) {
		ldebugfs_free_md_stats(obd);
		lprocfs_obd_cleanup(obd);
		return rc;
	}
	ptlrpc_lprocfs_register_obd(obd);

	return 0;
}

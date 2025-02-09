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
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/fld/lproc_fld.c
 *
 * FLD (FIDs Location Database)
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 *	Di Wang <di.wang@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FLD

#include <linux/module.h>
#include <linux/uaccess.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_req_layout.h>
#include <lustre_fld.h>
#include <lustre_fid.h>
#include "fld_internal.h"

static int
fld_debugfs_targets_seq_show(struct seq_file *m, void *unused)
{
	struct lu_client_fld *fld = (struct lu_client_fld *)m->private;
	struct lu_fld_target *target;

	spin_lock(&fld->lcf_lock);
	list_for_each_entry(target, &fld->lcf_targets, ft_chain)
		seq_printf(m, "%s\n", fld_target_name(target));
	spin_unlock(&fld->lcf_lock);

	return 0;
}

static int
fld_debugfs_hash_seq_show(struct seq_file *m, void *unused)
{
	struct lu_client_fld *fld = (struct lu_client_fld *)m->private;

	spin_lock(&fld->lcf_lock);
	seq_printf(m, "%s\n", fld->lcf_hash->fh_name);
	spin_unlock(&fld->lcf_lock);

	return 0;
}

static ssize_t
fld_debugfs_hash_seq_write(struct file *file,
			   const char __user *buffer,
			   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lu_client_fld *fld = m->private;
	struct lu_fld_hash *hash = NULL;
	char fh_name[8];
	int i;

	if (count > sizeof(fh_name))
		return -ENAMETOOLONG;

	if (copy_from_user(fh_name, buffer, count) != 0)
		return -EFAULT;

	for (i = 0; fld_hash[i].fh_name; i++) {
		if (count != strlen(fld_hash[i].fh_name))
			continue;

		if (!strncmp(fld_hash[i].fh_name, fh_name, count)) {
			hash = &fld_hash[i];
			break;
		}
	}

	if (hash) {
		spin_lock(&fld->lcf_lock);
		fld->lcf_hash = hash;
		spin_unlock(&fld->lcf_lock);

		CDEBUG(D_INFO, "%s: Changed hash to \"%s\"\n",
		       fld->lcf_name, hash->fh_name);
	}

	return count;
}

static ssize_t
ldebugfs_cache_flush_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *pos)
{
	struct seq_file *m = file->private_data;
	struct lu_client_fld *fld = m->private;

	fld_cache_flush(fld->lcf_cache);

	CDEBUG(D_INFO, "%s: Lookup cache is flushed\n", fld->lcf_name);

	return count;
}

LDEBUGFS_SEQ_FOPS_RO(fld_debugfs_targets);
LDEBUGFS_SEQ_FOPS(fld_debugfs_hash);
LDEBUGFS_SEQ_FOPS_WR_ONLY(fld, cache_flush);

struct ldebugfs_vars fld_client_debugfs_list[] = {
	{ .name =	"targets",
	  .fops =	&fld_debugfs_targets_fops	},
	{ .name =	"hash",
	  .fops =	&fld_debugfs_hash_fops		},
	{ .name =	"cache_flush",
	  .fops =	&fld_cache_flush_fops	},
	{ NULL }
};

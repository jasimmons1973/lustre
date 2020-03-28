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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/statfs.h>
#include <lprocfs_status.h>
#include <obd_class.h>
#include <linux/seq_file.h>
#include "lov_internal.h"

static ssize_t stripesize_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;

	return sprintf(buf, "%llu\n", desc->ld_default_stripe_size);
}

static ssize_t stripesize_store(struct kobject *kobj, struct attribute *attr,
				const char *buf, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;
	u64 val;
	int rc;

	rc = sysfs_memparse(buf, count, &val, "B");
	if (rc < 0)
		return rc;

	lov_fix_desc_stripe_size(&val);
	desc->ld_default_stripe_size = val;

	return count;
}
LUSTRE_RW_ATTR(stripesize);

static ssize_t stripeoffset_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;

	return sprintf(buf, "%lld\n", desc->ld_default_stripe_offset);
}

static ssize_t stripeoffset_store(struct kobject *kobj, struct attribute *attr,
				  const char *buf, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;
	long val;
	int rc;

	rc = kstrtol(buf, 0, &val);
	if (rc)
		return rc;

	if (val < -1 || val > LOV_MAX_STRIPE_COUNT)
		return -ERANGE;

	desc->ld_default_stripe_offset = val;

	return count;
}
LUSTRE_RW_ATTR(stripeoffset);

static ssize_t stripetype_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;

	return sprintf(buf, "%u\n", desc->ld_pattern);
}

static ssize_t stripetype_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;
	u32 pattern;
	int rc;

	rc = kstrtouint(buffer, 0, &pattern);
	if (rc)
		return rc;

	lov_fix_desc_pattern(&pattern);
	desc->ld_pattern = pattern;

	return count;
}
LUSTRE_RW_ATTR(stripetype);

static ssize_t stripecount_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;

	return sprintf(buf, "%d\n",
		       (s16)(desc->ld_default_stripe_count + 1) - 1);
}

static ssize_t stripecount_store(struct kobject *kobj, struct attribute *attr,
				 const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;
	int stripe_count;
	int rc;

	rc = kstrtoint(buffer, 0, &stripe_count);
	if (rc)
		return rc;

	if (stripe_count < -1)
		return -ERANGE;

	lov_fix_desc_stripe_count(&stripe_count);
	desc->ld_default_stripe_count = stripe_count;

	return count;
}
LUSTRE_RW_ATTR(stripecount);

static ssize_t numobd_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc;

	desc = &obd->u.lov.desc;
	return sprintf(buf, "%u\n", desc->ld_tgt_count);
}
LUSTRE_RO_ATTR(numobd);

static ssize_t activeobd_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc;

	desc = &obd->u.lov.desc;
	return sprintf(buf, "%u\n", desc->ld_active_tgt_count);
}
LUSTRE_RO_ATTR(activeobd);

static ssize_t desc_uuid_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lov_desc *desc = &obd->u.lov.desc;

	return sprintf(buf, "%s\n", desc->ld_uuid.uuid);
}
LUSTRE_RO_ATTR(desc_uuid);

static void *lov_tgt_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_device *obd = p->private;
	struct lov_obd *lov = &obd->u.lov;

	while (*pos < lov->desc.ld_tgt_count) {
		if (lov->lov_tgts[*pos])
			return lov->lov_tgts[*pos];
		++*pos;
	}
	return NULL;
}

static void lov_tgt_seq_stop(struct seq_file *p, void *v)
{
}

static void *lov_tgt_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct obd_device *obd = p->private;
	struct lov_obd *lov = &obd->u.lov;

	while (++*pos < lov->desc.ld_tgt_count) {
		if (lov->lov_tgts[*pos])
			return lov->lov_tgts[*pos];
	}
	return NULL;
}

static int lov_tgt_seq_show(struct seq_file *p, void *v)
{
	struct lov_tgt_desc *tgt = v;

	seq_printf(p, "%d: %s %sACTIVE\n",
		   tgt->ltd_index, obd_uuid2str(&tgt->ltd_uuid),
		   tgt->ltd_active ? "" : "IN");
	return 0;
}

static const struct seq_operations lov_tgt_sops = {
	.start		= lov_tgt_seq_start,
	.stop		= lov_tgt_seq_stop,
	.next		= lov_tgt_seq_next,
	.show		= lov_tgt_seq_show,
};

static int lov_target_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &lov_tgt_sops);
	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private;
	return 0;
}

static const struct file_operations lov_debugfs_target_fops = {
	.owner		= THIS_MODULE,
	.open		= lov_target_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct attribute *lov_attrs[] = {
	&lustre_attr_activeobd.attr,
	&lustre_attr_numobd.attr,
	&lustre_attr_desc_uuid.attr,
	&lustre_attr_stripesize.attr,
	&lustre_attr_stripeoffset.attr,
	&lustre_attr_stripetype.attr,
	&lustre_attr_stripecount.attr,
	NULL,
};

int lov_tunables_init(struct obd_device *obd)
{
	struct lov_obd *lov = &obd->u.lov;
	int rc;

	obd->obd_ktype.default_attrs = lov_attrs;
	rc = lprocfs_obd_setup(obd, false);
	if (rc)
		return rc;

	debugfs_create_file("target_obd", 0444, obd->obd_debugfs_entry, obd,
			    &lov_debugfs_target_fops);

	lov->lov_pool_debugfs_entry = debugfs_create_dir("pools",
							 obd->obd_debugfs_entry);

	return 0;
}

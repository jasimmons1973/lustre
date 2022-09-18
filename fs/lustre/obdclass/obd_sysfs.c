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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/linux/linux-module.c
 *
 * Object Devices Class Driver
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <asm/ioctls.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/seq_file.h>
#include <linux/kobject.h>

#include <linux/libcfs/libcfs_crypto.h>
#include <uapi/linux/lnet/lnetctl.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <uapi/linux/lustre/lustre_ver.h>

struct static_lustre_uintvalue_attr {
	struct {
		struct attribute attr;
		ssize_t (*show)(struct kobject *kobj, struct attribute *attr,
				char *buf);
		ssize_t (*store)(struct kobject *kobj, struct attribute *attr,
				 const char *buf, size_t len);
	} u;
	int *value;
};

static ssize_t static_uintvalue_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct static_lustre_uintvalue_attr *lattr = (void *)attr;

	return sprintf(buf, "%d\n", *lattr->value);
}

static ssize_t static_uintvalue_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	struct static_lustre_uintvalue_attr *lattr = (void *)attr;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	*lattr->value = val;

	return count;
}

#define LUSTRE_STATIC_UINT_ATTR(name, value)				\
static struct static_lustre_uintvalue_attr lustre_sattr_##name =	\
	{ __ATTR(name, 0644, static_uintvalue_show,			\
		 static_uintvalue_store), value }

LUSTRE_STATIC_UINT_ATTR(debug_peer_on_timeout, &obd_debug_peer_on_timeout);
LUSTRE_STATIC_UINT_ATTR(dump_on_timeout, &obd_dump_on_timeout);
LUSTRE_STATIC_UINT_ATTR(dump_on_eviction, &obd_dump_on_eviction);
LUSTRE_STATIC_UINT_ATTR(at_min, &at_min);
LUSTRE_STATIC_UINT_ATTR(at_max, &at_max);
LUSTRE_STATIC_UINT_ATTR(at_extra, &at_extra);
LUSTRE_STATIC_UINT_ATTR(at_early_margin, &at_early_margin);
LUSTRE_STATIC_UINT_ATTR(at_history, &at_history);
LUSTRE_STATIC_UINT_ATTR(lbug_on_eviction, &obd_lbug_on_eviction);
LUSTRE_STATIC_UINT_ATTR(ping_interval, &ping_interval);
LUSTRE_STATIC_UINT_ATTR(evict_multiplier, &ping_evict_timeout_multiplier);

static ssize_t max_dirty_mb_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	return sprintf(buf, "%lu\n",
		       obd_max_dirty_pages / (1 << (20 - PAGE_SHIFT)));
}

static ssize_t max_dirty_mb_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 10, &val);
	if (rc)
		return rc;

	val *= 1 << (20 - PAGE_SHIFT); /* convert to pages */

	if (val > ((totalram_pages() / 10) * 9)) {
		/* Somebody wants to assign too much memory to dirty pages */
		return -EINVAL;
	}

	if (val < 4 << (20 - PAGE_SHIFT)) {
		/* Less than 4 Mb for dirty cache is also bad */
		return -EINVAL;
	}

	obd_max_dirty_pages = val;

	return count;
}
LUSTRE_RW_ATTR(max_dirty_mb);

static ssize_t version_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%s\n", LUSTRE_VERSION_STRING);
}

static ssize_t pinger_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
#ifdef CONFIG_LUSTRE_FS_PINGER
	return sprintf(buf, "%s\n", "on");
#else
	return sprintf(buf, "%s\n", "off");
#endif
}

static ssize_t
health_check_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	bool healthy = true;
	int i;
	size_t len = 0;

	if (libcfs_catastrophe)
		return sprintf(buf, "LBUG\n");

	read_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		struct obd_device *obd;

		obd = class_num2obd(i);
		if (!obd || !obd->obd_attached || !obd->obd_set_up)
			continue;

		LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
		if (obd->obd_stopping)
			continue;

		class_incref(obd, __func__, current);
		read_unlock(&obd_dev_lock);

		if (obd_health_check(NULL, obd))
			healthy = false;

		class_decref(obd, __func__, current);
		read_lock(&obd_dev_lock);

		if (!healthy)
			break;
	}
	read_unlock(&obd_dev_lock);

	if (healthy)
		len = sprintf(buf, "healthy\n");
	else
		len = sprintf(buf, "NOT HEALTHY\n");

	return len;
}

static ssize_t jobid_var_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n", obd_jobid_var);
}

static ssize_t jobid_var_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer,
			       size_t count)
{
	static const char * const valid[] = {
		JOBSTATS_DISABLE,
		JOBSTATS_PROCNAME_UID,
		JOBSTATS_NODELOCAL,
		JOBSTATS_SESSION,
		NULL
	};
	int i;

	if (!count || count > JOBSTATS_JOBID_VAR_MAX_LEN)
		return -EINVAL;

	for (i = 0; valid[i]; i++)
		if (sysfs_streq(buffer, valid[i]))
			break;
	if (!valid[i])
		return -EINVAL;

	memset(obd_jobid_var, 0, JOBSTATS_JOBID_VAR_MAX_LEN + 1);
	strcpy(obd_jobid_var, valid[i]);

	return count;
}

static ssize_t jobid_name_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n", obd_jobid_name);
}

static ssize_t jobid_name_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer,
				size_t count)
{
	if (!count || count > LUSTRE_JOBID_SIZE)
		return -EINVAL;

	memcpy(obd_jobid_name, buffer, count);

	obd_jobid_name[count] = 0;

	/* Trim the trailing '\n' if any */
	if (obd_jobid_name[count - 1] == '\n')
		obd_jobid_name[count - 1] = 0;

	return count;
}

static ssize_t jobid_this_session_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	char *jid;
	int ret = -ENOENT;

	rcu_read_lock();
	jid = jobid_current();
	if (jid)
		ret = scnprintf(buf, PAGE_SIZE, "%s\n", jid);
	rcu_read_unlock();
	return ret;
}

static ssize_t jobid_this_session_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	char *jobid;
	int len;
	int ret;

	if (!count || count > LUSTRE_JOBID_SIZE)
		return -EINVAL;

	jobid = kstrndup(buffer, count, GFP_KERNEL);
	if (!jobid)
		return -ENOMEM;
	len = strcspn(jobid, "\n ");
	jobid[len] = '\0';
	ret = jobid_set_current(jobid);
	kfree(jobid);

	return ret ?: count;
}

static ssize_t timeout_show(struct kobject *kobj,
			    struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%u\n", obd_timeout);
}

static ssize_t timeout_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buffer,
			     size_t count)
{
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;
	obd_timeout = val ?: 1U;
	ping_interval = max(obd_timeout / 4, 1U);

	return count;
}

/* Root for /sys/kernel/debug/lustre */
struct dentry *debugfs_lustre_root;
EXPORT_SYMBOL_GPL(debugfs_lustre_root);

LUSTRE_RO_ATTR(version);
LUSTRE_RO_ATTR(pinger);
LUSTRE_RO_ATTR(health_check);
LUSTRE_RW_ATTR(jobid_var);
LUSTRE_RW_ATTR(jobid_name);
LUSTRE_RW_ATTR(jobid_this_session);
LUSTRE_RW_ATTR(timeout);

static struct attribute *lustre_attrs[] = {
	&lustre_attr_version.attr,
	&lustre_attr_pinger.attr,
	&lustre_attr_health_check.attr,
	&lustre_attr_jobid_name.attr,
	&lustre_attr_jobid_var.attr,
	&lustre_attr_jobid_this_session.attr,
	&lustre_attr_timeout.attr,
	&lustre_attr_max_dirty_mb.attr,
	&lustre_sattr_debug_peer_on_timeout.u.attr,
	&lustre_sattr_dump_on_timeout.u.attr,
	&lustre_sattr_dump_on_eviction.u.attr,
	&lustre_sattr_at_min.u.attr,
	&lustre_sattr_at_max.u.attr,
	&lustre_sattr_at_extra.u.attr,
	&lustre_sattr_at_early_margin.u.attr,
	&lustre_sattr_at_history.u.attr,
	&lustre_sattr_lbug_on_eviction.u.attr,
	&lustre_sattr_ping_interval.u.attr,
	&lustre_sattr_evict_multiplier.u.attr,
	NULL,
};

static void *obd_device_list_seq_start(struct seq_file *p, loff_t *pos)
{
	if (*pos >= class_devno_max())
		return NULL;

	return pos;
}

static void obd_device_list_seq_stop(struct seq_file *p, void *v)
{
}

static void *obd_device_list_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	++*pos;
	if (*pos >= class_devno_max())
		return NULL;

	return pos;
}

static int obd_device_list_seq_show(struct seq_file *p, void *v)
{
	loff_t index = *(loff_t *)v;
	struct obd_device *obd = class_num2obd((int)index);
	char *status;

	if (!obd)
		return 0;

	LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
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

	seq_printf(p, "%3d %s %s %s %s %d\n",
		   (int)index, status, obd->obd_type->typ_name,
		   obd->obd_name, obd->obd_uuid.uuid,
		   atomic_read(&obd->obd_refcount));
	return 0;
}

static const struct seq_operations obd_device_list_sops = {
	.start = obd_device_list_seq_start,
	.stop = obd_device_list_seq_stop,
	.next = obd_device_list_seq_next,
	.show = obd_device_list_seq_show,
};

static int obd_device_list_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc = seq_open(file, &obd_device_list_sops);

	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private;

	return 0;
}

static const struct file_operations obd_device_list_fops = {
	.owner   = THIS_MODULE,
	.open    = obd_device_list_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

/* checksum_speed */
static void *checksum_speed_start(struct seq_file *p, loff_t *pos)
{
	return pos;
}

static void checksum_speed_stop(struct seq_file *p, void *v)
{
}

static void *checksum_speed_next(struct seq_file *p, void *v, loff_t *pos)
{
	++(*pos);
	if (*pos >= CFS_HASH_ALG_SPEED_MAX - 1)
		return NULL;

	return pos;
}

static int checksum_speed_show(struct seq_file *p, void *v)
{
	loff_t index = *(loff_t *)v;

	if (!index || index > CFS_HASH_ALG_SPEED_MAX - 1)
		return 0;

	seq_printf(p, "%s: %d\n", cfs_crypto_hash_name(index),
		   cfs_crypto_hash_speeds[index]);

	return 0;
}

static const struct seq_operations checksum_speed_sops = {
	.start		= checksum_speed_start,
	.stop		= checksum_speed_stop,
	.next		= checksum_speed_next,
	.show		= checksum_speed_show,
};

static int checksum_speed_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &checksum_speed_sops);

	if (rc)
		return rc;

	return 0;
}

static const struct file_operations checksum_speed_fops = {
	.owner		= THIS_MODULE,
	.open		= checksum_speed_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int
health_check_seq_show(struct seq_file *m, void *unused)
{
	int i;

	read_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		struct obd_device *obd;

		obd = class_num2obd(i);
		if (!obd || !obd->obd_attached || !obd->obd_set_up)
			continue;

		LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
		if (obd->obd_stopping)
			continue;

		class_incref(obd, __func__, current);
		read_unlock(&obd_dev_lock);

		if (obd_health_check(NULL, obd)) {
			seq_printf(m, "device %s reported unhealthy\n",
				   obd->obd_name);
		}
		class_decref(obd, __func__, current);
		read_lock(&obd_dev_lock);
	}
	read_unlock(&obd_dev_lock);

	return 0;
}

LDEBUGFS_SEQ_FOPS_RO(health_check);

struct kset *lustre_kset;
EXPORT_SYMBOL_GPL(lustre_kset);

static const struct attribute_group lustre_attr_group = {
	.attrs = lustre_attrs,
};

ssize_t class_set_global(const char *param)
{
	const char *value = strchr(param, '=') + 1;
	size_t off = value - param - 1;
	ssize_t count = -ENOENT;
	int i;

	for (i = 0; lustre_attrs[i]; i++) {
		if (!strncmp(lustre_attrs[i]->name, param, off)) {
			count = lustre_attr_store(&lustre_kset->kobj,
						  lustre_attrs[i], value,
						  strlen(value));
			break;
		}
	}
	return count;
}

int class_procfs_init(void)
{
	int rc = -ENOMEM;

	lustre_kset = kset_create_and_add("lustre", NULL, fs_kobj);
	if (!lustre_kset)
		goto out;

	/* Create the files associated with this kobject */
	rc = sysfs_create_group(&lustre_kset->kobj, &lustre_attr_group);
	if (rc) {
		kset_unregister(lustre_kset);
		goto out;
	}

	rc = jobid_cache_init();
	if (rc) {
		kset_unregister(lustre_kset);
		goto out;
	}

	debugfs_lustre_root = debugfs_create_dir("lustre", NULL);

	debugfs_create_file("devices", 0444, debugfs_lustre_root, NULL,
			    &obd_device_list_fops);

	debugfs_create_file("health_check", 0444, debugfs_lustre_root,
			    NULL, &health_check_fops);

	debugfs_create_file("checksum_speed", 0444, debugfs_lustre_root,
			    NULL, &checksum_speed_fops);
out:
	return rc;
}

int class_procfs_clean(void)
{
	debugfs_remove_recursive(debugfs_lustre_root);

	debugfs_lustre_root = NULL;

	jobid_cache_fini();

	sysfs_remove_group(&lustre_kset->kobj, &lustre_attr_group);

	kset_unregister(lustre_kset);

	return 0;
}

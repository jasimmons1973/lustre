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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/atomic.h>
#include <linux/miscdevice.h>
#include <linux/libcfs/libcfs.h>
#include <linux/uaccess.h>

#include <obd_support.h>
#include <obd_class.h>
#include <uapi/linux/lnet/lnetctl.h>
#include <lustre_kernelcomm.h>
#include <lprocfs_status.h>
#include <linux/list.h>
#include <cl_object.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <uapi/linux/lnet/libcfs_ioctl.h>
#include "llog_internal.h"

/* The following are visible and mutable through /sys/fs/lustre. */
unsigned int obd_debug_peer_on_timeout;
EXPORT_SYMBOL(obd_debug_peer_on_timeout);
unsigned int obd_dump_on_timeout;
EXPORT_SYMBOL(obd_dump_on_timeout);
unsigned int obd_dump_on_eviction;
EXPORT_SYMBOL(obd_dump_on_eviction);
unsigned int obd_lbug_on_eviction;
EXPORT_SYMBOL(obd_lbug_on_eviction);
unsigned long obd_max_dirty_pages;
EXPORT_SYMBOL(obd_max_dirty_pages);
atomic_long_t obd_dirty_pages;
EXPORT_SYMBOL(obd_dirty_pages);
unsigned int obd_timeout = OBD_TIMEOUT_DEFAULT;   /* seconds */
EXPORT_SYMBOL(obd_timeout);
unsigned int ping_interval = (OBD_TIMEOUT_DEFAULT > 4) ?
			     (OBD_TIMEOUT_DEFAULT / 4) : 1;
EXPORT_SYMBOL(ping_interval);
unsigned int ping_evict_timeout_multiplier = 6;
EXPORT_SYMBOL(ping_evict_timeout_multiplier);
unsigned int obd_timeout_set;
EXPORT_SYMBOL(obd_timeout_set);
/* Adaptive timeout defs here instead of ptlrpc module for /sys/fs/ access */
unsigned int at_min;
EXPORT_SYMBOL(at_min);
unsigned int at_max = 600;
EXPORT_SYMBOL(at_max);
unsigned int at_history = 600;
EXPORT_SYMBOL(at_history);
int at_early_margin = 5;
EXPORT_SYMBOL(at_early_margin);
int at_extra = 30;
EXPORT_SYMBOL(at_extra);

int obd_ioctl_msg(const char *file, const char *func, int line, int level,
		  const char *name, unsigned int cmd, const char *msg, int rc)
{
	static struct cfs_debug_limit_state cdls;
	static char *dirs[] = {
		[_IOC_NONE]		= "_IO",
		[_IOC_READ]		= "_IOR",
		[_IOC_WRITE]		= "_IOW",
		[_IOC_READ|_IOC_WRITE]	= "_IOWR",
	};
	char type;

	type = _IOC_TYPE(cmd);
	__CDEBUG_WITH_LOC(file, func, line, level, &cdls,
			  "%s: iocontrol from '%s' cmd=%x %s('%c', %u, %u) %s: rc = %d\n",
			  name, current->comm, cmd,
			  dirs[_IOC_DIR(cmd)] ?: "_IO?",
			  isprint(type) ? type : '?', _IOC_NR(cmd),
			  _IOC_SIZE(cmd), msg, rc);
	return rc;
}
EXPORT_SYMBOL(obd_ioctl_msg);

static int class_resolve_dev_name(u32 len, const char *name)
{
	int rc;
	int dev;

	if (!len || !name) {
		CERROR("No name passed,!\n");
		rc = -EINVAL;
		goto out;
	}
	if (name[len - 1] != 0) {
		CERROR("Name not nul terminated!\n");
		rc = -EINVAL;
		goto out;
	}

	CDEBUG(D_IOCTL, "device name %s\n", name);
	dev = class_name2dev(name);
	if (dev == -1) {
		CDEBUG(D_IOCTL, "No device for name %s!\n", name);
		rc = -EINVAL;
		goto out;
	}

	CDEBUG(D_IOCTL, "device name %s, dev %d\n", name, dev);
	rc = dev;

out:
	return rc;
}

#define OBD_MAX_IOCTL_BUFFER    8192

static int obd_ioctl_is_invalid(struct obd_ioctl_data *data)
{
	const int maxlen = 1 << 30;

	if (data->ioc_len > maxlen) {
		CERROR("OBD ioctl: ioc_len larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen1 > maxlen) {
		CERROR("OBD ioctl: ioc_inllen1 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen2 > maxlen) {
		CERROR("OBD ioctl: ioc_inllen2 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen3 > maxlen) {
		CERROR("OBD ioctl: ioc_inllen3 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inllen4 > maxlen) {
		CERROR("OBD ioctl: ioc_inllen4 larger than 1<<30\n");
		return 1;
	}

	if (data->ioc_inlbuf1 && data->ioc_inllen1 == 0) {
		CERROR("OBD ioctl: inlbuf1 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf2 && data->ioc_inllen2 == 0) {
		CERROR("OBD ioctl: inlbuf2 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf3 && data->ioc_inllen3 == 0) {
		CERROR("OBD ioctl: inlbuf3 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_inlbuf4 && data->ioc_inllen4 == 0) {
		CERROR("OBD ioctl: inlbuf4 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_pbuf1 && data->ioc_plen1 == 0) {
		CERROR("OBD ioctl: pbuf1 pointer but 0 length\n");
		return 1;
	}

	if (data->ioc_pbuf2 && data->ioc_plen2 == 0) {
		CERROR("OBD ioctl: pbuf2 pointer but 0 length\n");
		return 1;
	}

	if (!data->ioc_pbuf1 && data->ioc_plen1 != 0) {
		CERROR("OBD ioctl: plen1 set but NULL pointer\n");
		return 1;
	}

	if (!data->ioc_pbuf2 && data->ioc_plen2 != 0) {
		CERROR("OBD ioctl: plen2 set but NULL pointer\n");
		return 1;
	}

	if (obd_ioctl_packlen(data) > data->ioc_len) {
		CERROR("OBD ioctl: packlen exceeds ioc_len (%d > %d)\n",
		       obd_ioctl_packlen(data), data->ioc_len);
		return 1;
	}

	return 0;
}

/* buffer MUST be at least the size of obd_ioctl_hdr */
int obd_ioctl_getdata(struct obd_ioctl_data **datap, int *len, void __user *arg)
{
	struct obd_ioctl_data *data;
	struct obd_ioctl_hdr hdr;
	int offset = 0;
	int rc = -EINVAL;

	if (copy_from_user(&hdr, arg, sizeof(hdr)))
		return -EFAULT;

	if (hdr.ioc_version != OBD_IOCTL_VERSION) {
		CERROR("%s: kernel/user version mismatch (%x != %x): rc = %d\n",
		       current->comm, OBD_IOCTL_VERSION, hdr.ioc_version, rc);
		return rc;
	}

	if (hdr.ioc_len > OBD_MAX_IOCTL_BUFFER) {
		CERROR("%s: user buffer len %d exceeds %d max: rc = %d\n",
		       current->comm, hdr.ioc_len, OBD_MAX_IOCTL_BUFFER, rc);
		return rc;
	}

	if (hdr.ioc_len < sizeof(*data)) {
		CERROR("%s: user buffer %d too small for ioctl %zu: rc = %d\n",
		       current->comm, hdr.ioc_len, sizeof(*data), rc);
		return rc;
	}

	/* When there are lots of processes calling vmalloc on multi-core
	 * system, the high lock contention will hurt performance badly,
	 * obdfilter-survey is an example, which relies on ioctl. So we'd
	 * better avoid vmalloc on ioctl path. LU-66
	 */
	data = kvzalloc(hdr.ioc_len, GFP_KERNEL);
	if (!data) {
		rc = -ENOMEM;
		CERROR("%s: cannot allocate control buffer len %d: rc = %d\n",
		       current->comm, hdr.ioc_len, rc);
		return rc;
	}
	*len = hdr.ioc_len;
	*datap = data;

	if (copy_from_user(data, arg, hdr.ioc_len)) {
		rc = -EFAULT;
		goto out_free;
	}

	if (hdr.ioc_len != data->ioc_len) {
		rc = -EINVAL;
		goto out_free;
	}

	if (obd_ioctl_is_invalid(data)) {
		rc = -EINVAL;
		goto out_free;
	}

	if (data->ioc_inllen1) {
		data->ioc_inlbuf1 = &data->ioc_bulk[0];
		offset += cfs_size_round(data->ioc_inllen1);
	}

	if (data->ioc_inllen2) {
		data->ioc_inlbuf2 = &data->ioc_bulk[0] + offset;
		offset += cfs_size_round(data->ioc_inllen2);
	}

	if (data->ioc_inllen3) {
		data->ioc_inlbuf3 = &data->ioc_bulk[0] + offset;
		offset += cfs_size_round(data->ioc_inllen3);
	}

	if (data->ioc_inllen4)
		data->ioc_inlbuf4 = &data->ioc_bulk[0] + offset;

	return 0;

out_free:
	kvfree(data);
	return rc;
}
EXPORT_SYMBOL(obd_ioctl_getdata);

int class_handle_ioctl(unsigned int cmd, void __user *uarg)
{
	struct obd_ioctl_data *data;
	struct obd_device *obd = NULL;
	int rc = 0, len = 0;

	CDEBUG(D_IOCTL, "obdclass: cmd=%x len=%u uarg=%pK\n", cmd, len, uarg);
	if (unlikely(_IOC_TYPE(cmd) != 'f' && cmd != IOC_OSC_SET_ACTIVE))
		return OBD_IOC_ERROR(obd->obd_name, cmd, "unknown", -ENOTTY);

	rc = obd_ioctl_getdata(&data, &len, uarg);
	if (rc) {
		CERROR("%s: ioctl data error: rc = %d\n", current->comm, rc);
		return rc;
	}

	switch (cmd) {
	case OBD_IOC_PROCESS_CFG: {
		struct lustre_cfg *lcfg;

		if (!data->ioc_plen1 || !data->ioc_pbuf1) {
			rc = OBD_IOC_ERROR("obdclass", cmd, "no config buffer",
					   -EINVAL);
			goto out;
		}
		lcfg = kzalloc(data->ioc_plen1, GFP_NOFS);
		if (!lcfg) {
			rc = -ENOMEM;
			goto out;
		}
		rc = copy_from_user(lcfg, data->ioc_pbuf1, data->ioc_plen1);
		if (!rc)
			rc = lustre_cfg_sanity_check(lcfg, data->ioc_plen1);
		if (!rc)
			rc = class_process_config(lcfg);

		kfree(lcfg);
		goto out;
	}

	case OBD_GET_VERSION: {
		/* This was the method to pass to user land the lustre version.
		 * Today that information is in the sysfs tree so we can in the
		 * future remove this.
		 */
		BUILD_BUG_ON(OBD_OCD_VERSION(3, 0, 53, 0) <=
			     LUSTRE_VERSION_CODE);

		if (!data->ioc_inlbuf1) {
			rc = OBD_IOC_ERROR("obdclass", cmd, "no buffer passed",
					   -EINVAL);
			goto out;
		}

		if (strlen(LUSTRE_VERSION_STRING) + 1 > data->ioc_inllen1) {
			rc = OBD_IOC_ERROR("obdclass", cmd, "buffer too small",
					   -EINVAL);
			goto out;
		}

		WARN_ONCE(1,
			  "ioctl(OBD_GET_VERSION) is deprecated, use llapi_get_version_string() and/or relink\n");

		memcpy(data->ioc_bulk, LUSTRE_VERSION_STRING,
		       strlen(LUSTRE_VERSION_STRING) + 1);

		if (copy_to_user(uarg, data, len))
			rc = -EFAULT;
		goto out;
	}
	case OBD_IOC_NAME2DEV: {
		/* Resolve a device name.  This does not change the
		 * currently selected device.
		 */
		int dev;

		dev = class_resolve_dev_name(data->ioc_inllen1,
					     data->ioc_inlbuf1);
		data->ioc_dev = dev;
		if (dev < 0) {
			rc = -EINVAL;
			goto out;
		}

		if (copy_to_user(uarg, data, sizeof(*data)))
			rc = -EFAULT;
		goto out;
	}

	case OBD_IOC_UUID2DEV: {
		/* Resolve device uuid, does not change current selected dev */
		struct obd_uuid uuid;
		int dev;

		if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
			rc = OBD_IOC_ERROR("obdclass", cmd, "no UUID passed",
					   -EINVAL);
			goto out;
		}
		if (data->ioc_inlbuf1[data->ioc_inllen1 - 1] != 0) {
			rc = OBD_IOC_ERROR("obdclass", cmd, "unterminated UUID",
					   -EINVAL);
			goto out;
		}

		CDEBUG(D_IOCTL, "device name %s\n", data->ioc_inlbuf1);
		obd_str2uuid(&uuid, data->ioc_inlbuf1);
		dev = class_uuid2dev(&uuid);
		data->ioc_dev = dev;
		if (dev == -1) {
			CDEBUG(D_IOCTL, "No device for UUID %s!\n",
			       data->ioc_inlbuf1);
			rc = -EINVAL;
			goto out;
		}

		CDEBUG(D_IOCTL, "device name %s, dev %d\n", data->ioc_inlbuf1,
		       dev);

		if (copy_to_user(uarg, data, sizeof(*data)))
			rc = -EFAULT;
		goto out;
	}

	case OBD_IOC_GETDEVICE: {
		int index = data->ioc_count;
		char *status, *str;

		if (!data->ioc_inlbuf1) {
			rc = OBD_IOC_ERROR("obdclass", cmd, "no buffer passed",
					    -EINVAL);
			goto out;
		}
		if (data->ioc_inllen1 < MAX_OBD_NAME) {
			rc = OBD_IOC_ERROR("obdclass", cmd, "too small version",
					   -EINVAL);
			goto out;
		}

		obd = class_num2obd(index);
		if (!obd) {
			rc = -ENOENT;
			goto out;
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
		str = (char *)data->ioc_bulk;
		snprintf(str, len - sizeof(*data), "%3d %s %s %s %s %d",
			 (int)index, status, obd->obd_type->typ_name,
			 obd->obd_name, obd->obd_uuid.uuid,
			 atomic_read(&obd->obd_refcount));

		if (copy_to_user(uarg, data, len))
			rc = -EFAULT;
		goto out;
	}
	}

	if (data->ioc_dev == OBD_DEV_BY_DEVNAME) {
		if (data->ioc_inllen4 <= 0 || !data->ioc_inlbuf4) {
			rc = -EINVAL;
			goto out;
		}
		if (strnlen(data->ioc_inlbuf4, MAX_OBD_NAME) >= MAX_OBD_NAME) {
			rc = -EINVAL;
			goto out;
		}
		obd = class_name2obd(data->ioc_inlbuf4);
	} else if (data->ioc_dev < class_devno_max()) {
		obd = class_num2obd(data->ioc_dev);
	} else {
		rc = OBD_IOC_ERROR("obdclass", cmd, "no device", -EINVAL);
		goto out;
	}

	if (!obd) {
		rc = OBD_IOC_ERROR(data->ioc_inlbuf4, cmd, "no device found",
				   -EINVAL);
		goto out;
	}
	LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);

	if (!obd->obd_set_up || obd->obd_stopping) {
		rc = -EINVAL;
		CERROR("obdclass: device %d not set up: rc = %d\n",
		       data->ioc_dev, rc);
		goto out;
	}

	rc = obd_iocontrol(cmd, obd->obd_self_export, len, data, NULL);
	if (rc)
		goto out;

	if (copy_to_user(uarg, data, len))
		rc = -EFAULT;
out:
	kvfree(data);
	return rc;
} /* class_handle_ioctl */

/* to control /dev/obd */
static long obd_class_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	/* Allow non-root access for some limited ioctls */
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if ((cmd & 0xffffff00) == ((int)'T') << 8) /* ignore all tty ioctls */
		return -ENOTTY;

	return class_handle_ioctl(cmd, (void __user *)arg);
}

/* declare character device */
static const struct file_operations obd_psdev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= obd_class_ioctl,
};

/* modules setup */
static struct miscdevice obd_psdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= OBD_DEV_NAME,
	.fops		= &obd_psdev_fops,
};

#define test_string_to_size_err(value, expect, def_unit, __rc)		       \
({									       \
	u64 __size;							       \
	int __ret;							       \
									       \
	BUILD_BUG_ON(sizeof(value) >= 23);				       \
	__ret = sysfs_memparse(value, sizeof(value) - 1, &__size, def_unit);   \
	if (__ret != __rc)						       \
		CERROR("string_helper: parsing '%s' expect rc %d != got %d\n", \
		       value, __rc, __ret);				       \
	else if (!__ret && (u64)expect != __size)			       \
		CERROR("string_helper: parsing '%s' expect %llu != got %llu\n",\
		       value, (u64)expect, __size);			       \
	__ret;								       \
})
#define test_string_to_size_one(value, expect, def_unit)		       \
	test_string_to_size_err(value, expect, def_unit, 0)

static int __init obd_init_checks(void)
{
	u64 u64val, div64val;
	char buf[64];
	int len, ret = 0;

	CDEBUG(D_INFO, "OBD_OBJECT_EOF = %#llx\n", (u64)OBD_OBJECT_EOF);

	u64val = OBD_OBJECT_EOF;
	CDEBUG(D_INFO, "u64val OBD_OBJECT_EOF = %#llx\n", u64val);
	if (u64val != OBD_OBJECT_EOF) {
		CERROR("u64 %#llx(%d) != 0xffffffffffffffff\n",
		       u64val, (int)sizeof(u64val));
		ret = -EINVAL;
	}
	len = snprintf(buf, sizeof(buf), "%#llx", u64val);
	if (len != 18) {
		CERROR("LPX64 wrong length! strlen(%s)=%d != 18\n", buf, len);
		ret = -EINVAL;
	}

	div64val = OBD_OBJECT_EOF;
	CDEBUG(D_INFO, "u64val OBD_OBJECT_EOF = %#llx\n", u64val);
	if (u64val != OBD_OBJECT_EOF) {
		CERROR("u64 %#llx(%d) != 0xffffffffffffffff\n",
		       u64val, (int)sizeof(u64val));
		ret = -EOVERFLOW;
	}
	if (u64val >> 8 != OBD_OBJECT_EOF >> 8) {
		CERROR("u64 %#llx(%d) != 0xffffffffffffffff\n",
		       u64val, (int)sizeof(u64val));
		ret = -EOVERFLOW;
	}
	if (do_div(div64val, 256) != (u64val & 255)) {
		CERROR("do_div(%#llx,256) != %llu\n", u64val, u64val & 255);
		ret = -EOVERFLOW;
	}
	if (u64val >> 8 != div64val) {
		CERROR("do_div(%#llx,256) %llu != %llu\n",
		       u64val, div64val, u64val >> 8);
		ret = -EOVERFLOW;
	}
	len = snprintf(buf, sizeof(buf), "%#llx", u64val);
	if (len != 18) {
		CERROR("LPX64 wrong length! strlen(%s)=%d != 18\n", buf, len);
		ret = -EINVAL;
	}
	len = snprintf(buf, sizeof(buf), "%llu", u64val);
	if (len != 20) {
		CERROR("LPU64 wrong length! strlen(%s)=%d != 20\n", buf, len);
		ret = -EINVAL;
	}
	len = snprintf(buf, sizeof(buf), "%lld", u64val);
	if (len != 2) {
		CERROR("LPD64 wrong length! strlen(%s)=%d != 2\n", buf, len);
		ret = -EINVAL;
	}
	if ((u64val & ~PAGE_MASK) >= PAGE_SIZE) {
		CERROR("mask failed: u64val %llu >= %llu\n", u64val,
		      (u64)PAGE_SIZE);
		ret = -EINVAL;
	}
	if (ret)
		return ret;

	/* invalid string */
	if (!test_string_to_size_err("256B34", 256, "B", -EINVAL)) {
		CERROR("string_helpers: format should be number then units\n");
		ret = -EINVAL;
	}
	if (!test_string_to_size_err("132OpQ", 132, "B", -EINVAL)) {
		CERROR("string_helpers: format should be number then units\n");
		ret = -EINVAL;
	}
	if (!test_string_to_size_err("1.82B", 1, "B", -EINVAL)) {
		CERROR("string_helpers: 'B' with '.' should be invalid\n");
		ret = -EINVAL;
	}
	if (test_string_to_size_one("343\n", 343, "B")) {
		CERROR("string_helpers: should ignore newline\n");
		ret = -EINVAL;
	}
	if (ret)
		return ret;

	/* memparse unit handling */
	ret = 0;
	ret += test_string_to_size_one("0B", 0, "B");
	ret += test_string_to_size_one("512B", 512, "B");
	ret += test_string_to_size_one("1.067kB", 1067, "B");
	ret += test_string_to_size_one("1.042KiB", 1067, "B");
	ret += test_string_to_size_one("8", 8388608, "M");
	ret += test_string_to_size_one("65536", 65536, "B");
	ret += test_string_to_size_one("128", 131072, "K");
	ret += test_string_to_size_one("1M", 1048576, "B");
	ret += test_string_to_size_one("0.5T", 549755813888ULL, "T");
	ret += test_string_to_size_one("256.5G", 275414777856ULL, "G");
	if (ret)
		return ret;

	/* string helper values */
	ret += test_string_to_size_one("16", 16777216, "MiB");
	ret += test_string_to_size_one("8.39MB", 8390000, "MiB");
	ret += test_string_to_size_one("8.00MiB", 8388608, "MiB");
	ret += test_string_to_size_one("256GB", 256000000000ULL, "GiB");
	ret += test_string_to_size_one("238.731GiB", 256335459385ULL, "GiB");
	if (ret)
		return ret;

	/* huge values */
	ret += test_string_to_size_one("0.4TB", 400000000000ULL, "TiB");
	ret += test_string_to_size_one("12.5TiB", 13743895347200ULL, "TiB");
	ret += test_string_to_size_one("2PB", 2000000000000000ULL, "PiB");
	ret += test_string_to_size_one("16PiB", 18014398509481984ULL, "PiB");
	if (ret)
		return ret;

	/* huge values should overflow */
	if (!test_string_to_size_err("1000EiB", 0, "EiB", -EOVERFLOW)) {
		CERROR("string_helpers: failed to detect binary overflow\n");
		ret = -EINVAL;
	}
	if (!test_string_to_size_err("1000EB", 0, "EiB", -EOVERFLOW)) {
		CERROR("string_helpers: failed to detect decimal overflow\n");
		ret = -EINVAL;
	}

	return ret;
}

static int __init obdclass_init(void)
{
	int err;

	LCONSOLE_INFO("Lustre: Build Version: " LUSTRE_VERSION_STRING "\n");

	err = libcfs_setup();
	if (err)
		return err;

	err = obd_init_checks();
	if (err)
		return err;

	err = libcfs_kkuc_init();
	if (err)
		return err;

	err = obd_zombie_impexp_init();
	if (err)
		goto cleanup_kkuc;

	err = class_handle_init();
	if (err)
		goto cleanup_zombie_impexp;

	err = misc_register(&obd_psdev);
	if (err) {
		CERROR("cannot register OBD miscdevices: err %d\n", err);
		goto cleanup_class_handle;
	}

	/* Default the dirty page cache cap to 1/2 of system memory.
	 * For clients with less memory, a larger fraction is needed
	 * for other purposes (mostly for BGL).
	 */
	if (totalram_pages() <= 512 << (20 - PAGE_SHIFT))
		obd_max_dirty_pages = totalram_pages() / 4;
	else
		obd_max_dirty_pages = totalram_pages() / 2;

	err = obd_init_caches();
	if (err)
		goto cleanup_deregister;

	err = class_procfs_init();
	if (err)
		goto cleanup_caches;

	err = lu_global_init();
	if (err)
		goto cleanup_class_procfs;

	err = cl_global_init();
	if (err != 0)
		goto cleanup_lu_global;

	err = llog_info_init();
	if (err)
		goto cleanup_cl_global;

	/* simulate a late OOM situation now to require all
	 * alloc'ed/initialized resources to be freed
	 */
	if (CFS_FAIL_CHECK(OBD_FAIL_OBDCLASS_MODULE_LOAD)) {
		/* force error to ensure module will be unloaded/cleaned */
		err = -ENOMEM;
		goto cleanup_all;
	}
	return 0;

cleanup_all:
	llog_info_fini();

cleanup_cl_global:
	cl_global_fini();

cleanup_lu_global:
	lu_global_fini();

cleanup_class_procfs:
	class_procfs_clean();

cleanup_caches:
	obd_cleanup_caches();

cleanup_deregister:
	misc_deregister(&obd_psdev);

cleanup_class_handle:
	class_handle_cleanup();

cleanup_zombie_impexp:
	obd_zombie_impexp_stop();

cleanup_kkuc:
	libcfs_kkuc_fini();

	return err;
}

static void obdclass_exit(void)
{
	misc_deregister(&obd_psdev);
	llog_info_fini();
	cl_global_fini();
	lu_global_fini();

	obd_cleanup_caches();

	class_procfs_clean();

	class_handle_cleanup();
	class_del_uuid(NULL); /* Delete all UUIDs. */
	obd_zombie_impexp_stop();
	libcfs_kkuc_fini();
}

void obd_heat_clear(struct obd_heat_instance *instance, int count)
{
	memset(instance, 0, sizeof(*instance) * count);
}
EXPORT_SYMBOL(obd_heat_clear);

/*
 * The file heat is calculated for every time interval period I. The access
 * frequency during each period is counted. The file heat is only recalculated
 * at the end of a time period.  And a percentage of the former file heat is
 * lost when recalculated. The recursion formula to calculate the heat of the
 * file f is as follow:
 *
 * Hi+1(f) = (1-P)*Hi(f)+ P*Ci
 *
 * Where Hi is the heat value in the period between time points i*I and
 * (i+1)*I; Ci is the access count in the period; the symbol P refers to the
 * weight of Ci. The larger the value the value of P is, the more influence Ci
 * has on the file heat.
 */
void obd_heat_decay(struct obd_heat_instance *instance,  u64 time_second,
		    unsigned int weight, unsigned int period_second)
{
	u64 second;

	if (instance->ohi_time_second > time_second) {
		obd_heat_clear(instance, 1);
		return;
	}

	if (instance->ohi_time_second == 0)
		return;

	for (second = instance->ohi_time_second + period_second;
	     second < time_second;
	     second += period_second) {
		instance->ohi_heat = instance->ohi_heat *
				(256 - weight) / 256 +
				instance->ohi_count * weight / 256;
		instance->ohi_count = 0;
		instance->ohi_time_second = second;
	}
}
EXPORT_SYMBOL(obd_heat_decay);

u64 obd_heat_get(struct obd_heat_instance *instance, unsigned int time_second,
		 unsigned int weight, unsigned int period_second)
{
	obd_heat_decay(instance, time_second, weight, period_second);

	if (instance->ohi_count == 0)
		return instance->ohi_heat;

	return instance->ohi_heat * (256 - weight) / 256 +
	       instance->ohi_count * weight / 256;
}
EXPORT_SYMBOL(obd_heat_get);

void obd_heat_add(struct obd_heat_instance *instance,
		  unsigned int time_second,  u64 count,
		  unsigned int weight, unsigned int period_second)
{
	obd_heat_decay(instance, time_second, weight, period_second);
	if (instance->ohi_time_second == 0) {
		instance->ohi_time_second = time_second;
		instance->ohi_heat = 0;
		instance->ohi_count = count;
	} else {
		instance->ohi_count += count;
	}
}
EXPORT_SYMBOL(obd_heat_add);

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Class Driver");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(obdclass_init);
module_exit(obdclass_exit);

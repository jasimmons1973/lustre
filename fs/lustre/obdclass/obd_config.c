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
 *
 * lustre/obdclass/obd_config.c
 *
 * Config API
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/uaccess.h>
#include <linux/string.h>

#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_disk.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <llog_swab.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <obd_class.h>

#include "llog_internal.h"

/*
 * uuid<->export lustre hash operations
 */
/*
 * NOTE: It is impossible to find an export that is in failed
 *       state with this function
 */
static int
uuid_keycmp(struct rhashtable_compare_arg *arg, const void *obj)
{
	const struct obd_uuid *uuid = arg->key;
	const struct obd_export *exp = obj;

	if (obd_uuid_equals(uuid, &exp->exp_client_uuid) &&
	    !exp->exp_failed)
		return 0;
	return -ESRCH;
}

static void
uuid_export_exit(void *vexport, void *data)
{
	struct obd_export *exp = vexport;

	class_export_put(exp);
}

static const struct rhashtable_params uuid_hash_params = {
	.key_len	= sizeof(struct obd_uuid),
	.key_offset	= offsetof(struct obd_export, exp_client_uuid),
	.head_offset	= offsetof(struct obd_export, exp_uuid_hash),
	.obj_cmpfn	= uuid_keycmp,
	.automatic_shrinking = true,
};

int obd_uuid_add(struct obd_device *obd, struct obd_export *export)
{
	int rc;

	rc = rhashtable_lookup_insert_fast(&obd->obd_uuid_hash,
					   &export->exp_uuid_hash,
					   uuid_hash_params);
	if (rc == 0)
		class_export_get(export);
	else if (rc == -EEXIST)
		rc = -EALREADY;
	else
		/* map obscure error codes to -ENOMEM */
		rc = -ENOMEM;
	return rc;
}

void obd_uuid_del(struct obd_device *obd, struct obd_export *export)
{
	int rc;

	rc = rhashtable_remove_fast(&obd->obd_uuid_hash,
				    &export->exp_uuid_hash,
				    uuid_hash_params);

	if (rc == 0)
		class_export_put(export);
}

/*********** string parsing utils *********/

/* returns 0 if we find this key in the buffer, else 1 */
int class_find_param(char *buf, char *key, char **valp)
{
	char *ptr;

	if (!buf)
		return 1;

	ptr = strstr(buf, key);
	if (!ptr)
		return 1;

	if (valp)
		*valp = ptr + strlen(key);

	return 0;
}
EXPORT_SYMBOL(class_find_param);

/* returns 0 if this is the first key in the buffer, else 1.
 * valp points to first char after key.
 */
static int class_match_param(char *buf, const char *key, char **valp)
{
	if (!buf)
		return 1;

	if (memcmp(buf, key, strlen(key)) != 0)
		return 1;

	if (valp)
		*valp = buf + strlen(key);

	return 0;
}

static int parse_nid(char *buf, void *value, int quiet)
{
	struct lnet_nid *nid = value;

	if (libcfs_strnid(nid, buf) == 0)
		return 0;

	if (!quiet)
		LCONSOLE_ERROR_MSG(0x159, "Can't parse NID '%s'\n", buf);
	return -EINVAL;
}

static int parse_net(char *buf, void *value)
{
	u32 *net = value;

	*net = libcfs_str2net(buf);
	CDEBUG(D_INFO, "Net %s\n", libcfs_net2str(*net));
	return 0;
}

enum {
	CLASS_PARSE_NID = 1,
	CLASS_PARSE_NET,
};

/* 0 is good nid,
 * 1 not found
 * < 0 error
 * endh is set to next separator
 */
static int class_parse_value(char *buf, int opc, void *value, char **endh,
			     int quiet)
{
	char *endp;
	char tmp;
	int rc = 0;

	if (!buf)
		return 1;
	while (*buf == ',' || *buf == ':')
		buf++;
	if (*buf == ' ' || *buf == '/' || *buf == '\0')
		return 1;

	/* nid separators or end of nids */
	endp = strpbrk(buf, ",: /");
	if (!endp)
		endp = buf + strlen(buf);

	tmp = *endp;
	*endp = '\0';
	switch (opc) {
	default:
		LBUG();
	case CLASS_PARSE_NID:
		rc = parse_nid(buf, value, quiet);
		break;
	case CLASS_PARSE_NET:
		rc = parse_net(buf, value);
		break;
	}
	*endp = tmp;
	if (rc != 0)
		return rc;
	if (endh)
		*endh = endp;
	return 0;
}

int class_parse_nid(char *buf, struct lnet_nid *nid, char **endh)
{
	return class_parse_value(buf, CLASS_PARSE_NID, (void *)nid, endh, 0);
}
EXPORT_SYMBOL(class_parse_nid);

int class_parse_nid_quiet(char *buf, struct lnet_nid *nid, char **endh)
{
	return class_parse_value(buf, CLASS_PARSE_NID, (void *)nid, endh, 1);
}
EXPORT_SYMBOL(class_parse_nid_quiet);

char *lustre_cfg_string(struct lustre_cfg *lcfg, u32 index)
{
	char *s;

	if (!lcfg->lcfg_buflens[index])
		return NULL;

	s = lustre_cfg_buf(lcfg, index);
	if (!s)
		return NULL;

	/*
	 * make sure it's NULL terminated, even if this kills a char
	 * of data. Try to use the padding first though.
	 */
	if (s[lcfg->lcfg_buflens[index] - 1] != '\0') {
		size_t last = ALIGN(lcfg->lcfg_buflens[index], 8) - 1;
		char lost;

		/* Use the smaller value */
		if (last > lcfg->lcfg_buflens[index])
			last = lcfg->lcfg_buflens[index];

		lost = s[last];
		s[last] = '\0';
		if (lost != '\0') {
			CWARN("Truncated buf %d to '%s' (lost '%c'...)\n",
			      index, s, lost);
		}
	}
	return s;
}
EXPORT_SYMBOL(lustre_cfg_string);

/********************** class fns **********************/

/**
 * Create a new obd device and set the type, name and uuid.  If successful,
 * the new device can be accessed by either name or uuid.
 */
static int class_attach(struct lustre_cfg *lcfg)
{
	struct obd_device *obd = NULL;
	char *typename, *name, *uuid;
	struct obd_export *exp;
	int rc, len;

	if (!LUSTRE_CFG_BUFLEN(lcfg, 1)) {
		CERROR("No type passed!\n");
		return -EINVAL;
	}
	typename = lustre_cfg_string(lcfg, 1);

	if (!LUSTRE_CFG_BUFLEN(lcfg, 0)) {
		CERROR("No name passed!\n");
		return -EINVAL;
	}
	name = lustre_cfg_string(lcfg, 0);

	if (!LUSTRE_CFG_BUFLEN(lcfg, 2)) {
		CERROR("No UUID passed!\n");
		return -EINVAL;
	}

	uuid = lustre_cfg_string(lcfg, 2);
	len = strlen(uuid);
	if (len >= sizeof(obd->obd_uuid)) {
		CERROR("uuid must be < %d bytes long\n",
		       (int)sizeof(obd->obd_uuid));
		return -EINVAL;
	}

	obd = class_newdev(typename, name, uuid);
	if (IS_ERR(obd)) {
		/* Already exists or out of obds */
		rc = PTR_ERR(obd);
		CERROR("Cannot create device %s of type %s : %d\n",
		       name, typename, rc);
		return rc;
	}
	LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC,
		 "obd %p obd_magic %08X != %08X\n",
		 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
	LASSERTF(strncmp(obd->obd_name, name, strlen(name)) == 0,
		 "%p obd_name %s != %s\n", obd, obd->obd_name, name);

	exp = class_new_export_self(obd, &obd->obd_uuid);
	if (IS_ERR(exp)) {
		rc = PTR_ERR(exp);
		class_free_dev(obd);
		return rc;
	}

	obd->obd_self_export = exp;
	class_export_put(exp);

	rc = class_register_device(obd);
	if (rc) {
		class_decref(obd, "newdev", obd);
		return rc;
	}

	obd->obd_attached = 1;
	CDEBUG(D_IOCTL, "OBD: dev %d attached type %s with refcount %d\n",
	       obd->obd_minor, typename, atomic_read(&obd->obd_refcount));

	return 0;
}

/** Create hashes, self-export, and call type-specific setup.
 * Setup is effectively the "start this obd" call.
 */
static int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	int err = 0;

	LASSERT(obd);
	LASSERTF(obd == class_num2obd(obd->obd_minor),
		 "obd %p != obd_devs[%d] %p\n",
		 obd, obd->obd_minor, class_num2obd(obd->obd_minor));
	LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC,
		 "obd %p obd_magic %08x != %08x\n",
		 obd, obd->obd_magic, OBD_DEVICE_MAGIC);

	/* have we attached a type to this device? */
	if (!obd->obd_attached) {
		CERROR("Device %d not attached\n", obd->obd_minor);
		return -ENODEV;
	}

	if (obd->obd_set_up) {
		CERROR("Device %d already setup (type %s)\n",
		       obd->obd_minor, obd->obd_type->typ_name);
		return -EEXIST;
	}

	/* is someone else setting us up right now? (attach inits spinlock) */
	spin_lock(&obd->obd_dev_lock);
	if (obd->obd_starting) {
		spin_unlock(&obd->obd_dev_lock);
		CERROR("Device %d setup in progress (type %s)\n",
		       obd->obd_minor, obd->obd_type->typ_name);
		return -EEXIST;
	}
	/* just leave this on forever.  I can't use obd_set_up here because
	 * other fns check that status, and we're not actually set up yet.
	 */
	obd->obd_starting = 1;
	spin_unlock(&obd->obd_dev_lock);

	/* create an uuid-export lustre hash */
	err = rhashtable_init(&obd->obd_uuid_hash, &uuid_hash_params);
	if (err)
		goto err_hash;

	err = obd_setup(obd, lcfg);
	if (err)
		goto err_setup;

	obd->obd_set_up = 1;

	spin_lock(&obd->obd_dev_lock);
	/* cleanup drops this */
	class_incref(obd, "setup", obd);
	spin_unlock(&obd->obd_dev_lock);

	CDEBUG(D_IOCTL, "finished setup of obd %s (uuid %s)\n",
	       obd->obd_name, obd->obd_uuid.uuid);

	return 0;
err_setup:
	rhashtable_destroy(&obd->obd_uuid_hash);
err_hash:
	obd->obd_starting = 0;
	CERROR("setup %s failed (%d)\n", obd->obd_name, err);
	return err;
}

/** We have finished using this obd and are ready to destroy it.
 * There can be no more references to this obd.
 */
static int class_detach(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	if (obd->obd_set_up) {
		CERROR("OBD device %d still set up\n", obd->obd_minor);
		return -EBUSY;
	}

	spin_lock(&obd->obd_dev_lock);
	if (!obd->obd_attached) {
		spin_unlock(&obd->obd_dev_lock);
		CERROR("OBD device %d not attached\n", obd->obd_minor);
		return -ENODEV;
	}
	obd->obd_attached = 0;
	spin_unlock(&obd->obd_dev_lock);

	/* cleanup in progress. we don't like to find this device after now */
	class_unregister_device(obd);

	CDEBUG(D_IOCTL, "detach on obd %s (uuid %s)\n",
	       obd->obd_name, obd->obd_uuid.uuid);

	class_decref(obd, "newdev", obd);
	return 0;
}

/** Start shutting down the obd.  There may be in-progress ops when
 * this is called.  We tell them to start shutting down with a call
 * to class_disconnect_exports().
 */
static int class_cleanup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	int err = 0;
	char *flag;

	CFS_RACE(OBD_FAIL_LDLM_RECOV_CLIENTS);

	if (!obd->obd_set_up) {
		CERROR("Device %d not setup\n", obd->obd_minor);
		return -ENODEV;
	}

	spin_lock(&obd->obd_dev_lock);
	if (obd->obd_stopping) {
		spin_unlock(&obd->obd_dev_lock);
		CERROR("OBD %d already stopping\n", obd->obd_minor);
		return -ENODEV;
	}
	/* Leave this on forever */
	obd->obd_stopping = 1;
	spin_unlock(&obd->obd_dev_lock);

	while (obd->obd_conn_inprogress > 0)
		cond_resched();
	smp_rmb();

	if (lcfg->lcfg_bufcount >= 2 && LUSTRE_CFG_BUFLEN(lcfg, 1) > 0) {
		for (flag = lustre_cfg_string(lcfg, 1); *flag != 0; flag++)
			switch (*flag) {
			case 'F':
				obd->obd_force = 1;
				break;
			case 'A':
				LCONSOLE(D_WARNING, "Failing over %s\n",
					 obd->obd_name);
				spin_lock(&obd->obd_dev_lock);
				obd->obd_fail = 1;
				obd->obd_no_recov = 1;
				spin_unlock(&obd->obd_dev_lock);
				if (OBP(obd, iocontrol)) {
					obd_iocontrol(OBD_IOC_SYNC,
						      obd->obd_self_export,
						      0, NULL, NULL);
				}
				break;
			default:
				CERROR("Unrecognised flag '%c'\n", *flag);
			}
	}

	LASSERT(obd->obd_self_export);

	/* Precleanup, we must make sure all exports get destroyed. */
	err = obd_precleanup(obd);
	if (err)
		CERROR("Precleanup %s returned %d\n",
		       obd->obd_name, err);

	/* destroy an uuid-export hash body */
	rhashtable_free_and_destroy(&obd->obd_uuid_hash, uuid_export_exit,
				    NULL);

	class_decref(obd, "setup", obd);
	obd->obd_set_up = 0;

	return 0;
}

struct obd_device *class_incref(struct obd_device *obd,
				const char *scope, const void *source)
{
	lu_ref_add_atomic(&obd->obd_reference, scope, source);
	atomic_inc(&obd->obd_refcount);
	CDEBUG(D_INFO, "incref %s (%p) now %d - %s\n", obd->obd_name, obd,
	       atomic_read(&obd->obd_refcount), scope);

	return obd;
}
EXPORT_SYMBOL(class_incref);

void class_decref(struct obd_device *obd, const char *scope, const void *source)
{
	int last;

	CDEBUG(D_INFO, "Decref %s (%p) now %d - %s\n", obd->obd_name, obd,
	       atomic_read(&obd->obd_refcount), scope);

	LASSERT(obd->obd_num_exports >= 0);
	last = atomic_dec_and_test(&obd->obd_refcount);
	lu_ref_del(&obd->obd_reference, scope, source);

	if (last) {
		struct obd_export *exp;

		LASSERT(!obd->obd_attached);
		/* All exports have been destroyed; there should
		 * be no more in-progress ops by this point.
		 */
		exp = obd->obd_self_export;
		if (exp) {
			exp->exp_flags |= exp_flags_from_obd(obd);
			class_unlink_export(exp);
		}
	}
}
EXPORT_SYMBOL(class_decref);

/** Add a failover nid location.
 * Client obd types contact server obd types using this nid list.
 */
static int class_add_conn(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct obd_import *imp;
	struct obd_uuid uuid;
	int rc;

	if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
	    LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(struct obd_uuid)) {
		CERROR("invalid conn_uuid\n");
		return -EINVAL;
	}
	if (strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_LWP_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_MGC_NAME)) {
		CERROR("can't add connection on non-client dev\n");
		return -EINVAL;
	}

	imp = obd->u.cli.cl_import;
	if (!imp) {
		CERROR("try to add conn on immature client dev\n");
		return -EINVAL;
	}

	obd_str2uuid(&uuid, lustre_cfg_string(lcfg, 1));
	rc = obd_add_conn(imp, &uuid, lcfg->lcfg_num);

	return rc;
}

/** Remove a failover nid location.
 */
static int class_del_conn(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct obd_import *imp;
	struct obd_uuid uuid;
	int rc;

	if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
	    LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(struct obd_uuid)) {
		CERROR("invalid conn_uuid\n");
		return -EINVAL;
	}
	if (strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME)) {
		CERROR("can't del connection on non-client dev\n");
		return -EINVAL;
	}

	imp = obd->u.cli.cl_import;
	if (!imp) {
		CERROR("try to del conn on immature client dev\n");
		return -EINVAL;
	}

	obd_str2uuid(&uuid, lustre_cfg_string(lcfg, 1));
	rc = obd_del_conn(imp, &uuid);

	return rc;
}

static LIST_HEAD(lustre_profile_list);
static DEFINE_SPINLOCK(lustre_profile_list_lock);

static struct lustre_profile *class_get_profile_nolock(const char *prof)
{
	struct lustre_profile *lprof;

	list_for_each_entry(lprof, &lustre_profile_list, lp_list) {
		if (strcmp(lprof->lp_profile, prof) == 0) {
			lprof->lp_refs++;
			return lprof;
		}
	}
	return NULL;
}

struct lustre_profile *class_get_profile(const char *prof)
{
	struct lustre_profile *lprof;

	spin_lock(&lustre_profile_list_lock);
	lprof = class_get_profile_nolock(prof);
	spin_unlock(&lustre_profile_list_lock);
	return lprof;
}
EXPORT_SYMBOL(class_get_profile);

/** Create a named "profile".
 * This defines the mdc and osc names to use for a client.
 * This also is used to define the lov to be used by a mdt.
 */
static int class_add_profile(int proflen, char *prof, int osclen, char *osc,
			     int mdclen, char *mdc)
{
	struct lustre_profile *lprof;
	int err = 0;

	CDEBUG(D_CONFIG, "Add profile %s\n", prof);

	lprof = kzalloc(sizeof(*lprof), GFP_NOFS);
	if (!lprof)
		return -ENOMEM;
	INIT_LIST_HEAD(&lprof->lp_list);

	LASSERT(proflen == (strlen(prof) + 1));
	lprof->lp_profile = kmemdup(prof, proflen, GFP_NOFS);
	if (!lprof->lp_profile) {
		err = -ENOMEM;
		goto free_lprof;
	}

	LASSERT(osclen == (strlen(osc) + 1));
	lprof->lp_dt = kmemdup(osc, osclen, GFP_NOFS);
	if (!lprof->lp_dt) {
		err = -ENOMEM;
		goto free_lp_profile;
	}

	if (mdclen > 0) {
		LASSERT(mdclen == (strlen(mdc) + 1));
		lprof->lp_md = kmemdup(mdc, mdclen, GFP_NOFS);
		if (!lprof->lp_md) {
			err = -ENOMEM;
			goto free_lp_dt;
		}
	}

	spin_lock(&lustre_profile_list_lock);
	lprof->lp_refs = 1;
	lprof->lp_list_deleted = false;
	list_add(&lprof->lp_list, &lustre_profile_list);
	spin_unlock(&lustre_profile_list_lock);
	return err;

free_lp_dt:
	kfree(lprof->lp_dt);
free_lp_profile:
	kfree(lprof->lp_profile);
free_lprof:
	kfree(lprof);
	return err;
}

void class_del_profile(const char *prof)
{
	struct lustre_profile *lprof;

	CDEBUG(D_CONFIG, "Del profile %s\n", prof);

	spin_lock(&lustre_profile_list_lock);
	lprof = class_get_profile_nolock(prof);
	if (lprof) {
		/* because get profile increments the ref counter */
		lprof->lp_refs--;
		list_del(&lprof->lp_list);
		lprof->lp_list_deleted = true;
		spin_unlock(&lustre_profile_list_lock);

		class_put_profile(lprof);
	} else {
		spin_unlock(&lustre_profile_list_lock);
	}
}
EXPORT_SYMBOL(class_del_profile);

void class_put_profile(struct lustre_profile *lprof)
{
	spin_lock(&lustre_profile_list_lock);
	if (--lprof->lp_refs > 0) {
		LASSERT(lprof->lp_refs > 0);
		spin_unlock(&lustre_profile_list_lock);
		return;
	}
	spin_unlock(&lustre_profile_list_lock);

	/* confirm not a negative number */
	LASSERT(!lprof->lp_refs);

	/*
	 * At least one class_del_profile/profiles must be called
	 * on the target profile or lustre_profile_list will corrupt
	 */
	LASSERT(lprof->lp_list_deleted);
	kfree(lprof->lp_profile);
	kfree(lprof->lp_dt);
	kfree(lprof->lp_md);
	kfree(lprof);
}
EXPORT_SYMBOL(class_put_profile);

/* COMPAT_146 */
void class_del_profiles(void)
{
	struct lustre_profile *lprof, *n;

	spin_lock(&lustre_profile_list_lock);
	list_for_each_entry_safe(lprof, n, &lustre_profile_list, lp_list) {
		list_del(&lprof->lp_list);
		lprof->lp_list_deleted = true;
		spin_unlock(&lustre_profile_list_lock);

		class_put_profile(lprof);

		spin_lock(&lustre_profile_list_lock);
	}
	spin_unlock(&lustre_profile_list_lock);
}
EXPORT_SYMBOL(class_del_profiles);

static int process_param2_config(struct lustre_cfg *lcfg)
{
	char *param = lustre_cfg_string(lcfg, 1);
	struct kobject *kobj = NULL;
	const char *subsys = param;
	char *envp[4];
	char *value;
	size_t len;
	int rc;
	int i;

	print_lustre_cfg(lcfg);

	len = strcspn(param, ".=");
	if (!len)
		return -EINVAL;

	/* If we find '=' then its the top level sysfs directory */
	if (param[len] == '=')
		return class_set_global(param);

	subsys = kstrndup(param, len, GFP_KERNEL);
	if (!subsys)
		return -ENOMEM;

	kobj = kset_find_obj(lustre_kset, subsys);
	kfree(subsys);
	if (!kobj)
		return -ENODEV;

	value = param;
	param = strsep(&value, "=");
	envp[0] = kasprintf(GFP_KERNEL, "PARAM=%s", param);
	envp[1] = kasprintf(GFP_KERNEL, "SETTING=%s", value);
	envp[2] = kasprintf(GFP_KERNEL, "TIME=%lld",
			    ktime_get_real_seconds());
	envp[3] = NULL;

	rc = kobject_uevent_env(kobj, KOBJ_CHANGE, envp);
	for (i = 0; i < ARRAY_SIZE(envp); i++)
		kfree(envp[i]);

	kobject_put(kobj);

	return rc;
}

/** Process configuration commands given in lustre_cfg form.
 * These may come from direct calls (e.g. class_manual_cleanup)
 * or processing the config llog, or ioctl from lctl.
 */
int class_process_config(struct lustre_cfg *lcfg)
{
	struct obd_device *obd;
	struct lnet_nid nid;
	int err;

	LASSERT(lcfg && !IS_ERR(lcfg));
	CDEBUG(D_IOCTL, "processing cmd: %x\n", lcfg->lcfg_command);

	/* Commands that don't need a device */
	switch (lcfg->lcfg_command) {
	case LCFG_ATTACH: {
		err = class_attach(lcfg);
		goto out;
	}
	case LCFG_ADD_UUID: {
		CDEBUG(D_IOCTL,
		       "adding mapping from uuid %s to nid %#llx (%s)\n",
		       lustre_cfg_string(lcfg, 1), lcfg->lcfg_nid,
		       libcfs_nid2str(lcfg->lcfg_nid));

		lnet_nid4_to_nid(lcfg->lcfg_nid, &nid);
		err = class_add_uuid(lustre_cfg_string(lcfg, 1), &nid);
		goto out;
	}
	case LCFG_DEL_UUID: {
		CDEBUG(D_IOCTL, "removing mappings for uuid %s\n",
		       (lcfg->lcfg_bufcount < 2 || LUSTRE_CFG_BUFLEN(lcfg, 1) == 0)
		       ? "<all uuids>" : lustre_cfg_string(lcfg, 1));

		err = class_del_uuid(lustre_cfg_string(lcfg, 1));
		goto out;
	}
	case LCFG_MOUNTOPT: {
		CDEBUG(D_IOCTL, "mountopt: profile %s osc %s mdc %s\n",
		       lustre_cfg_string(lcfg, 1),
		       lustre_cfg_string(lcfg, 2),
		       lustre_cfg_string(lcfg, 3));
		/* set these mount options somewhere, so ll_fill_super
		 * can find them.
		 */
		err = class_add_profile(LUSTRE_CFG_BUFLEN(lcfg, 1),
					lustre_cfg_string(lcfg, 1),
					LUSTRE_CFG_BUFLEN(lcfg, 2),
					lustre_cfg_string(lcfg, 2),
					LUSTRE_CFG_BUFLEN(lcfg, 3),
					lustre_cfg_string(lcfg, 3));
		goto out;
	}
	case LCFG_DEL_MOUNTOPT: {
		CDEBUG(D_IOCTL, "mountopt: profile %s\n",
		       lustre_cfg_string(lcfg, 1));
		class_del_profile(lustre_cfg_string(lcfg, 1));
		err = 0;
		goto out;
	}
	case LCFG_SET_TIMEOUT: {
		CDEBUG(D_IOCTL, "changing lustre timeout from %d to %d\n",
		       obd_timeout, lcfg->lcfg_num);
		obd_timeout = max(lcfg->lcfg_num, 1U);
		ping_interval = max(obd_timeout / 4, 1U);
		obd_timeout_set = 1;
		err = 0;
		goto out;
	}
	case LCFG_SET_LDLM_TIMEOUT: {
		/* ldlm_timeout is not used on the client */
		err = 0;
		goto out;
	}
	case LCFG_SET_UPCALL: {
		LCONSOLE_ERROR_MSG(0x15a, "recovery upcall is deprecated\n");
		/* COMPAT_146 Don't fail on old configs */
		err = 0;
		goto out;
	}
	case LCFG_MARKER: {
		struct cfg_marker *marker;

		marker = lustre_cfg_buf(lcfg, 1);
		CDEBUG(D_IOCTL, "marker %d (%#x) %.16s %s\n", marker->cm_step,
		       marker->cm_flags, marker->cm_tgtname,
		       marker->cm_comment);
		err = 0;
		goto out;
	}
	case LCFG_PARAM: {
		char *tmp;

		/* llite has no obd */
		if (class_match_param(lustre_cfg_string(lcfg, 1),
				      PARAM_LLITE, NULL) == 0) {
			struct lustre_sb_info *lsi;
			unsigned long addr;
			ssize_t count;

			/* The instance name contains the sb:
			 * lustre-client-aacfe000
			 */
			tmp = strrchr(lustre_cfg_string(lcfg, 0), '-');
			if (!tmp || !*(++tmp)) {
				err = -EINVAL;
				goto out;
			}

			if (sscanf(tmp, "%lx", &addr) != 1) {
				err = -EINVAL;
				goto out;
			}

			lsi = s2lsi((struct super_block *)addr);
			/* This better be a real Lustre superblock! */
			LASSERT(lsi->lsi_lmd->lmd_magic == LMD_MAGIC);

			count = class_modify_config(lcfg, PARAM_LLITE,
						    lsi->lsi_kobj);
			err = count < 0 ? count : 0;
			goto out;
		} else if ((class_match_param(lustre_cfg_string(lcfg, 1),
					      PARAM_SYS, &tmp) == 0)) {
			/* Global param settings */
			err = class_set_global(tmp);
			/*
			 * Client or server should not fail to mount if
			 * it hits an unknown configuration parameter.
			 */
			if (err < 0)
				CWARN("Ignoring unknown param %s\n", tmp);

			err = 0;
			goto out;
		}

		break;
	}
	case LCFG_SET_PARAM: {
		err = process_param2_config(lcfg);
		goto out;
	}
	}
	/* Commands that require a device */
	obd = class_name2obd(lustre_cfg_string(lcfg, 0));
	if (!obd) {
		if (!LUSTRE_CFG_BUFLEN(lcfg, 0))
			CERROR("this lcfg command requires a device name\n");
		else
			CERROR("no device for: %s\n",
			       lustre_cfg_string(lcfg, 0));

		err = -EINVAL;
		goto out;
	}
	switch (lcfg->lcfg_command) {
	case LCFG_SETUP: {
		err = class_setup(obd, lcfg);
		goto out;
	}
	case LCFG_DETACH: {
		err = class_detach(obd, lcfg);
		err = 0;
		goto out;
	}
	case LCFG_CLEANUP: {
		err = class_cleanup(obd, lcfg);
		err = 0;
		goto out;
	}
	case LCFG_ADD_CONN: {
		err = class_add_conn(obd, lcfg);
		err = 0;
		goto out;
	}
	case LCFG_DEL_CONN: {
		err = class_del_conn(obd, lcfg);
		err = 0;
		goto out;
	}
	case LCFG_POOL_NEW: {
		err = obd_pool_new(obd, lustre_cfg_string(lcfg, 2));
		err = 0;
		goto out;
	}
	case LCFG_POOL_ADD: {
		err = obd_pool_add(obd, lustre_cfg_string(lcfg, 2),
				   lustre_cfg_string(lcfg, 3));
		err = 0;
		goto out;
	}
	case LCFG_POOL_REM: {
		err = obd_pool_rem(obd, lustre_cfg_string(lcfg, 2),
				   lustre_cfg_string(lcfg, 3));
		err = 0;
		goto out;
	}
	case LCFG_POOL_DEL: {
		err = obd_pool_del(obd, lustre_cfg_string(lcfg, 2));
		err = 0;
		goto out;
	}
	/* Process config log ADD_MDC record twice to add MDC also to LOV
	 * for Data-on-MDT:
	 *
	 * add 0:lustre-clilmv 1:lustre-MDT0000_UUID 2:0 3:1
	 *     4:lustre-MDT0000-mdc_UUID
	 */
	case LCFG_ADD_MDC: {
		struct obd_device *lov_obd;
		char *clilmv;

		err = obd_process_config(obd, sizeof(*lcfg), lcfg);
		if (err)
			goto out;

		/* make sure this is client LMV log entry */
		clilmv = strstr(lustre_cfg_string(lcfg, 0), "clilmv");
		if (!clilmv)
			goto out;

		/* replace 'lmv' with 'lov' name to address LOV device and
		 * process llog record to add MDC there.
		 */
		clilmv[4] = 'o';
		lov_obd = class_name2obd(lustre_cfg_string(lcfg, 0));
		if (!lov_obd) {
			err = -ENOENT;
			CERROR("%s: Cannot find LOV by %s name, rc = %d\n",
			       obd->obd_name, lustre_cfg_string(lcfg, 0), err);
		} else {
			err = obd_process_config(lov_obd, sizeof(*lcfg), lcfg);
		}
		/* restore 'lmv' name */
		clilmv[4] = 'm';
		goto out;
	}
	default: {
		err = obd_process_config(obd, sizeof(*lcfg), lcfg);
		goto out;
	}
	}
out:
	if ((err < 0) && !(lcfg->lcfg_command & LCFG_REQUIRED)) {
		CWARN("Ignoring error %d on optional command %#x\n", err,
		      lcfg->lcfg_command);
		err = 0;
	}
	return err;
}
EXPORT_SYMBOL(class_process_config);

ssize_t class_modify_config(struct lustre_cfg *lcfg, const char *prefix,
			    struct kobject *kobj)
{
	struct kobj_type *typ;
	ssize_t count = 0;
	int i;

	if (lcfg->lcfg_command != LCFG_PARAM) {
		CERROR("Unknown command: %d\n", lcfg->lcfg_command);
		return -EINVAL;
	}

	typ = get_ktype(kobj);
	if (!typ || !typ->default_groups)
		return -ENODEV;

	print_lustre_cfg(lcfg);

	/*
	 * e.g. tunefs.lustre --param mdt.group_upcall=foo /r/tmp/lustre-mdt
	 * or   lctl conf_param lustre-MDT0000.mdt.group_upcall=bar
	 * or   lctl conf_param lustre-OST0000.osc.max_dirty_mb=36
	 */
	for (i = 1; i < lcfg->lcfg_bufcount; i++) {
		struct attribute *attr = NULL;
		size_t keylen;
		char *value;
		char *key;

		key = lustre_cfg_buf(lcfg, i);
		/* Strip off prefix */
		if (class_match_param(key, prefix, &key))
			/* If the prefix doesn't match, return error so we
			 * can pass it down the stack
			 */
			return -EINVAL;

		value = strchr(key, '=');
		if (!value || *(value + 1) == 0) {
			CERROR("%s: can't parse param '%s' (missing '=')\n",
			       lustre_cfg_string(lcfg, 0),
			       lustre_cfg_string(lcfg, i));
			/* continue parsing other params */
			continue;
		}
		keylen = value - key;
		value++;

		attr = get_attr_starts_with(typ, key, keylen);
		if (!attr) {
			char *envp[4], *param, *path;

			path = kobject_get_path(kobj, GFP_KERNEL);
			if (!path)
				return -EINVAL;

			/* convert sysfs path to uevent format */
			param = path;
			while ((param = strchr(param, '/')) != NULL)
				*param = '.';

			param = strstr(path, "fs.lustre.") + 10;

			envp[0] = kasprintf(GFP_KERNEL, "PARAM=%s.%.*s",
					    param, (int)keylen, key);
			envp[1] = kasprintf(GFP_KERNEL, "SETTING=%s", value);
			envp[2] = kasprintf(GFP_KERNEL, "TIME=%lld",
					    ktime_get_real_seconds());
			envp[3] = NULL;

			if (kobject_uevent_env(kobj, KOBJ_CHANGE, envp)) {
				CERROR("%s: failed to send uevent %s\n",
				       kobject_name(kobj), key);
			}

			for (i = 0; i < ARRAY_SIZE(envp); i++)
				kfree(envp[i]);
			kfree(path);
		} else {
			count += lustre_attr_store(kobj, attr, value,
						   strlen(value));
		}
	}
	return count;
}
EXPORT_SYMBOL(class_modify_config);

/** Parse a configuration llog, doing various manipulations on them
 * for various reasons, (modifications for compatibility, skip obsolete
 * records, change uuids, etc), then class_process_config() resulting
 * net records.
 */
int class_config_llog_handler(const struct lu_env *env,
			      struct llog_handle *handle,
			      struct llog_rec_hdr *rec, void *data)
{
	struct config_llog_instance *clli = data;
	int cfg_len = rec->lrh_len;
	char *cfg_buf = (char *)(rec + 1);
	int rc = 0;

	switch (rec->lrh_type) {
	case OBD_CFG_REC: {
		struct lustre_cfg *lcfg, *lcfg_new;
		struct lustre_cfg_bufs bufs;
		char *inst_name = NULL;
		int inst_len = 0;
		size_t lcfg_len;
		int swab = 0;

		lcfg = (struct lustre_cfg *)cfg_buf;
		if (lcfg->lcfg_version == __swab32(LUSTRE_CFG_VERSION)) {
			lustre_swab_lustre_cfg(lcfg);
			swab = 1;
		}

		rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
		if (rc)
			goto out;

		/* Figure out config state info */
		if (lcfg->lcfg_command == LCFG_MARKER) {
			struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);

			lustre_swab_cfg_marker(marker, swab,
					       LUSTRE_CFG_BUFLEN(lcfg, 1));
			CDEBUG(D_CONFIG, "Marker, inst_flg=%#x mark_flg=%#x\n",
			       clli->cfg_flags, marker->cm_flags);
			if (marker->cm_flags & CM_START) {
				/* all previous flags off */
				clli->cfg_flags = CFG_F_MARKER;
				if (marker->cm_flags & CM_SKIP) {
					clli->cfg_flags |= CFG_F_SKIP;
					CDEBUG(D_CONFIG, "SKIP #%d\n",
					       marker->cm_step);
				} else if ((marker->cm_flags & CM_EXCLUDE) ||
					   (clli->cfg_sb &&
					    lustre_check_exclusion(clli->cfg_sb,
							 marker->cm_tgtname))) {
					clli->cfg_flags |= CFG_F_EXCLUDE;
					CDEBUG(D_CONFIG, "EXCLUDE %d\n",
					       marker->cm_step);
				}
			} else if (marker->cm_flags & CM_END) {
				clli->cfg_flags = 0;
			}
		}
		/* A config command without a start marker before it is
		 * illegal (post 146)
		 */
		if (!(clli->cfg_flags & CFG_F_COMPAT146) &&
		    !(clli->cfg_flags & CFG_F_MARKER) &&
		    (lcfg->lcfg_command != LCFG_MARKER)) {
			CWARN("Config not inside markers, ignoring! (inst: %p, uuid: %s, flags: %#x)\n",
			      clli->cfg_instance,
			      clli->cfg_uuid.uuid, clli->cfg_flags);
			clli->cfg_flags |= CFG_F_SKIP;
		}
		if (clli->cfg_flags & CFG_F_SKIP) {
			CDEBUG(D_CONFIG, "skipping %#x\n",
			       clli->cfg_flags);
			rc = 0;
			/* No processing! */
			goto out_inst;
		}

		/*
		 * For interoperability between 1.8 and 2.0,
		 * rename "mds" obd device type to "mdt".
		 */
		{
			char *typename = lustre_cfg_string(lcfg, 1);
			char *index = lustre_cfg_string(lcfg, 2);

			if ((lcfg->lcfg_command == LCFG_ATTACH && typename &&
			     strcmp(typename, "mds") == 0)) {
				CWARN("For 1.8 interoperability, rename obd type from mds to mdt\n");
				typename[2] = 't';
			}
			if ((lcfg->lcfg_command == LCFG_SETUP && index &&
			     strcmp(index, "type") == 0)) {
				CDEBUG(D_INFO, "For 1.8 interoperability, set this index to '0'\n");
				index[0] = '0';
				index[1] = 0;
			}
		}

		if (clli->cfg_flags & CFG_F_EXCLUDE) {
			CDEBUG(D_CONFIG, "cmd: %x marked EXCLUDED\n",
			       lcfg->lcfg_command);
			if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD)
				/* Add inactive instead */
				lcfg->lcfg_command = LCFG_LOV_ADD_INA;
		}

		lustre_cfg_bufs_reset(&bufs, NULL);
		lustre_cfg_bufs_init(&bufs, lcfg);

		if (clli && clli->cfg_instance &&
		    lcfg->lcfg_command != LCFG_SPTLRPC_CONF &&
		    LUSTRE_CFG_BUFLEN(lcfg, 0) > 0) {
			inst_len = LUSTRE_CFG_BUFLEN(lcfg, 0) +
				   LUSTRE_MAXINSTANCE + 4;
			inst_name = kasprintf(GFP_NOFS, "%s-%px",
					      lustre_cfg_string(lcfg, 0),
					      clli->cfg_instance);
			if (!inst_name) {
				rc = -ENOMEM;
				goto out;
			}
			lustre_cfg_bufs_set_string(&bufs, 0, inst_name);
			CDEBUG(D_CONFIG, "cmd %x, instance name: %s\n",
			       lcfg->lcfg_command, inst_name);
		}

		/* we override the llog's uuid for clients, to insure they
		 * are unique
		 */
		if (clli && clli->cfg_instance &&
		    lcfg->lcfg_command == LCFG_ATTACH) {
			lustre_cfg_bufs_set_string(&bufs, 2,
						   clli->cfg_uuid.uuid);
		}
		/*
		 * sptlrpc config record, we expect 2 data segments:
		 *  [0]: fs_name/target_name,
		 *  [1]: rule string
		 * moving them to index [1] and [2], and insert MGC's
		 * obdname at index [0].
		 */
		if (clli && !clli->cfg_instance &&
		    lcfg->lcfg_command == LCFG_SPTLRPC_CONF) {
			struct obd_device *obd = clli->cfg_instance;

			lustre_cfg_bufs_set(&bufs, 2, bufs.lcfg_buf[1],
					    bufs.lcfg_buflen[1]);
			lustre_cfg_bufs_set(&bufs, 1, bufs.lcfg_buf[0],
					    bufs.lcfg_buflen[0]);
			lustre_cfg_bufs_set_string(&bufs, 0,
						   obd->obd_name);
		}

		/* Add net info to setup command
		 * if given on command line.
		 * So config log will be:
		 * [0]: client name
		 * [1]: client UUID
		 * [2]: server UUID
		 * [3]: inactive-on-startup
		 * [4]: restrictive net
		 */
		if (clli && clli->cfg_sb && s2lsi(clli->cfg_sb)) {
			struct lustre_sb_info *lsi = s2lsi(clli->cfg_sb);
			char *nidnet = lsi->lsi_lmd->lmd_nidnet;

			if (lcfg->lcfg_command == LCFG_SETUP &&
			    lcfg->lcfg_bufcount != 2 && nidnet) {
				CDEBUG(D_CONFIG,
				       "Adding net %s info to setup command for client %s\n",
				       nidnet, lustre_cfg_string(lcfg, 0));
				lustre_cfg_bufs_set_string(&bufs, 4, nidnet);
			}
		}

		lcfg_len = lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen);
		lcfg_new = kzalloc(lcfg_len, GFP_NOFS);
		if (!lcfg_new) {
			rc = -ENOMEM;
			goto out_inst;
		}

		lustre_cfg_init(lcfg_new, lcfg->lcfg_command, &bufs);
		lcfg_new->lcfg_num = lcfg->lcfg_num;
		lcfg_new->lcfg_flags = lcfg->lcfg_flags;

		/* XXX Hack to try to remain binary compatible with
		 * pre-newconfig logs
		 */
		if (lcfg->lcfg_nal != 0 &&      /* pre-newconfig log? */
		    (lcfg->lcfg_nid >> 32) == 0) {
			u32 addr = (u32)(lcfg->lcfg_nid & 0xffffffff);

			lcfg_new->lcfg_nid =
				LNET_MKNID(LNET_MKNET(lcfg->lcfg_nal, 0), addr);
			CWARN("Converted pre-newconfig NAL %d NID %x to %s\n",
			      lcfg->lcfg_nal, addr,
			      libcfs_nid2str(lcfg_new->lcfg_nid));
		} else {
			lcfg_new->lcfg_nid = lcfg->lcfg_nid;
		}

		lcfg_new->lcfg_nal = 0; /* illegal value for obsolete field */

		rc = class_process_config(lcfg_new);
		kfree(lcfg_new);
out_inst:
		kfree(inst_name);
		break;
	}
	default:
		CERROR("Unknown llog record type %#x encountered\n",
		       rec->lrh_type);
		break;
	}
out:
	if (rc) {
		CERROR("%s: cfg command failed: rc = %d\n",
		       handle->lgh_ctxt->loc_obd->obd_name, rc);
		class_config_dump_handler(NULL, handle, rec, data);
	}
	return rc;
}
EXPORT_SYMBOL(class_config_llog_handler);

int class_config_parse_llog(const struct lu_env *env, struct llog_ctxt *ctxt,
			    char *name, struct config_llog_instance *cfg)
{
	struct llog_process_cat_data cd = {
		.lpcd_first_idx = 0,
		.lpcd_read_mode = LLOG_READ_MODE_NORMAL,
	};
	struct llog_handle *llh;
	llog_cb_t callback;
	int rc;

	CDEBUG(D_INFO, "looking up llog %s\n", name);
	rc = llog_open(env, ctxt, &llh, NULL, name, LLOG_OPEN_EXISTS);
	if (rc)
		return rc;

	rc = llog_init_handle(env, llh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		goto parse_out;

	/* continue processing from where we last stopped to end-of-log */
	if (cfg) {
		cd.lpcd_first_idx = cfg->cfg_last_idx;
		callback = cfg->cfg_callback;
		LASSERT(callback);
	} else {
		callback = class_config_llog_handler;
	}

	cd.lpcd_last_idx = 0;

	rc = llog_process(env, llh, callback, cfg, &cd);

	CDEBUG(D_CONFIG, "Processed log %s gen %d-%d (rc=%d)\n", name,
	       cd.lpcd_first_idx + 1, cd.lpcd_last_idx, rc);
	if (cfg)
		cfg->cfg_last_idx = cd.lpcd_last_idx;

parse_out:
	llog_close(env, llh);
	return rc;
}
EXPORT_SYMBOL(class_config_parse_llog);

/**
 * parse config record and output dump in supplied buffer.
 * This is separated from class_config_dump_handler() to use
 * for ioctl needs as well
 */
static int class_config_parse_rec(struct llog_rec_hdr *rec, char *buf,
				  int size)
{
	struct lustre_cfg *lcfg = (struct lustre_cfg *)(rec + 1);
	char *ptr = buf;
	char *end = buf + size;
	int rc = 0;

	LASSERT(rec->lrh_type == OBD_CFG_REC);
	rc = lustre_cfg_sanity_check(lcfg, rec->lrh_len);
	if (rc < 0)
		return rc;

	ptr += snprintf(ptr, end - ptr, "cmd=%05x ", lcfg->lcfg_command);
	if (lcfg->lcfg_flags)
		ptr += snprintf(ptr, end - ptr, "flags=%#08x ",
				lcfg->lcfg_flags);

	if (lcfg->lcfg_num)
		ptr += snprintf(ptr, end - ptr, "num=%#08x ", lcfg->lcfg_num);

	if (lcfg->lcfg_nid) {
		char nidstr[LNET_NIDSTR_SIZE];

		libcfs_nid2str_r(lcfg->lcfg_nid, nidstr, sizeof(nidstr));
		ptr += snprintf(ptr, end - ptr, "nid=%s(%#llx)  ",
				nidstr, lcfg->lcfg_nid);
	}

	if (lcfg->lcfg_command == LCFG_MARKER) {
		struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);

		ptr += snprintf(ptr, end - ptr, "marker=%d(%#x)%s '%s'",
				marker->cm_step, marker->cm_flags,
				marker->cm_tgtname, marker->cm_comment);
	} else {
		int i;

		for (i = 0; i <  lcfg->lcfg_bufcount; i++) {
			ptr += snprintf(ptr, end - ptr, "%d:%s  ", i,
					lustre_cfg_string(lcfg, i));
		}
	}
	ptr += snprintf(ptr, end - ptr, "\n");
	/* return consumed bytes */
	rc = ptr - buf;
	return rc;
}

int class_config_dump_handler(const struct lu_env *env,
			      struct llog_handle *handle,
			      struct llog_rec_hdr *rec, void *data)
{
	char *outstr;
	int rc = 0;

	outstr = kzalloc(256, GFP_NOFS);
	if (!outstr)
		return -ENOMEM;

	if (rec->lrh_type == OBD_CFG_REC) {
		class_config_parse_rec(rec, outstr, 256);
		LCONSOLE(D_WARNING, "   %s", outstr);
	} else {
		LCONSOLE(D_WARNING, "unhandled lrh_type: %#x\n", rec->lrh_type);
		rc = -EINVAL;
	}

	kfree(outstr);
	return rc;
}

/** Call class_cleanup and class_detach.
 * "Manual" only in the sense that we're faking lcfg commands.
 */
int class_manual_cleanup(struct obd_device *obd)
{
	char flags[3] = "";
	struct lustre_cfg *lcfg;
	struct lustre_cfg_bufs bufs;
	int rc;

	if (!obd) {
		CERROR("empty cleanup\n");
		return -EALREADY;
	}

	if (obd->obd_force)
		strcat(flags, "F");
	if (obd->obd_fail)
		strcat(flags, "A");

	CDEBUG(D_CONFIG, "Manual cleanup of %s (flags='%s')\n",
	       obd->obd_name, flags);

	lustre_cfg_bufs_reset(&bufs, obd->obd_name);
	lustre_cfg_bufs_set_string(&bufs, 1, flags);
	lcfg = kzalloc(lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen),
			GFP_NOFS);
	if (!lcfg)
		return -ENOMEM;
	lustre_cfg_init(lcfg, LCFG_CLEANUP, &bufs);

	rc = class_process_config(lcfg);
	if (rc) {
		CERROR("cleanup failed %d: %s\n", rc, obd->obd_name);
		goto out;
	}

	/* the lcfg is almost the same for both ops */
	lcfg->lcfg_command = LCFG_DETACH;
	rc = class_process_config(lcfg);
	if (rc)
		CERROR("detach failed %d: %s\n", rc, obd->obd_name);
out:
	kfree(lcfg);
	return rc;
}
EXPORT_SYMBOL(class_manual_cleanup);

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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_SEC

#include <linux/libcfs/libcfs.h>
#include <linux/crypto.h>
#include <linux/key.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_import.h>
#include <lustre_disk.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

enum lustre_sec_part sptlrpc_target_sec_part(struct obd_device *obd)
{
	const char *type = obd->obd_type->typ_name;

	if (!strcmp(type, LUSTRE_MDT_NAME))
		return LUSTRE_SP_MDT;
	if (!strcmp(type, LUSTRE_OST_NAME))
		return LUSTRE_SP_OST;
	if (!strcmp(type, LUSTRE_MGS_NAME))
		return LUSTRE_SP_MGS;

	CERROR("unknown target %p(%s)\n", obd, type);
	return LUSTRE_SP_ANY;
}

/****************************************
 * user supplied flavor string parsing  *
 ****************************************/

/*
 * format: <base_flavor>[-<bulk_type:alg_spec>]
 */
int sptlrpc_parse_flavor(const char *str, struct sptlrpc_flavor *flvr)
{
	char buf[32];
	char *bulk, *alg;

	memset(flvr, 0, sizeof(*flvr));

	if (!str || str[0] == '\0') {
		flvr->sf_rpc = SPTLRPC_FLVR_INVALID;
		return 0;
	}

	strlcpy(buf, str, sizeof(buf));

	bulk = strchr(buf, '-');
	if (bulk)
		*bulk++ = '\0';

	flvr->sf_rpc = sptlrpc_name2flavor_base(buf);
	if (flvr->sf_rpc == SPTLRPC_FLVR_INVALID)
		goto err_out;

	/*
	 * currently only base flavor "plain" can have bulk specification.
	 */
	if (flvr->sf_rpc == SPTLRPC_FLVR_PLAIN) {
		flvr->u_bulk.hash.hash_alg = BULK_HASH_ALG_ADLER32;
		if (bulk) {
			/*
			 * format: plain-hash:<hash_alg>
			 */
			alg = strchr(bulk, ':');
			if (!alg)
				goto err_out;
			*alg++ = '\0';

			if (strcmp(bulk, "hash"))
				goto err_out;

			flvr->u_bulk.hash.hash_alg = sptlrpc_get_hash_alg(alg);
			if (flvr->u_bulk.hash.hash_alg >= BULK_HASH_ALG_MAX)
				goto err_out;
		}

		if (flvr->u_bulk.hash.hash_alg == BULK_HASH_ALG_NULL)
			flvr_set_bulk_svc(&flvr->sf_rpc, SPTLRPC_BULK_SVC_NULL);
		else
			flvr_set_bulk_svc(&flvr->sf_rpc, SPTLRPC_BULK_SVC_INTG);
	} else {
		if (bulk)
			goto err_out;
	}

	flvr->sf_flags = 0;
	return 0;

err_out:
	CERROR("invalid flavor string: %s\n", str);
	return -EINVAL;
}
EXPORT_SYMBOL(sptlrpc_parse_flavor);

/****************************************
 * configure rules		      *
 ****************************************/

static void get_default_flavor(struct sptlrpc_flavor *sf)
{
	memset(sf, 0, sizeof(*sf));

	sf->sf_rpc = SPTLRPC_FLVR_NULL;
	sf->sf_flags = 0;
}

static void sptlrpc_rule_init(struct sptlrpc_rule *rule)
{
	rule->sr_netid = LNET_NET_ANY;
	rule->sr_from = LUSTRE_SP_ANY;
	rule->sr_to = LUSTRE_SP_ANY;
	rule->sr_padding = 0;

	get_default_flavor(&rule->sr_flvr);
}

/*
 * format: network[.direction]=flavor
 */
static int sptlrpc_parse_rule(char *param, struct sptlrpc_rule *rule)
{
	char *flavor, *dir;
	int rc;

	sptlrpc_rule_init(rule);

	flavor = strchr(param, '=');
	if (!flavor) {
		CERROR("invalid param, no '='\n");
		return -EINVAL;
	}
	*flavor++ = '\0';

	dir = strchr(param, '.');
	if (dir)
		*dir++ = '\0';

	/* 1.1 network */
	if (strcmp(param, "default")) {
		rule->sr_netid = libcfs_str2net(param);
		if (rule->sr_netid == LNET_NET_ANY) {
			CERROR("invalid network name: %s\n", param);
			return -EINVAL;
		}
	}

	/* 1.2 direction */
	if (dir) {
		if (!strcmp(dir, "mdt2ost")) {
			rule->sr_from = LUSTRE_SP_MDT;
			rule->sr_to = LUSTRE_SP_OST;
		} else if (!strcmp(dir, "mdt2mdt")) {
			rule->sr_from = LUSTRE_SP_MDT;
			rule->sr_to = LUSTRE_SP_MDT;
		} else if (!strcmp(dir, "cli2ost")) {
			rule->sr_from = LUSTRE_SP_CLI;
			rule->sr_to = LUSTRE_SP_OST;
		} else if (!strcmp(dir, "cli2mdt")) {
			rule->sr_from = LUSTRE_SP_CLI;
			rule->sr_to = LUSTRE_SP_MDT;
		} else {
			CERROR("invalid rule dir segment: %s\n", dir);
			return -EINVAL;
		}
	}

	/* 2.1 flavor */
	rc = sptlrpc_parse_flavor(flavor, &rule->sr_flvr);
	if (rc)
		return -EINVAL;

	return 0;
}

static void sptlrpc_rule_set_free(struct sptlrpc_rule_set *rset)
{
	LASSERT(rset->srs_nslot ||
		(rset->srs_nrule == 0 && !rset->srs_rules));

	if (rset->srs_nslot) {
		kfree(rset->srs_rules);
		sptlrpc_rule_set_init(rset);
	}
}

/*
 * return 0 if the rule set could accommodate one more rule.
 */
static int sptlrpc_rule_set_expand(struct sptlrpc_rule_set *rset)
{
	struct sptlrpc_rule *rules;
	int nslot;

	might_sleep();

	if (rset->srs_nrule < rset->srs_nslot)
		return 0;

	nslot = rset->srs_nslot + 8;

	/* better use realloc() if available */
	rules = kcalloc(nslot, sizeof(*rset->srs_rules), GFP_NOFS);
	if (!rules)
		return -ENOMEM;

	if (rset->srs_nrule) {
		LASSERT(rset->srs_nslot && rset->srs_rules);
		memcpy(rules, rset->srs_rules,
		       rset->srs_nrule * sizeof(*rset->srs_rules));

		kfree(rset->srs_rules);
	}

	rset->srs_rules = rules;
	rset->srs_nslot = nslot;
	return 0;
}

static inline int rule_spec_dir(struct sptlrpc_rule *rule)
{
	return (rule->sr_from != LUSTRE_SP_ANY ||
		rule->sr_to != LUSTRE_SP_ANY);
}

static inline int rule_spec_net(struct sptlrpc_rule *rule)
{
	return (rule->sr_netid != LNET_NET_ANY);
}

static inline int rule_match_dir(struct sptlrpc_rule *r1,
				 struct sptlrpc_rule *r2)
{
	return (r1->sr_from == r2->sr_from && r1->sr_to == r2->sr_to);
}

static inline int rule_match_net(struct sptlrpc_rule *r1,
				 struct sptlrpc_rule *r2)
{
	return (r1->sr_netid == r2->sr_netid);
}

/*
 * merge @rule into @rset.
 * the @rset slots might be expanded.
 */
static int sptlrpc_rule_set_merge(struct sptlrpc_rule_set *rset,
				  struct sptlrpc_rule *rule)
{
	struct sptlrpc_rule *p = rset->srs_rules;
	int spec_dir, spec_net;
	int rc, n, match = 0;

	might_sleep();

	spec_net = rule_spec_net(rule);
	spec_dir = rule_spec_dir(rule);

	for (n = 0; n < rset->srs_nrule; n++) {
		p = &rset->srs_rules[n];

		/* test network match, if failed:
		 * - spec rule: skip rules which is also spec rule match, until
		 *   we hit a wild rule, which means no more chance
		 * - wild rule: skip until reach the one which is also wild
		 *   and matches
		 */
		if (!rule_match_net(p, rule)) {
			if (spec_net) {
				if (rule_spec_net(p))
					continue;
				else
					break;
			} else {
				continue;
			}
		}

		/* test dir match, same logic as net matching */
		if (!rule_match_dir(p, rule)) {
			if (spec_dir) {
				if (rule_spec_dir(p))
					continue;
				else
					break;
			} else {
				continue;
			}
		}

		/* find a match */
		match = 1;
		break;
	}

	if (match) {
		LASSERT(n >= 0 && n < rset->srs_nrule);

		if (rule->sr_flvr.sf_rpc == SPTLRPC_FLVR_INVALID) {
			/* remove this rule */
			if (n < rset->srs_nrule - 1)
				memmove(&rset->srs_rules[n],
					&rset->srs_rules[n + 1],
					(rset->srs_nrule - n - 1) *
					sizeof(*rule));
			rset->srs_nrule--;
		} else {
			/* override the rule */
			memcpy(&rset->srs_rules[n], rule, sizeof(*rule));
		}
	} else {
		LASSERT(n >= 0 && n <= rset->srs_nrule);

		if (rule->sr_flvr.sf_rpc != SPTLRPC_FLVR_INVALID) {
			rc = sptlrpc_rule_set_expand(rset);
			if (rc)
				return rc;

			if (n < rset->srs_nrule)
				memmove(&rset->srs_rules[n + 1],
					&rset->srs_rules[n],
					(rset->srs_nrule - n) * sizeof(*rule));
			memcpy(&rset->srs_rules[n], rule, sizeof(*rule));
			rset->srs_nrule++;
		} else {
			CDEBUG(D_CONFIG, "ignore the unmatched deletion\n");
		}
	}

	return 0;
}

/**
 * given from/to/nid, determine a matching flavor in ruleset.
 * return 1 if a match found, otherwise return 0.
 */
static int sptlrpc_rule_set_choose(struct sptlrpc_rule_set *rset,
				   enum lustre_sec_part from,
				   enum lustre_sec_part to,
				   struct lnet_nid *nid,
				   struct sptlrpc_flavor *sf)
{
	struct sptlrpc_rule *r;
	int n;

	for (n = 0; n < rset->srs_nrule; n++) {
		r = &rset->srs_rules[n];

		if (!LNET_NID_IS_ANY(nid) &&
		    r->sr_netid != LNET_NET_ANY &&
		    __be16_to_cpu(nid->nid_num) != r->sr_netid)
			continue;

		if (from != LUSTRE_SP_ANY && r->sr_from != LUSTRE_SP_ANY &&
		    from != r->sr_from)
			continue;

		if (to != LUSTRE_SP_ANY && r->sr_to != LUSTRE_SP_ANY &&
		    to != r->sr_to)
			continue;

		*sf = r->sr_flvr;
		return 1;
	}

	return 0;
}

/**********************************
 * sptlrpc configuration support  *
 **********************************/

struct sptlrpc_conf_tgt {
	struct list_head		sct_list;
	char				sct_name[MAX_OBD_NAME];
	struct sptlrpc_rule_set		sct_rset;
};

struct sptlrpc_conf {
	struct list_head		sc_list;
	char				sc_fsname[MTI_NAME_MAXLEN];
	/* modified during updating */
	unsigned int			sc_modified;
	unsigned int			sc_updated:1, /* updated copy from
						       * MGS
						       */
					sc_local:1; /* local copy from target */
	/* fs general rules */
	struct sptlrpc_rule_set		sc_rset;
	/* target-specific rules */
	struct list_head		sc_tgts;
};

static struct mutex sptlrpc_conf_lock;
static LIST_HEAD(sptlrpc_confs);

static inline int is_hex(char c)
{
	return ((c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f'));
}

static void target2fsname(const char *tgt, char *fsname, int buflen)
{
	const char *ptr;
	int len;

	ptr = strrchr(tgt, '-');
	if (ptr) {
		if ((strncmp(ptr, "-MDT", 4) != 0 &&
		     strncmp(ptr, "-OST", 4) != 0) ||
		    !is_hex(ptr[4]) || !is_hex(ptr[5]) ||
		    !is_hex(ptr[6]) || !is_hex(ptr[7]))
			ptr = NULL;
	}

	/* if we didn't find the pattern, treat the whole string as fsname */
	if (!ptr)
		len = strlen(tgt);
	else
		len = ptr - tgt;

	len = min(len, buflen - 1);
	memcpy(fsname, tgt, len);
	fsname[len] = '\0';
}

static void sptlrpc_conf_free_rsets(struct sptlrpc_conf *conf)
{
	struct sptlrpc_conf_tgt *conf_tgt, *conf_tgt_next;

	sptlrpc_rule_set_free(&conf->sc_rset);

	list_for_each_entry_safe(conf_tgt, conf_tgt_next,
				 &conf->sc_tgts, sct_list) {
		sptlrpc_rule_set_free(&conf_tgt->sct_rset);
		list_del(&conf_tgt->sct_list);
		kfree(conf_tgt);
	}
	LASSERT(list_empty(&conf->sc_tgts));

	conf->sc_updated = 0;
	conf->sc_local = 0;
}

static void sptlrpc_conf_free(struct sptlrpc_conf *conf)
{
	CDEBUG(D_SEC, "free sptlrpc conf %s\n", conf->sc_fsname);

	sptlrpc_conf_free_rsets(conf);
	list_del(&conf->sc_list);
	kfree(conf);
}

static
struct sptlrpc_conf_tgt *sptlrpc_conf_get_tgt(struct sptlrpc_conf *conf,
					      const char *name,
					      int create)
{
	struct sptlrpc_conf_tgt *conf_tgt;

	list_for_each_entry(conf_tgt, &conf->sc_tgts, sct_list) {
		if (strcmp(conf_tgt->sct_name, name) == 0)
			return conf_tgt;
	}

	if (!create)
		return NULL;

	conf_tgt = kzalloc(sizeof(*conf_tgt), GFP_NOFS);
	if (conf_tgt) {
		strlcpy(conf_tgt->sct_name, name, sizeof(conf_tgt->sct_name));
		sptlrpc_rule_set_init(&conf_tgt->sct_rset);
		list_add(&conf_tgt->sct_list, &conf->sc_tgts);
	}

	return conf_tgt;
}

static
struct sptlrpc_conf *sptlrpc_conf_get(const char *fsname,
				      int create)
{
	struct sptlrpc_conf *conf;
	size_t len;

	list_for_each_entry(conf, &sptlrpc_confs, sc_list) {
		if (strcmp(conf->sc_fsname, fsname) == 0)
			return conf;
	}

	if (!create)
		return NULL;

	conf = kzalloc(sizeof(*conf), GFP_NOFS);
	if (!conf)
		return NULL;

	len = strlcpy(conf->sc_fsname, fsname, sizeof(conf->sc_fsname));
	if (len >= sizeof(conf->sc_fsname)) {
		kfree(conf);
		return NULL;
	}
	sptlrpc_rule_set_init(&conf->sc_rset);
	INIT_LIST_HEAD(&conf->sc_tgts);
	list_add(&conf->sc_list, &sptlrpc_confs);

	CDEBUG(D_SEC, "create sptlrpc conf %s\n", conf->sc_fsname);
	return conf;
}

/**
 * caller must hold conf_lock already.
 */
static int sptlrpc_conf_merge_rule(struct sptlrpc_conf *conf,
				   const char *target,
				   struct sptlrpc_rule *rule)
{
	struct sptlrpc_conf_tgt *conf_tgt;
	struct sptlrpc_rule_set *rule_set;

	/* fsname == target means general rules for the whole fs */
	if (strcmp(conf->sc_fsname, target) == 0) {
		rule_set = &conf->sc_rset;
	} else {
		conf_tgt = sptlrpc_conf_get_tgt(conf, target, 1);
		if (conf_tgt) {
			rule_set = &conf_tgt->sct_rset;
		} else {
			CERROR("out of memory, can't merge rule!\n");
			return -ENOMEM;
		}
	}

	return sptlrpc_rule_set_merge(rule_set, rule);
}

/**
 * process one LCFG_SPTLRPC_CONF record. if @conf is NULL, we
 * find one through the target name in the record inside conf_lock;
 * otherwise means caller already hold conf_lock.
 */
static int __sptlrpc_process_config(char *target, const char *fsname,
				    struct sptlrpc_rule *rule,
				    struct sptlrpc_conf *conf)
{
	int rc;

	if (!conf) {
		if (!fsname)
			return -ENODEV;

		mutex_lock(&sptlrpc_conf_lock);
		conf = sptlrpc_conf_get(fsname, 0);
		if (!conf) {
			CERROR("can't find conf\n");
			rc = -ENOMEM;
		} else {
			rc = sptlrpc_conf_merge_rule(conf, target, rule);
		}
		mutex_unlock(&sptlrpc_conf_lock);
	} else {
		LASSERT(mutex_is_locked(&sptlrpc_conf_lock));
		rc = sptlrpc_conf_merge_rule(conf, target, rule);
	}

	if (!rc)
		conf->sc_modified++;

	return rc;
}

int sptlrpc_process_config(struct lustre_cfg *lcfg)
{
	char fsname[MTI_NAME_MAXLEN];
	struct sptlrpc_rule rule;
	char *target, *param;
	int rc;

	print_lustre_cfg(lcfg);

	target = lustre_cfg_string(lcfg, 1);
	if (!target) {
		CERROR("missing target name\n");
		return -EINVAL;
	}

	param = lustre_cfg_string(lcfg, 2);
	if (!param) {
		CERROR("missing parameter\n");
		return -EINVAL;
	}

	/* parse rule to make sure the format is correct */
	if (strncmp(param, PARAM_SRPC_FLVR,
		    sizeof(PARAM_SRPC_FLVR) - 1) != 0) {
		CERROR("Invalid sptlrpc parameter: %s\n", param);
		return -EINVAL;
	}
	param += sizeof(PARAM_SRPC_FLVR) - 1;

	CDEBUG(D_SEC, "processing rule: %s.%s\n", target, param);

	/*
	 * Three types of targets exist for sptlrpc using conf_param
	 * 1.	'_mgs' which targets mgc srpc settings. Treat it as
	 *	as a special file system name.
	 * 2.	target is a device which can be fsname-MDTXXXX or
	 *	fsname-OSTXXXX. This can be verified by the function
	 *	server_name2fsname.
	 * 3.	If both above conditions are not meet then the target
	 *	is a actual filesystem.
	 */
	if (server_name2fsname(target, fsname, NULL))
		strlcpy(fsname, target, sizeof(fsname));

	rc = sptlrpc_parse_rule(param, &rule);
	if (rc)
		return rc;

	return __sptlrpc_process_config(target, fsname, &rule, NULL);
}
EXPORT_SYMBOL(sptlrpc_process_config);

static int logname2fsname(const char *logname, char *buf, int buflen)
{
	char *ptr;
	int len;

	ptr = strrchr(logname, '-');
	if (!ptr || strcmp(ptr, "-sptlrpc")) {
		CERROR("%s is not a sptlrpc config log\n", logname);
		return -EINVAL;
	}

	len = min((int)(ptr - logname), buflen - 1);

	memcpy(buf, logname, len);
	buf[len] = '\0';
	return 0;
}

void sptlrpc_conf_log_update_begin(const char *logname)
{
	struct sptlrpc_conf *conf;
	char fsname[16];

	if (logname2fsname(logname, fsname, sizeof(fsname)))
		return;

	mutex_lock(&sptlrpc_conf_lock);

	conf = sptlrpc_conf_get(fsname, 0);
	if (conf) {
		if (conf->sc_local) {
			LASSERT(conf->sc_updated == 0);
			sptlrpc_conf_free_rsets(conf);
		}
		conf->sc_modified = 0;
	}

	mutex_unlock(&sptlrpc_conf_lock);
}
EXPORT_SYMBOL(sptlrpc_conf_log_update_begin);

/**
 * mark a config log has been updated
 */
void sptlrpc_conf_log_update_end(const char *logname)
{
	struct sptlrpc_conf *conf;
	char fsname[16];

	if (logname2fsname(logname, fsname, sizeof(fsname)))
		return;

	mutex_lock(&sptlrpc_conf_lock);

	conf = sptlrpc_conf_get(fsname, 0);
	if (conf) {
		/*
		 * if original state is not updated, make sure the
		 * modified counter > 0 to enforce updating local copy.
		 */
		if (conf->sc_updated == 0)
			conf->sc_modified++;

		conf->sc_updated = 1;
	}

	mutex_unlock(&sptlrpc_conf_lock);
}
EXPORT_SYMBOL(sptlrpc_conf_log_update_end);

void sptlrpc_conf_log_start(const char *logname)
{
	char fsname[16];

	if (logname2fsname(logname, fsname, sizeof(fsname)))
		return;

	mutex_lock(&sptlrpc_conf_lock);
	sptlrpc_conf_get(fsname, 1);
	mutex_unlock(&sptlrpc_conf_lock);
}
EXPORT_SYMBOL(sptlrpc_conf_log_start);

void sptlrpc_conf_log_stop(const char *logname)
{
	struct sptlrpc_conf *conf;
	char fsname[16];

	if (logname2fsname(logname, fsname, sizeof(fsname)))
		return;

	mutex_lock(&sptlrpc_conf_lock);
	conf = sptlrpc_conf_get(fsname, 0);
	if (conf)
		sptlrpc_conf_free(conf);
	mutex_unlock(&sptlrpc_conf_lock);
}
EXPORT_SYMBOL(sptlrpc_conf_log_stop);

static inline void flavor_set_flags(struct sptlrpc_flavor *sf,
				    enum lustre_sec_part from,
				    enum lustre_sec_part to,
				    unsigned int fl_udesc)
{
	/*
	 * null flavor doesn't need to set any flavor, and in fact
	 * we'd better not do that because everybody share a single sec.
	 */
	if (sf->sf_rpc == SPTLRPC_FLVR_NULL)
		return;

	if (from == LUSTRE_SP_MDT) {
		/* MDT->MDT; MDT->OST */
		sf->sf_flags |= PTLRPC_SEC_FL_ROOTONLY;
	} else if (from == LUSTRE_SP_CLI && to == LUSTRE_SP_OST) {
		/* CLI->OST */
		sf->sf_flags |= PTLRPC_SEC_FL_ROOTONLY | PTLRPC_SEC_FL_BULK;
	} else if (from == LUSTRE_SP_CLI && to == LUSTRE_SP_MDT) {
		/* CLI->MDT */
		if (fl_udesc && sf->sf_rpc != SPTLRPC_FLVR_NULL)
			sf->sf_flags |= PTLRPC_SEC_FL_UDESC;
	}
}

void sptlrpc_conf_choose_flavor(enum lustre_sec_part from,
				enum lustre_sec_part to,
				struct obd_uuid *target,
				struct lnet_nid *nid,
				struct sptlrpc_flavor *sf)
{
	struct sptlrpc_conf *conf;
	struct sptlrpc_conf_tgt *conf_tgt;
	char name[MTI_NAME_MAXLEN];
	int len, rc = 0;

	target2fsname(target->uuid, name, sizeof(name));

	mutex_lock(&sptlrpc_conf_lock);

	conf = sptlrpc_conf_get(name, 0);
	if (!conf)
		goto out;

	/* convert uuid name (supposed end with _UUID) to target name */
	len = strlen(target->uuid);
	LASSERT(len > 5);
	memcpy(name, target->uuid, len - 5);
	name[len - 5] = '\0';

	conf_tgt = sptlrpc_conf_get_tgt(conf, name, 0);
	if (conf_tgt) {
		rc = sptlrpc_rule_set_choose(&conf_tgt->sct_rset, from, to,
					     nid, sf);
		if (rc)
			goto out;
	}

	rc = sptlrpc_rule_set_choose(&conf->sc_rset, from, to,
				     nid, sf);
out:
	mutex_unlock(&sptlrpc_conf_lock);

	if (rc == 0)
		get_default_flavor(sf);

	flavor_set_flags(sf, from, to, 1);
}

#define SEC_ADAPT_DELAY		(10)

/**
 * called by client devices, notify the sptlrpc config has changed and
 * do import_sec_adapt later.
 */
void sptlrpc_conf_client_adapt(struct obd_device *obd)
{
	struct obd_import *imp;
	int rc;

	LASSERT(strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) == 0);
	CDEBUG(D_SEC, "obd %s\n", obd->u.cli.cl_target_uuid.uuid);

	/* serialize with connect/disconnect import */
	with_imp_locked_nested(obd, imp, rc, OBD_CLI_SEM_MDCOSC) {
		write_lock(&imp->imp_sec_lock);
		if (imp->imp_sec)
			imp->imp_sec_expire = ktime_get_real_seconds() +
				SEC_ADAPT_DELAY;
		write_unlock(&imp->imp_sec_lock);
	}
}
EXPORT_SYMBOL(sptlrpc_conf_client_adapt);

int sptlrpc_conf_init(void)
{
	mutex_init(&sptlrpc_conf_lock);
	return 0;
}

void sptlrpc_conf_fini(void)
{
	struct sptlrpc_conf *conf;

	mutex_lock(&sptlrpc_conf_lock);
	while (!list_empty(&sptlrpc_confs)) {
		conf = list_first_entry(&sptlrpc_confs,
					struct sptlrpc_conf, sc_list);
		sptlrpc_conf_free(conf);
	}
	mutex_unlock(&sptlrpc_conf_lock);
}

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
 * Copyright (c) 2017, DDN Storage Corporation.
 */
/*
 * Persistent Client Cache
 *
 * PCC is a new framework which provides a group of local cache on Lustre
 * client side. It works in two modes: RW-PCC enables a read-write cache on the
 * local SSDs of a single client; RO-PCC provides a read-only cache on the
 * local SSDs of multiple clients. Less overhead is visible to the applications
 * and network latencies and lock conflicts can be significantly reduced.
 *
 * For RW-PCC, no global namespace will be provided. Each client uses its own
 * local storage as a cache for itself. Local file system is used to manage
 * the data on local caches. Cached I/O is directed to local file system while
 * normal I/O is directed to OSTs. RW-PCC uses HSM for data synchronization.
 * It uses HSM copytool to restore file from local caches to Lustre OSTs. Each
 * PCC has a copytool instance running with unique archive number. Any remote
 * access from another Lustre client would trigger the data synchronization. If
 * a client with RW-PCC goes offline, the cached data becomes inaccessible for
 * other client temporarily. And after the RW-PCC client reboots and the
 * copytool restarts, the data will be accessible again.
 *
 * Following is what will happen in different conditions for RW-PCC:
 *
 * > When file is being created on RW-PCC
 *
 * A normal HSM released file is created on MDT;
 * An empty mirror file is created on local cache;
 * The HSM status of the Lustre file will be set to archived and released;
 * The archive number will be set to the proper value.
 *
 * > When file is being prefetched to RW-PCC
 *
 * An file is copied to the local cache;
 * The HSM status of the Lustre file will be set to archived and released;
 * The archive number will be set to the proper value.
 *
 * > When file is being accessed from PCC
 *
 * Data will be read directly from local cache;
 * Metadata will be read from MDT, except file size;
 * File size will be got from local cache.
 *
 * > When PCC cached file is being accessed on another client
 *
 * RW-PCC cached files are automatically restored when a process on another
 * client tries to read or modify them. The corresponding I/O will block
 * waiting for the released file to be restored. This is transparent to the
 * process.
 *
 * For RW-PCC, when a file is being created, a rule-based policy is used to
 * determine whether it will be cached. Rule-based caching of newly created
 * files can determine which file can use a cache on PCC directly without any
 * admission control.
 *
 * RW-PCC design can accelerate I/O intensive applications with one-to-one
 * mappings between files and accessing clients. However, in several use cases,
 * files will never be updated, but need to be read simultaneously from many
 * clients. RO-PCC implements a read-only caching on Lustre clients using
 * SSDs. RO-PCC is based on the same framework as RW-PCC, expect
 * that no HSM mechanism is used.
 *
 * The main advantages to use this SSD cache on the Lustre clients via PCC
 * is that:
 * - The I/O stack becomes much simpler for the cached data, as there is no
 *   interference with I/Os from other clients, which enables easier
 *   performance optimizations;
 * - The requirements on the HW inside the client nodes are small, any kind of
 *   SSDs or even HDDs can be used as cache devices;
 * - Caching reduces the pressure on the object storage targets (OSTs), as
 *   small or random I/Os can be regularized to big sequential I/Os and
 *   temporary files do not even need to be flushed to OSTs.
 *
 * PCC can accelerate applications with certain I/O patterns:
 * - small-sized random writes (< 1MB) from a single client
 * - repeated read of data that is larger than RAM
 * - clients with high network latency
 *
 * Author: Li Xi <lixi@ddn.com>
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include "pcc.h"
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/libcfs/libcfs_string.h>
#include "llite_internal.h"

struct kmem_cache *pcc_inode_slab;

int pcc_super_init(struct pcc_super *super)
{
	struct cred *cred;

	super->pccs_cred = cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	/* Never override disk quota limits or use reserved space */
	cap_lower(cred->cap_effective, CAP_SYS_RESOURCE);
	init_rwsem(&super->pccs_rw_sem);
	INIT_LIST_HEAD(&super->pccs_datasets);

	return 0;
}

/* Rule based auto caching */
static void pcc_id_list_free(struct list_head *id_list)
{
	struct pcc_match_id *id, *n;

	list_for_each_entry_safe(id, n, id_list, pmi_linkage) {
		list_del_init(&id->pmi_linkage);
		kfree(id);
	}
}

static void pcc_fname_list_free(struct list_head *fname_list)
{
	struct pcc_match_fname *fname, *n;

	list_for_each_entry_safe(fname, n, fname_list, pmf_linkage) {
		kfree(fname->pmf_name);
		list_del_init(&fname->pmf_linkage);
		kfree(fname);
	}
}

static void pcc_expression_free(struct pcc_expression *expr)
{
	LASSERT(expr->pe_field >= PCC_FIELD_UID &&
		expr->pe_field < PCC_FIELD_MAX);
	switch (expr->pe_field) {
	case PCC_FIELD_UID:
	case PCC_FIELD_GID:
	case PCC_FIELD_PROJID:
		pcc_id_list_free(&expr->pe_cond);
		break;
	case PCC_FIELD_FNAME:
		pcc_fname_list_free(&expr->pe_cond);
		break;
	default:
		LBUG();
	}
	kfree(expr);
}

static void pcc_conjunction_free(struct pcc_conjunction *conjunction)
{
	struct pcc_expression *expression, *n;

	LASSERT(list_empty(&conjunction->pc_linkage));
	list_for_each_entry_safe(expression, n,
				 &conjunction->pc_expressions,
				 pe_linkage) {
		list_del_init(&expression->pe_linkage);
		pcc_expression_free(expression);
	}
	kfree(conjunction);
}

static void pcc_rule_conds_free(struct list_head *cond_list)
{
	struct pcc_conjunction *conjunction, *n;

	list_for_each_entry_safe(conjunction, n, cond_list, pc_linkage) {
		list_del_init(&conjunction->pc_linkage);
		pcc_conjunction_free(conjunction);
	}
}

static void pcc_cmd_fini(struct pcc_cmd *cmd)
{
	if (cmd->pccc_cmd == PCC_ADD_DATASET) {
		if (!list_empty(&cmd->u.pccc_add.pccc_conds))
			pcc_rule_conds_free(&cmd->u.pccc_add.pccc_conds);
		kfree(cmd->u.pccc_add.pccc_conds_str);
	}
}

#define PCC_DISJUNCTION_DELIM	(',')
#define PCC_CONJUNCTION_DELIM	('&')
#define PCC_EXPRESSION_DELIM	('=')

static int
pcc_fname_list_add(struct cfs_lstr *id, struct list_head *fname_list)
{
	struct pcc_match_fname *fname;

	fname = kzalloc(sizeof(*fname), GFP_KERNEL);
	if (!fname)
		return -ENOMEM;

	fname->pmf_name = kzalloc(id->ls_len + 1, GFP_KERNEL);
	if (!fname->pmf_name) {
		kfree(fname);
		return -ENOMEM;
	}

	memcpy(fname->pmf_name, id->ls_str, id->ls_len);
	list_add_tail(&fname->pmf_linkage, fname_list);
	return 0;
}

static int
pcc_fname_list_parse(char *str, int len, struct list_head *fname_list)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;

	src.ls_str = str;
	src.ls_len = len;
	INIT_LIST_HEAD(fname_list);
	while (src.ls_str) {
		rc = cfs_gettok(&src, ' ', &res);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = pcc_fname_list_add(&res, fname_list);
		if (rc)
			break;
	}
	if (rc)
		pcc_fname_list_free(fname_list);
	return rc;
}

static int
pcc_id_list_parse(char *str, int len, struct list_head *id_list,
		  enum pcc_field type)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;

	if (type != PCC_FIELD_UID && type != PCC_FIELD_GID &&
	    type != PCC_FIELD_PROJID)
		return -EINVAL;

	src.ls_str = str;
	src.ls_len = len;
	INIT_LIST_HEAD(id_list);
	while (src.ls_str) {
		struct pcc_match_id *id;
		u32 id_val;

		if (cfs_gettok(&src, ' ', &res) == 0) {
			rc = -EINVAL;
			goto out;
		}

		if (!cfs_str2num_check(res.ls_str, res.ls_len,
				       &id_val, 0, (u32)~0U)) {
			rc = -EINVAL;
			goto out;
		}

		id = kzalloc(sizeof(*id), GFP_KERNEL);
		if (!id) {
			rc = -ENOMEM;
			goto out;
		}

		id->pmi_id = id_val;
		list_add_tail(&id->pmi_linkage, id_list);
	}
out:
	if (rc)
		pcc_id_list_free(id_list);
	return rc;
}

static inline bool
pcc_check_field(struct cfs_lstr *field, char *str)
{
	int len = strlen(str);

	return (field->ls_len == len &&
		strncmp(field->ls_str, str, len) == 0);
}

static int
pcc_expression_parse(struct cfs_lstr *src, struct list_head *cond_list)
{
	struct pcc_expression *expr;
	struct cfs_lstr field;
	int rc = 0;

	expr = kzalloc(sizeof(*expr), GFP_KERNEL);
	if (!expr)
		return -ENOMEM;

	rc = cfs_gettok(src, PCC_EXPRESSION_DELIM, &field);
	if (rc == 0 || src->ls_len <= 2 || src->ls_str[0] != '{' ||
	    src->ls_str[src->ls_len - 1] != '}') {
		rc = -EINVAL;
		goto out;
	}

	/* Skip '{' and '}' */
	src->ls_str++;
	src->ls_len -= 2;

	if (pcc_check_field(&field, "uid")) {
		if (pcc_id_list_parse(src->ls_str,
				      src->ls_len,
				      &expr->pe_cond,
				      PCC_FIELD_UID) < 0) {
			rc = -EINVAL;
			goto out;
		}
		expr->pe_field = PCC_FIELD_UID;
	} else if (pcc_check_field(&field, "gid")) {
		if (pcc_id_list_parse(src->ls_str,
				      src->ls_len,
				      &expr->pe_cond,
				      PCC_FIELD_GID) < 0) {
			rc = -EINVAL;
			goto out;
		}
		expr->pe_field = PCC_FIELD_GID;
	} else if (pcc_check_field(&field, "projid")) {
		if (pcc_id_list_parse(src->ls_str,
				      src->ls_len,
				      &expr->pe_cond,
				      PCC_FIELD_PROJID) < 0) {
			rc = -EINVAL;
			goto out;
		}
		expr->pe_field = PCC_FIELD_PROJID;
	} else if (pcc_check_field(&field, "fname")) {
		if (pcc_fname_list_parse(src->ls_str,
					 src->ls_len,
					 &expr->pe_cond) < 0) {
			rc = -EINVAL;
			goto out;
		}
		expr->pe_field = PCC_FIELD_FNAME;
	} else {
		rc = -EINVAL;
		goto out;
	}

	list_add_tail(&expr->pe_linkage, cond_list);
	return 0;
out:
	kfree(expr);
	return rc;
}

static int
pcc_conjunction_parse(struct cfs_lstr *src, struct list_head *cond_list)
{
	struct pcc_conjunction *conjunction;
	struct cfs_lstr expr;
	int rc = 0;

	conjunction = kzalloc(sizeof(*conjunction), GFP_KERNEL);
	if (!conjunction)
		return -ENOMEM;

	INIT_LIST_HEAD(&conjunction->pc_expressions);
	list_add_tail(&conjunction->pc_linkage, cond_list);

	while (src->ls_str) {
		rc = cfs_gettok(src, PCC_CONJUNCTION_DELIM, &expr);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = pcc_expression_parse(&expr,
					  &conjunction->pc_expressions);
		if (rc)
			break;
	}
	return rc;
}

static int pcc_conds_parse(char *str, int len, struct list_head *cond_list)
{
	struct cfs_lstr src;
	struct cfs_lstr res;
	int rc = 0;

	src.ls_str = str;
	src.ls_len = len;
	INIT_LIST_HEAD(cond_list);
	while (src.ls_str) {
		rc = cfs_gettok(&src, PCC_DISJUNCTION_DELIM, &res);
		if (rc == 0) {
			rc = -EINVAL;
			break;
		}
		rc = pcc_conjunction_parse(&res, cond_list);
		if (rc)
			break;
	}
	return rc;
}

static int pcc_id_parse(struct pcc_cmd *cmd, const char *id)
{
	int rc;

	cmd->u.pccc_add.pccc_conds_str = kzalloc(strlen(id) + 1, GFP_KERNEL);
	if (!cmd->u.pccc_add.pccc_conds_str)
		return -ENOMEM;

	memcpy(cmd->u.pccc_add.pccc_conds_str, id, strlen(id));

	rc = pcc_conds_parse(cmd->u.pccc_add.pccc_conds_str,
			     strlen(cmd->u.pccc_add.pccc_conds_str),
			     &cmd->u.pccc_add.pccc_conds);
	if (rc)
		pcc_cmd_fini(cmd);

	return rc;
}

static int
pcc_parse_value_pair(struct pcc_cmd *cmd, char *buffer)
{
	char *key, *val;
	unsigned long id;
	int rc;

	val = buffer;
	key = strsep(&val, "=");
	if (!val || strlen(val) == 0)
		return -EINVAL;

	/* Key of the value pair */
	if (strcmp(key, "rwid") == 0) {
		rc = kstrtoul(val, 10, &id);
		if (rc)
			return rc;
		if (id <= 0)
			return -EINVAL;
		cmd->u.pccc_add.pccc_rwid = id;
	} else if (strcmp(key, "roid") == 0) {
		rc = kstrtoul(val, 10, &id);
		if (rc)
			return rc;
		if (id <= 0)
			return -EINVAL;
		cmd->u.pccc_add.pccc_roid = id;
	} else if (strcmp(key, "open_attach") == 0) {
		rc = kstrtoul(val, 10, &id);
		if (rc)
			return rc;
		if (id > 0)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_OPEN_ATTACH;
	} else if (strcmp(key, "rwpcc") == 0) {
		rc = kstrtoul(val, 10, &id);
		if (rc)
			return rc;
		if (id > 0)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_RWPCC;
	} else if (strcmp(key, "ropcc") == 0) {
		rc = kstrtoul(val, 10, &id);
		if (rc)
			return rc;
		if (id > 0)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_ROPCC;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int
pcc_parse_value_pairs(struct pcc_cmd *cmd, char *buffer)
{
	char *val;
	char *token;
	int rc;

	val = buffer;
	while (val && strlen(val) != 0) {
		token = strsep(&val, " ");
		rc = pcc_parse_value_pair(cmd, token);
		if (rc)
			return rc;
	}

	switch (cmd->pccc_cmd) {
	case PCC_ADD_DATASET:
		if (cmd->u.pccc_add.pccc_flags & PCC_DATASET_RWPCC &&
		    cmd->u.pccc_add.pccc_flags & PCC_DATASET_ROPCC)
			return -EINVAL;
		/*
		 * By default, a PCC backend can provide caching service for
		 * both RW-PCC and RO-PCC.
		 */
		if ((cmd->u.pccc_add.pccc_flags & PCC_DATASET_PCC_ALL) == 0)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_PCC_ALL;
		break;
	case PCC_DEL_DATASET:
	case PCC_CLEAR_ALL:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void
pcc_dataset_rule_fini(struct pcc_match_rule *rule)
{
	if (!list_empty(&rule->pmr_conds))
		pcc_rule_conds_free(&rule->pmr_conds);
	LASSERT(rule->pmr_conds_str);
	kfree(rule->pmr_conds_str);
}

static int
pcc_dataset_rule_init(struct pcc_match_rule *rule, struct pcc_cmd *cmd)
{
	int rc = 0;

	LASSERT(cmd->u.pccc_add.pccc_conds_str);
	rule->pmr_conds_str = kzalloc(
		strlen(cmd->u.pccc_add.pccc_conds_str) + 1,
		GFP_KERNEL);
	if (!rule->pmr_conds_str)
		return -ENOMEM;

	memcpy(rule->pmr_conds_str,
	       cmd->u.pccc_add.pccc_conds_str,
	       strlen(cmd->u.pccc_add.pccc_conds_str));

	INIT_LIST_HEAD(&rule->pmr_conds);
	if (!list_empty(&cmd->u.pccc_add.pccc_conds))
		rc = pcc_conds_parse(rule->pmr_conds_str,
					  strlen(rule->pmr_conds_str),
					  &rule->pmr_conds);

	if (rc)
		pcc_dataset_rule_fini(rule);

	return rc;
}

/* Rule Matching */
static int
pcc_id_list_match(struct list_head *id_list, u32 id_val)
{
	struct pcc_match_id *id;

	list_for_each_entry(id, id_list, pmi_linkage) {
		if (id->pmi_id == id_val)
			return 1;
	}
	return 0;
}

static bool
cfs_match_wildcard(const char *pattern, const char *content)
{
	if (*pattern == '\0' && *content == '\0')
		return true;

	if (*pattern == '*' && *(pattern + 1) != '\0' && *content == '\0')
		return false;

	while (*pattern == *content) {
		pattern++;
		content++;
		if (*pattern == '\0' && *content == '\0')
			return true;

		if (*pattern == '*' && *(pattern + 1) != '\0' &&
		    *content == '\0')
			return false;
	}

	if (*pattern == '*')
		return (cfs_match_wildcard(pattern + 1, content) ||
			cfs_match_wildcard(pattern, content + 1));

	return false;
}

static int
pcc_fname_list_match(struct list_head *fname_list, const char *name)
{
	struct pcc_match_fname *fname;

	list_for_each_entry(fname, fname_list, pmf_linkage) {
		if (cfs_match_wildcard(fname->pmf_name, name))
			return 1;
	}
	return 0;
}

static int
pcc_expression_match(struct pcc_expression *expr, struct pcc_matcher *matcher)
{
	switch (expr->pe_field) {
	case PCC_FIELD_UID:
		return pcc_id_list_match(&expr->pe_cond, matcher->pm_uid);
	case PCC_FIELD_GID:
		return pcc_id_list_match(&expr->pe_cond, matcher->pm_gid);
	case PCC_FIELD_PROJID:
		return pcc_id_list_match(&expr->pe_cond, matcher->pm_projid);
	case PCC_FIELD_FNAME:
		return pcc_fname_list_match(&expr->pe_cond,
					    matcher->pm_name->name);
	default:
		return 0;
	}
}

static int
pcc_conjunction_match(struct pcc_conjunction *conjunction,
		      struct pcc_matcher *matcher)
{
	struct pcc_expression *expr;
	int matched;

	list_for_each_entry(expr, &conjunction->pc_expressions, pe_linkage) {
		matched = pcc_expression_match(expr, matcher);
		if (!matched)
			return 0;
	}

	return 1;
}

static int
pcc_cond_match(struct pcc_match_rule *rule, struct pcc_matcher *matcher)
{
	struct pcc_conjunction *conjunction;
	int matched;

	list_for_each_entry(conjunction, &rule->pmr_conds, pc_linkage) {
		matched = pcc_conjunction_match(conjunction, matcher);
		if (matched)
			return 1;
	}

	return 0;
}

struct pcc_dataset*
pcc_dataset_match_get(struct pcc_super *super, struct pcc_matcher *matcher)
{
	struct pcc_dataset *dataset;
	struct pcc_dataset *selected = NULL;

	down_read(&super->pccs_rw_sem);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		if (!(dataset->pccd_flags & PCC_DATASET_RWPCC))
			continue;

		if (pcc_cond_match(&dataset->pccd_rule, matcher)) {
			atomic_inc(&dataset->pccd_refcount);
			selected = dataset;
			break;
		}
	}
	up_read(&super->pccs_rw_sem);
	if (selected)
		CDEBUG(D_CACHE, "PCC create, matched %s - %d:%d:%d:%s\n",
		       dataset->pccd_rule.pmr_conds_str,
		       matcher->pm_uid, matcher->pm_gid,
		       matcher->pm_projid, matcher->pm_name->name);

	return selected;
}

/**
 * pcc_dataset_add - Add a Cache policy to control which files need be
 * cached and where it will be cached.
 *
 * @super:	superblock of pcc
 * @cmd:	pcc command
 */
static int
pcc_dataset_add(struct pcc_super *super, struct pcc_cmd *cmd)
{
	char *pathname = cmd->pccc_pathname;
	struct pcc_dataset *dataset;
	struct pcc_dataset *tmp;
	bool found = false;
	int rc;

	dataset = kzalloc(sizeof(*dataset), GFP_NOFS);
	if (!dataset)
		return -ENOMEM;

	rc = kern_path(pathname, LOOKUP_DIRECTORY, &dataset->pccd_path);
	if (unlikely(rc)) {
		kfree(dataset);
		return rc;
	}
	strncpy(dataset->pccd_pathname, pathname, PATH_MAX);
	dataset->pccd_rwid = cmd->u.pccc_add.pccc_rwid;
	dataset->pccd_roid = cmd->u.pccc_add.pccc_roid;
	dataset->pccd_flags = cmd->u.pccc_add.pccc_flags;
	atomic_set(&dataset->pccd_refcount, 1);

	rc = pcc_dataset_rule_init(&dataset->pccd_rule, cmd);
	if (rc) {
		pcc_dataset_put(dataset);
		return rc;
	}

	down_write(&super->pccs_rw_sem);
	list_for_each_entry(tmp, &super->pccs_datasets, pccd_linkage) {
		if (strcmp(tmp->pccd_pathname, pathname) == 0 ||
		    (dataset->pccd_rwid != 0 &&
		     dataset->pccd_rwid == tmp->pccd_rwid) ||
		    (dataset->pccd_roid != 0 &&
		     dataset->pccd_roid == tmp->pccd_roid)) {
			found = true;
			break;
		}
	}
	if (!found)
		list_add(&dataset->pccd_linkage, &super->pccs_datasets);
	up_write(&super->pccs_rw_sem);

	if (found) {
		pcc_dataset_put(dataset);
		rc = -EEXIST;
	}

	return rc;
}

struct pcc_dataset *
pcc_dataset_get(struct pcc_super *super, enum lu_pcc_type type, u32 id)
{
	struct pcc_dataset *dataset;
	struct pcc_dataset *selected = NULL;

	if (id == 0)
		return NULL;

	/*
	 * archive ID (read-write ID) or read-only ID is unique in the list,
	 * we just return last added one as first priority.
	 */
	down_read(&super->pccs_rw_sem);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		if (type == LU_PCC_READWRITE && (dataset->pccd_rwid != id ||
		    !(dataset->pccd_flags & PCC_DATASET_RWPCC)))
			continue;
		atomic_inc(&dataset->pccd_refcount);
		selected = dataset;
		break;
	}
	up_read(&super->pccs_rw_sem);
	if (selected)
		CDEBUG(D_CACHE, "matched id %u, PCC mode %d\n", id, type);

	return selected;
}

void
pcc_dataset_put(struct pcc_dataset *dataset)
{
	if (atomic_dec_and_test(&dataset->pccd_refcount)) {
		pcc_dataset_rule_fini(&dataset->pccd_rule);
		path_put(&dataset->pccd_path);
		kfree(dataset);
	}
}

static int
pcc_dataset_del(struct pcc_super *super, char *pathname)
{
	struct list_head *l, *tmp;
	struct pcc_dataset *dataset;
	int rc = -ENOENT;

	down_write(&super->pccs_rw_sem);
	list_for_each_safe(l, tmp, &super->pccs_datasets) {
		dataset = list_entry(l, struct pcc_dataset, pccd_linkage);
		if (strcmp(dataset->pccd_pathname, pathname) == 0) {
			list_del_init(&dataset->pccd_linkage);
			pcc_dataset_put(dataset);
			rc = 0;
			break;
		}
	}
	up_write(&super->pccs_rw_sem);
	return rc;
}

static void
pcc_dataset_dump(struct pcc_dataset *dataset, struct seq_file *m)
{
	seq_printf(m, "%s:\n", dataset->pccd_pathname);
	seq_printf(m, "  rwid: %u\n", dataset->pccd_rwid);
	seq_printf(m, "  flags: %x\n", dataset->pccd_flags);
	seq_printf(m, "  autocache: %s\n", dataset->pccd_rule.pmr_conds_str);
}

int
pcc_super_dump(struct pcc_super *super, struct seq_file *m)
{
	struct pcc_dataset *dataset;

	down_read(&super->pccs_rw_sem);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		pcc_dataset_dump(dataset, m);
	}
	up_read(&super->pccs_rw_sem);
	return 0;
}

static void pcc_remove_datasets(struct pcc_super *super)
{
	struct pcc_dataset *dataset, *tmp;

	down_write(&super->pccs_rw_sem);
	list_for_each_entry_safe(dataset, tmp,
				 &super->pccs_datasets, pccd_linkage) {
		list_del(&dataset->pccd_linkage);
		pcc_dataset_put(dataset);
	}
	up_write(&super->pccs_rw_sem);
}

void pcc_super_fini(struct pcc_super *super)
{
	pcc_remove_datasets(super);
	put_cred(super->pccs_cred);
}

static bool pathname_is_valid(const char *pathname)
{
	/* Needs to be absolute path */
	if (!pathname || strlen(pathname) == 0 ||
	    strlen(pathname) >= PATH_MAX || pathname[0] != '/')
		return false;
	return true;
}

static struct pcc_cmd *
pcc_cmd_parse(char *buffer, unsigned long count)
{
	static struct pcc_cmd *cmd;
	char *token;
	char *val;
	int rc = 0;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		rc = -ENOMEM;
		goto out;
	}

	/* clear all setting */
	if (strncmp(buffer, "clear", 5) == 0) {
		cmd->pccc_cmd = PCC_CLEAR_ALL;
		rc = 0;
		goto out;
	}

	val = buffer;
	token = strsep(&val, " ");
	if (!val || strlen(val) == 0) {
		rc = -EINVAL;
		goto out_free_cmd;
	}

	/* Type of the command */
	if (strcmp(token, "add") == 0) {
		cmd->pccc_cmd = PCC_ADD_DATASET;
	} else if (strcmp(token, "del") == 0) {
		cmd->pccc_cmd = PCC_DEL_DATASET;
	} else {
		rc = -EINVAL;
		goto out_free_cmd;
	}

	/* Pathname of the dataset */
	token = strsep(&val, " ");
	if ((!val && cmd->pccc_cmd != PCC_DEL_DATASET) ||
	    !pathname_is_valid(token)) {
		rc = -EINVAL;
		goto out_free_cmd;
	}
	cmd->pccc_pathname = token;

	if (cmd->pccc_cmd == PCC_ADD_DATASET) {
		/* List of ID */
		LASSERT(val);
		token = val;
		val = strrchr(token, '}');
		if (!val) {
			rc = -EINVAL;
			goto out_free_cmd;
		}

		/* Skip '}' */
		val++;
		if (*val == '\0') {
			val = NULL;
		} else if (*val == ' ') {
			*val = '\0';
			val++;
		} else {
			rc = -EINVAL;
			goto out_free_cmd;
		}

		rc = pcc_id_parse(cmd, token);
		if (rc)
			goto out_free_cmd;

		rc = pcc_parse_value_pairs(cmd, val);
		if (rc) {
			rc = -EINVAL;
			goto out_cmd_fini;
		}
	}
	goto out;
out_cmd_fini:
	pcc_cmd_fini(cmd);
out_free_cmd:
	kfree(cmd);
out:
	if (rc)
		cmd = ERR_PTR(rc);
	return cmd;
}

int pcc_cmd_handle(char *buffer, unsigned long count,
		   struct pcc_super *super)
{
	int rc = 0;
	struct pcc_cmd *cmd;

	cmd = pcc_cmd_parse(buffer, count);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	switch (cmd->pccc_cmd) {
	case PCC_ADD_DATASET:
		rc = pcc_dataset_add(super, cmd);
		break;
	case PCC_DEL_DATASET:
		rc = pcc_dataset_del(super, cmd->pccc_pathname);
		break;
	case PCC_CLEAR_ALL:
		pcc_remove_datasets(super);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	pcc_cmd_fini(cmd);
	kfree(cmd);
	return rc;
}

static inline void pcc_inode_lock(struct inode *inode)
{
	mutex_lock(&ll_i2info(inode)->lli_pcc_lock);
}

static inline void pcc_inode_unlock(struct inode *inode)
{
	mutex_unlock(&ll_i2info(inode)->lli_pcc_lock);
}

static void pcc_inode_init(struct pcc_inode *pcci, struct ll_inode_info *lli)
{
	pcci->pcci_lli = lli;
	lli->lli_pcc_inode = pcci;
	lli->lli_pcc_state = PCC_STATE_FL_NONE;
	atomic_set(&pcci->pcci_refcount, 0);
	pcci->pcci_type = LU_PCC_NONE;
	pcci->pcci_layout_gen = CL_LAYOUT_GEN_NONE;
	atomic_set(&pcci->pcci_active_ios, 0);
	init_waitqueue_head(&pcci->pcci_waitq);
}

static void pcc_inode_fini(struct pcc_inode *pcci)
{
	struct ll_inode_info *lli = pcci->pcci_lli;

	path_put(&pcci->pcci_path);
	pcci->pcci_type = LU_PCC_NONE;
	kmem_cache_free(pcc_inode_slab, pcci);
	lli->lli_pcc_inode = NULL;
}

static void pcc_inode_get(struct pcc_inode *pcci)
{
	atomic_inc(&pcci->pcci_refcount);
}

static void pcc_inode_put(struct pcc_inode *pcci)
{
	if (atomic_dec_and_test(&pcci->pcci_refcount))
		pcc_inode_fini(pcci);
}

void pcc_inode_free(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	if (pcci) {
		WARN_ON(atomic_read(&pcci->pcci_refcount) > 1);
		pcc_inode_put(pcci);
	}
}

/*
 * TODO:
 * As Andreas suggested, we'd better use new layout to
 * reduce overhead:
 * (fid->f_oid >> 16 & oxFFFF)/FID
 */
#define MAX_PCC_DATABASE_PATH (6 * 5 + FID_NOBRACE_LEN + 1)
static int pcc_fid2dataset_path(char *buf, int sz, struct lu_fid *fid)
{
	return snprintf(buf, sz, "%04x/%04x/%04x/%04x/%04x/%04x/"
			DFID_NOBRACE,
			(fid)->f_oid       & 0xFFFF,
			(fid)->f_oid >> 16 & 0xFFFF,
			(unsigned int)((fid)->f_seq       & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 16 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 32 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 48 & 0xFFFF),
			PFID(fid));
}

static inline const struct cred *pcc_super_cred(struct super_block *sb)
{
	return ll_s2sbi(sb)->ll_pcc_super.pccs_cred;
}

void pcc_file_init(struct pcc_file *pccf)
{
	pccf->pccf_file = NULL;
	pccf->pccf_type = LU_PCC_NONE;
}

static inline bool pcc_open_attach_enabled(struct pcc_dataset *dataset)
{
	return dataset->pccd_flags & PCC_DATASET_OPEN_ATTACH;
}

static const char pcc_xattr_layout[] = XATTR_USER_PREFIX "PCC.layout";

static int pcc_layout_xattr_set(struct pcc_inode *pcci, u32 gen)
{
	struct dentry *pcc_dentry = pcci->pcci_path.dentry;
	struct ll_inode_info *lli = pcci->pcci_lli;
	int rc;

	if (!(lli->lli_pcc_state & PCC_STATE_FL_OPEN_ATTACH))
		return 0;

	rc = __vfs_setxattr(pcc_dentry, pcc_dentry->d_inode, pcc_xattr_layout,
			    &gen, sizeof(gen), 0);
	return rc;
}

static int pcc_get_layout_info(struct inode *inode, struct cl_layout *clt)
{
	struct lu_env *env;
	struct ll_inode_info *lli = ll_i2info(inode);
	u16 refcheck;
	int rc;

	if (!lli->lli_clob)
		return -EINVAL;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	rc = cl_object_layout_get(env, lli->lli_clob, clt);
	if (rc)
		CDEBUG(D_INODE, "Cannot get layout for "DFID"\n",
		       PFID(ll_inode2fid(inode)));

	cl_env_put(env, &refcheck);
	return rc;
}

static int pcc_fid2dataset_fullpath(char *buf, int sz, struct lu_fid *fid,
				    struct pcc_dataset *dataset)
{
	return snprintf(buf, sz, "%s/%04x/%04x/%04x/%04x/%04x/%04x/"
			DFID_NOBRACE,
			dataset->pccd_pathname,
			(fid)->f_oid       & 0xFFFF,
			(fid)->f_oid >> 16 & 0xFFFF,
			(unsigned int)((fid)->f_seq       & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 16 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 32 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 48 & 0xFFFF),
			PFID(fid));
}

/* Must be called with pcci->pcci_lock held */
static void pcc_inode_attach_init(struct pcc_dataset *dataset,
				  struct pcc_inode *pcci,
				  struct dentry *dentry,
				  enum lu_pcc_type type)
{
	pcci->pcci_path.mnt = mntget(dataset->pccd_path.mnt);
	pcci->pcci_path.dentry = dentry;
	LASSERT(atomic_read(&pcci->pcci_refcount) == 0);
	atomic_set(&pcci->pcci_refcount, 1);
	pcci->pcci_type = type;
	pcci->pcci_attr_valid = false;

	if (pcc_open_attach_enabled(dataset)) {
		struct ll_inode_info *lli = pcci->pcci_lli;

		lli->lli_pcc_state |= PCC_STATE_FL_OPEN_ATTACH;
	}
}

static inline void pcc_layout_gen_set(struct pcc_inode *pcci,
				      u32 gen)
{
	pcci->pcci_layout_gen = gen;
}

static inline bool pcc_inode_has_layout(struct pcc_inode *pcci)
{
	return pcci->pcci_layout_gen != CL_LAYOUT_GEN_NONE;
}

static int pcc_try_dataset_attach(struct inode *inode, u32 gen,
				  enum lu_pcc_type type,
				  struct pcc_dataset *dataset,
				  bool *cached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci = lli->lli_pcc_inode;
	const struct cred *old_cred;
	struct dentry *pcc_dentry;
	struct path path;
	char *pathname;
	u32 pcc_gen;
	int rc;

	if (type == LU_PCC_READWRITE &&
	    !(dataset->pccd_flags & PCC_DATASET_RWPCC))
		return 0;

	pathname = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!pathname)
		return -ENOMEM;

	pcc_fid2dataset_fullpath(pathname, PATH_MAX, &lli->lli_fid, dataset);

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = kern_path(pathname, LOOKUP_FOLLOW, &path);
	if (rc) {
		/* ignore this error */
		rc = 0;
		goto out;
	}

	pcc_dentry = path.dentry;
	rc = __vfs_getxattr(pcc_dentry, pcc_dentry->d_inode, pcc_xattr_layout,
			    &pcc_gen, sizeof(pcc_gen));
	if (rc < 0) {
		/* ignore this error */
		rc = 0;
		goto out_put_path;
	}

	rc = 0;
	/* The file is still valid cached in PCC, attach it immediately. */
	if (pcc_gen == gen) {
		CDEBUG(D_CACHE, DFID" L.Gen (%d) consistent, auto attached.\n",
		       PFID(&lli->lli_fid), gen);
		if (!pcci) {
			pcci = kmem_cache_zalloc(pcc_inode_slab, GFP_NOFS);
			if (!pcci) {
				rc = -ENOMEM;
				goto out_put_path;
			}

			pcc_inode_init(pcci, lli);
			dget(pcc_dentry);
			pcc_inode_attach_init(dataset, pcci, pcc_dentry, type);
		} else {
			/*
			 * This happened when a file was once attached into
			 * PCC, and some processes keep this file opened
			 * (pcci->refcount > 1) and corresponding PCC file
			 * without any I/O activity, and then this file was
			 * detached by the manual detach command or the
			 * revocation of the layout lock (i.e. cached LRU lock
			 * shrinking).
			 */
			pcc_inode_get(pcci);
			pcci->pcci_type = type;
		}
		pcc_layout_gen_set(pcci, gen);
		*cached = true;
	}
out_put_path:
	path_put(&path);
out:
	revert_creds(old_cred);
	kfree(pathname);
	return rc;
}

static int pcc_try_datasets_attach(struct inode *inode, u32 gen,
				   enum lu_pcc_type type, bool *cached)
{
	struct pcc_dataset *dataset, *tmp;
	struct pcc_super *super = &ll_i2sbi(inode)->ll_pcc_super;
	int rc = 0;

	down_read(&super->pccs_rw_sem);
	list_for_each_entry_safe(dataset, tmp,
				 &super->pccs_datasets, pccd_linkage) {
		if (!pcc_open_attach_enabled(dataset))
			continue;
		rc = pcc_try_dataset_attach(inode, gen, type, dataset, cached);
		if (rc < 0 || (!rc && *cached))
			break;
	}
	up_read(&super->pccs_rw_sem);

	return rc;
}

static int pcc_try_open_attach(struct inode *inode, bool *cached)
{
	struct pcc_super *super = &ll_i2sbi(inode)->ll_pcc_super;
	struct cl_layout clt = {
		.cl_layout_gen = 0,
		.cl_is_released = false,
	};
	int rc;

	/*
	 * Quick check whether there is PCC device.
	 */
	if (list_empty(&super->pccs_datasets))
		return 0;

	/*
	 * The file layout lock was cancelled. And this open does not
	 * obtain valid layout lock from MDT (i.e. the file is being
	 * HSM restoring).
	 */
	if (ll_layout_version_get(ll_i2info(inode)) == CL_LAYOUT_GEN_NONE)
		return 0;

	rc = pcc_get_layout_info(inode, &clt);
	if (rc)
		return rc;

	if (clt.cl_is_released)
		rc = pcc_try_datasets_attach(inode, clt.cl_layout_gen,
					     LU_PCC_READWRITE, cached);

	return rc;
}

int pcc_file_open(struct inode *inode, struct file *file)
{
	struct pcc_inode *pcci;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct file *pcc_file;
	struct path *path;
	struct qstr *dname;
	bool cached = false;
	int rc = 0;

	if (!S_ISREG(inode->i_mode))
		return 0;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);

	if (lli->lli_pcc_state & PCC_STATE_FL_ATTACHING)
		goto out_unlock;

	if (!pcci || !pcc_inode_has_layout(pcci)) {
		rc = pcc_try_open_attach(inode, &cached);
		if (rc < 0 || !cached)
			goto out_unlock;

		if (!pcci)
			pcci = ll_i2pcci(inode);
	}

	pcc_inode_get(pcci);
	WARN_ON(pccf->pccf_file);

	path = &pcci->pcci_path;
	dname = &path->dentry->d_name;
	CDEBUG(D_CACHE, "opening pcc file '%.*s'\n", dname->len,
	       dname->name);

	pcc_file = dentry_open(path, file->f_flags,
			       pcc_super_cred(inode->i_sb));
	if (IS_ERR_OR_NULL(pcc_file)) {
		rc = pcc_file ? PTR_ERR(pcc_file) : -EINVAL;
		pcc_inode_put(pcci);
	} else {
		pccf->pccf_file = pcc_file;
		pccf->pccf_type = pcci->pcci_type;
	}

out_unlock:
	pcc_inode_unlock(inode);
	return rc;
}

void pcc_file_release(struct inode *inode, struct file *file)
{
	struct pcc_inode *pcci;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf;
	struct path *path;
	struct qstr *dname;

	if (!S_ISREG(inode->i_mode) || !fd)
		return;

	pccf = &fd->fd_pcc_file;
	pcc_inode_lock(inode);
	if (!pccf->pccf_file)
		goto out;

	pcci = ll_i2pcci(inode);
	LASSERT(pcci);
	path = &pcci->pcci_path;
	dname = &path->dentry->d_name;
	CDEBUG(D_CACHE, "releasing pcc file \"%.*s\"\n", dname->len,
	       dname->name);
	pcc_inode_put(pcci);
	fput(pccf->pccf_file);
	pccf->pccf_file = NULL;
out:
	pcc_inode_unlock(inode);
}

static void pcc_io_init(struct inode *inode, bool *cached)
{
	struct pcc_inode *pcci;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);
		atomic_inc(&pcci->pcci_active_ios);
		*cached = true;
	} else {
		*cached = false;
	}
	pcc_inode_unlock(inode);
}

static void pcc_io_fini(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	LASSERT(pcci && atomic_read(&pcci->pcci_active_ios) > 0);
	if (atomic_dec_and_test(&pcci->pcci_active_ios))
		wake_up_all(&pcci->pcci_waitq);
}

ssize_t pcc_file_read_iter(struct kiocb *iocb,
			   struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct inode *inode = file_inode(file);
	ssize_t result;

	if (!pccf->pccf_file) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	iocb->ki_filp = pccf->pccf_file;
	/* generic_file_aio_read does not support ext4-dax,
	 * filp->f_ops->read_iter uses ->aio_read hook directly
	 * to add support for ext4-dax.
	 */
	result = file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;

	pcc_io_fini(inode);
	return result;
}

ssize_t pcc_file_write_iter(struct kiocb *iocb,
			    struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct inode *inode = file_inode(file);
	ssize_t result;

	if (!pccf->pccf_file) {
		*cached = false;
		return 0;
	}

	if (pccf->pccf_type != LU_PCC_READWRITE) {
		*cached = false;
		return -EAGAIN;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	if (OBD_FAIL_CHECK(OBD_FAIL_LLITE_PCC_FAKE_ERROR)) {
		result = -ENOSPC;
		goto out;
	}

	iocb->ki_filp = pccf->pccf_file;

	/* Since file->fop->write_iter makes write calls via
	 * the normal vfs interface to the local PCC file system,
	 * the inode lock is not needed.
	 */
	result = file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
out:
	pcc_io_fini(inode);
	return result;
}

int pcc_inode_setattr(struct inode *inode, struct iattr *attr,
		      bool *cached)
{
	int rc = 0;
	const struct cred *old_cred;
	struct iattr attr2 = *attr;
	struct dentry *pcc_dentry;
	struct pcc_inode *pcci;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	attr2.ia_valid = attr->ia_valid & (ATTR_SIZE | ATTR_ATIME |
			 ATTR_ATIME_SET | ATTR_MTIME | ATTR_MTIME_SET |
			 ATTR_CTIME | ATTR_UID | ATTR_GID);
	pcci = ll_i2pcci(inode);
	pcc_dentry = pcci->pcci_path.dentry;
	inode_lock(pcc_dentry->d_inode);
	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = pcc_dentry->d_inode->i_op->setattr(pcc_dentry, &attr2);
	revert_creds(old_cred);
	inode_unlock(pcc_dentry->d_inode);

	pcc_io_fini(inode);
	return rc;
}

int pcc_inode_getattr(struct inode *inode, bool *cached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	const struct cred *old_cred;
	struct kstat stat;
	s64 atime;
	s64 mtime;
	s64 ctime;
	int rc = 0;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = vfs_getattr(&ll_i2pcci(inode)->pcci_path, &stat,
			 STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
	revert_creds(old_cred);
	if (rc)
		goto out;

	ll_inode_size_lock(inode);
	if (test_and_clear_bit(LLIF_UPDATE_ATIME, &lli->lli_flags) ||
	    inode->i_atime.tv_sec < lli->lli_atime)
		inode->i_atime.tv_sec = lli->lli_atime;

	inode->i_mtime.tv_sec = lli->lli_mtime;
	inode->i_ctime.tv_sec = lli->lli_ctime;

	atime = inode->i_atime.tv_sec;
	mtime = inode->i_mtime.tv_sec;
	ctime = inode->i_ctime.tv_sec;

	if (atime < stat.atime.tv_sec)
		atime = stat.atime.tv_sec;

	if (ctime < stat.ctime.tv_sec)
		ctime = stat.ctime.tv_sec;

	if (mtime < stat.mtime.tv_sec)
		mtime = stat.mtime.tv_sec;

	i_size_write(inode, stat.size);
	inode->i_blocks = stat.blocks;

	inode->i_atime.tv_sec = atime;
	inode->i_mtime.tv_sec = mtime;
	inode->i_ctime.tv_sec = ctime;

	ll_inode_size_unlock(inode);
out:
	pcc_io_fini(inode);
	return rc;
}

ssize_t pcc_file_splice_read(struct file *in_file, loff_t *ppos,
			     struct pipe_inode_info *pipe,
			     size_t count, unsigned int flags,
			     bool *cached)
{
	struct inode *inode = file_inode(in_file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(in_file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	ssize_t result;

	*cached = false;
	if (!pcc_file)
		return 0;

	if (!file_inode(pcc_file)->i_fop->splice_read)
		return -ENOTSUPP;

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	result = file_inode(pcc_file)->i_fop->splice_read(pcc_file,
							  ppos, pipe, count,
							  flags);

	pcc_io_fini(inode);
	return result;
}

int pcc_fsync(struct file *file, loff_t start, loff_t end,
	      int datasync, bool *cached)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	int rc;

	if (!pcc_file) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	rc = file_inode(pcc_file)->i_fop->fsync(pcc_file,
						start, end, datasync);

	pcc_io_fini(inode);
	return rc;
}

int pcc_file_mmap(struct file *file, struct vm_area_struct *vma,
		  bool *cached)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	struct pcc_inode *pcci;
	int rc = 0;

	if (!pcc_file || !file_inode(pcc_file)->i_fop->mmap) {
		*cached = false;
		return 0;
	}

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 1);
		*cached = true;
		vma->vm_file = pcc_file;
		rc = file_inode(pcc_file)->i_fop->mmap(pcc_file, vma);
		vma->vm_file = file;
		/* Save the vm ops of backend PCC */
		vma->vm_private_data = (void *)vma->vm_ops;
	} else {
		*cached = false;
	}
	pcc_inode_unlock(inode);

	return rc;
}

void pcc_vm_open(struct vm_area_struct *vma)
{
	struct pcc_inode *pcci;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	const struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->open)
		return;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		vma->vm_file = pcc_file;
		pcc_vm_ops->open(vma);
		vma->vm_file = file;
	}
	pcc_inode_unlock(inode);
}

void pcc_vm_close(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	const struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->close)
		return;

	pcc_inode_lock(inode);
	/* Layout lock maybe revoked here */
	vma->vm_file = pcc_file;
	pcc_vm_ops->close(vma);
	vma->vm_file = file;
	pcc_inode_unlock(inode);
}

int pcc_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
		     bool *cached)
{
	struct page *page = vmf->page;
	struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	const struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;
	int rc;

	if (!pcc_file || !pcc_vm_ops) {
		*cached = false;
		return 0;
	}

	if (!pcc_vm_ops->page_mkwrite &&
	    page->mapping == pcc_file->f_mapping) {
		CDEBUG(D_MMAP,
		       "%s: PCC backend fs not support ->page_mkwrite()\n",
		       ll_i2sbi(inode)->ll_fsname);
		pcc_ioctl_detach(inode, PCC_DETACH_OPT_NONE);
		up_read(&mm->mmap_sem);
		*cached = true;
		return VM_FAULT_RETRY | VM_FAULT_NOPAGE;
	}
	/* Pause to allow for a race with concurrent detach */
	OBD_FAIL_TIMEOUT(OBD_FAIL_LLITE_PCC_MKWRITE_PAUSE, cfs_fail_val);

	pcc_io_init(inode, cached);
	if (!*cached) {
		/* This happens when the file is detached from PCC after got
		 * the fault page via ->fault() on the inode of the PCC copy.
		 * Here it can not simply fall back to normal Lustre I/O path.
		 * The reason is that the address space of fault page used by
		 * ->page_mkwrite() is still the one of PCC inode. In the
		 * normal Lustre ->page_mkwrite() I/O path, it will be wrongly
		 * handled as the address space of the fault page is not
		 * consistent with the one of the Lustre inode (though the
		 * fault page was truncated).
		 * As the file is detached from PCC, the fault page must
		 * be released frist, and retry the mmap write (->fault() and
		 * ->page_mkwrite).
		 * We use an ugly and tricky method by returning
		 * VM_FAULT_NOPAGE | VM_FAULT_RETRY to the caller
		 * __do_page_fault and retry the memory fault handling.
		 */
		if (page->mapping == pcc_file->f_mapping) {
			*cached = true;
			up_read(&mm->mmap_sem);
			return VM_FAULT_RETRY | VM_FAULT_NOPAGE;
		}

		return 0;
	}

	/*
	 * This fault injection can also be used to simulate -ENOSPC and
	 * -EDQUOT failure of underlying PCC backend fs.
	 */
	if (OBD_FAIL_CHECK(OBD_FAIL_LLITE_PCC_DETACH_MKWRITE)) {
		pcc_io_fini(inode);
		pcc_ioctl_detach(inode, PCC_DETACH_OPT_NONE);
		up_read(&mm->mmap_sem);
		return VM_FAULT_RETRY | VM_FAULT_NOPAGE;
	}

	vma->vm_file = pcc_file;
	rc = pcc_vm_ops->page_mkwrite(vmf);
	vma->vm_file = file;

	pcc_io_fini(inode);
	return rc;
}

int pcc_fault(struct vm_area_struct *vma, struct vm_fault *vmf,
	      bool *cached)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	const struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;
	int rc;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->fault) {
		*cached = false;
		return 0;
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		return 0;

	vma->vm_file = pcc_file;
	rc = pcc_vm_ops->fault(vmf);
	vma->vm_file = file;

	pcc_io_fini(inode);
	return rc;
}

static void pcc_layout_wait(struct pcc_inode *pcci)
{
	if (atomic_read(&pcci->pcci_active_ios) > 0)
		CDEBUG(D_CACHE, "Waiting for IO completion: %d\n",
		       atomic_read(&pcci->pcci_active_ios));
	wait_event_idle(pcci->pcci_waitq,
			atomic_read(&pcci->pcci_active_ios) == 0);
}

static void __pcc_layout_invalidate(struct pcc_inode *pcci)
{
	pcci->pcci_type = LU_PCC_NONE;
	pcc_layout_gen_set(pcci, CL_LAYOUT_GEN_NONE);
	pcc_layout_wait(pcci);
}

void pcc_layout_invalidate(struct inode *inode)
{
	struct pcc_inode *pcci;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);
		__pcc_layout_invalidate(pcci);

		CDEBUG(D_CACHE, "Invalidate "DFID" layout gen %d\n",
		       PFID(&ll_i2info(inode)->lli_fid), pcci->pcci_layout_gen);

		pcc_inode_put(pcci);
	}
	pcc_inode_unlock(inode);
}

static int pcc_inode_remove(struct inode *inode, struct dentry *pcc_dentry)
{
	int rc;

	rc = vfs_unlink(pcc_dentry->d_parent->d_inode, pcc_dentry, NULL);
	if (rc)
		CWARN("%s: failed to unlink PCC file %.*s, rc = %d\n",
		      ll_i2sbi(inode)->ll_fsname, pcc_dentry->d_name.len,
		      pcc_dentry->d_name.name, rc);

	return rc;
}

/* Create directory under base if directory does not exist */
static struct dentry *
pcc_mkdir(struct dentry *base, const char *name, umode_t mode)
{
	int rc;
	struct dentry *dentry;
	struct inode *dir = base->d_inode;

	inode_lock(dir);
	dentry = lookup_one_len(name, base, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_is_positive(dentry))
		goto out;

	rc = vfs_mkdir(dir, dentry, mode);
	if (rc) {
		dput(dentry);
		dentry = ERR_PTR(rc);
		goto out;
	}
out:
	inode_unlock(dir);
	return dentry;
}

static struct dentry *
pcc_mkdir_p(struct dentry *root, char *path, umode_t mode)
{
	char *ptr, *entry_name;
	struct dentry *parent;
	struct dentry *child = ERR_PTR(-EINVAL);

	ptr = path;
	while (*ptr == '/')
		ptr++;

	entry_name = ptr;
	parent = dget(root);
	while ((ptr = strchr(ptr, '/')) != NULL) {
		*ptr = '\0';
		child = pcc_mkdir(parent, entry_name, mode);
		*ptr = '/';
		dput(parent);
		if (IS_ERR(child))
			break;

		parent = child;
		ptr++;
		entry_name = ptr;
	}

	return child;
}

/* Create file under base. If file already exist, return failure */
static struct dentry *
pcc_create(struct dentry *base, const char *name, umode_t mode)
{
	int rc;
	struct dentry *dentry;
	struct inode *dir = base->d_inode;

	inode_lock(dir);
	dentry = lookup_one_len(name, base, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_is_positive(dentry))
		goto out;

	rc = vfs_create(dir, dentry, mode, false);
	if (rc) {
		dput(dentry);
		dentry = ERR_PTR(rc);
		goto out;
	}
out:
	inode_unlock(dir);
	return dentry;
}

static int __pcc_inode_create(struct pcc_dataset *dataset,
			      struct lu_fid *fid,
			      struct dentry **dentry)
{
	char *path;
	struct dentry *base;
	struct dentry *child;
	int rc = 0;

	path = kzalloc(MAX_PCC_DATABASE_PATH, GFP_NOFS);
	if (!path)
		return -ENOMEM;

	pcc_fid2dataset_path(path, MAX_PCC_DATABASE_PATH, fid);

	base = pcc_mkdir_p(dataset->pccd_path.dentry, path, 0);
	if (IS_ERR(base)) {
		rc = PTR_ERR(base);
		goto out;
	}

	snprintf(path, MAX_PCC_DATABASE_PATH, DFID_NOBRACE, PFID(fid));
	child = pcc_create(base, path, 0);
	if (IS_ERR(child)) {
		rc = PTR_ERR(child);
		goto out_base;
	}
	*dentry = child;

out_base:
	dput(base);
out:
	kfree(path);
	return rc;
}

/* TODO: Set the project ID for PCC copy */
int pcc_inode_store_ugpid(struct dentry *dentry, kuid_t uid, kgid_t gid)
{
	struct inode *inode = dentry->d_inode;
	struct iattr attr;
	int rc;

	attr.ia_valid = ATTR_UID | ATTR_GID;
	attr.ia_uid = uid;
	attr.ia_gid = gid;

	inode_lock(inode);
	rc = notify_change(dentry, &attr, NULL);
	inode_unlock(inode);

	return rc;
}

int pcc_inode_create(struct super_block *sb, struct pcc_dataset *dataset,
		     struct lu_fid *fid, struct dentry **pcc_dentry)
{
	const struct cred *old_cred;
	int rc;

	old_cred = override_creds(pcc_super_cred(sb));
	rc = __pcc_inode_create(dataset, fid, pcc_dentry);
	revert_creds(old_cred);
	return rc;
}

int pcc_inode_create_fini(struct pcc_dataset *dataset, struct inode *inode,
			  struct dentry *pcc_dentry)
{
	const struct cred *old_cred;
	struct pcc_inode *pcci;
	int rc = 0;

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	pcc_inode_lock(inode);
	LASSERT(!ll_i2pcci(inode));
	pcci = kmem_cache_zalloc(pcc_inode_slab, GFP_NOFS);
	if (!pcci) {
		rc = -ENOMEM;
		goto out_put;
	}

	rc = pcc_inode_store_ugpid(pcc_dentry, old_cred->suid,
				   old_cred->sgid);
	if (rc)
		goto out_put;

	pcc_inode_init(pcci, ll_i2info(inode));
	pcc_inode_attach_init(dataset, pcci, pcc_dentry, LU_PCC_READWRITE);

	rc = pcc_layout_xattr_set(pcci, 0);
	if (rc) {
		(void) pcc_inode_remove(inode, pcci->pcci_path.dentry);
		pcc_inode_put(pcci);
		goto out_unlock;
	}

	/* Set the layout generation of newly created file with 0 */
	pcc_layout_gen_set(pcci, 0);

out_put:
	if (rc) {
		(void) pcc_inode_remove(inode, pcc_dentry);
		dput(pcc_dentry);

		kmem_cache_free(pcc_inode_slab, pcci);
	}
out_unlock:
	pcc_inode_unlock(inode);
	revert_creds(old_cred);

	return rc;
}

static int pcc_filp_write(struct file *filp, const void *buf, ssize_t count,
			  loff_t *offset)
{
	while (count > 0) {
		ssize_t size;

		size = kernel_write(filp, buf, count, offset);
		if (size < 0)
			return size;
		count -= size;
		buf += size;
	}
	return 0;
}

static int pcc_copy_data(struct file *src, struct file *dst)
{
	int rc = 0;
	ssize_t rc2;
	loff_t pos, offset = 0;
	size_t buf_len = 1048576;
	void *buf;

	buf = kvzalloc(buf_len, GFP_NOFS);
	if (!buf)
		return -ENOMEM;

	while (1) {
		pos = offset;
		rc2 = kernel_read(src, buf, buf_len, &pos);
		if (rc2 < 0) {
			rc = rc2;
			goto out_free;
		} else if (rc2 == 0)
			break;

		pos = offset;
		rc = pcc_filp_write(dst, buf, rc2, &pos);
		if (rc < 0)
			goto out_free;
		offset += rc2;
	}

out_free:
	kvfree(buf);
	return rc;
}

static int pcc_attach_allowed_check(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	int rc = 0;

	pcc_inode_lock(inode);
	if (lli->lli_pcc_state & PCC_STATE_FL_ATTACHING) {
		rc = -EBUSY;
		goto out_unlock;
	}

	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		rc = -EEXIST;
		goto out_unlock;
	}

	lli->lli_pcc_state |= PCC_STATE_FL_ATTACHING;
out_unlock:
	pcc_inode_unlock(inode);
	return rc;
}

int pcc_readwrite_attach(struct file *file, struct inode *inode,
			 u32 archive_id)
{
	struct pcc_dataset *dataset;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	const struct cred *old_cred;
	struct dentry *dentry;
	struct file *pcc_filp;
	struct path path;
	int rc;

	rc = pcc_attach_allowed_check(inode);
	if (rc)
		return rc;

	dataset = pcc_dataset_get(&ll_i2sbi(inode)->ll_pcc_super,
				  LU_PCC_READWRITE, archive_id);
	if (!dataset)
		return -ENOENT;

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = __pcc_inode_create(dataset, &lli->lli_fid, &dentry);
	if (rc) {
		revert_creds(old_cred);
		goto out_dataset_put;
	}

	path.mnt = dataset->pccd_path.mnt;
	path.dentry = dentry;
	pcc_filp = dentry_open(&path, O_TRUNC | O_WRONLY | O_LARGEFILE,
			       current_cred());
	if (IS_ERR_OR_NULL(pcc_filp)) {
		rc = pcc_filp ? PTR_ERR(pcc_filp) : -EINVAL;
		revert_creds(old_cred);
		goto out_dentry;
	}

	rc = pcc_inode_store_ugpid(dentry, old_cred->uid, old_cred->gid);
	revert_creds(old_cred);
	if (rc)
		goto out_fput;

	rc = pcc_copy_data(file, pcc_filp);
	if (rc)
		goto out_fput;

	/* Pause to allow for a race with concurrent HSM remove */
	OBD_FAIL_TIMEOUT(OBD_FAIL_LLITE_PCC_ATTACH_PAUSE, cfs_fail_val);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	LASSERT(!pcci);
	pcci = kmem_cache_zalloc(pcc_inode_slab, GFP_NOFS);
	if (!pcci) {
		rc = -ENOMEM;
		goto out_unlock;
	}

	pcc_inode_init(pcci, lli);
	pcc_inode_attach_init(dataset, pcci, dentry, LU_PCC_READWRITE);
out_unlock:
	pcc_inode_unlock(inode);
out_fput:
	fput(pcc_filp);
out_dentry:
	if (rc) {
		old_cred = override_creds(pcc_super_cred(inode->i_sb));
		(void) pcc_inode_remove(inode, dentry);
		revert_creds(old_cred);
		dput(dentry);
	}
out_dataset_put:
	pcc_dataset_put(dataset);
	return rc;
}

int pcc_readwrite_attach_fini(struct file *file, struct inode *inode,
			      u32 gen, bool lease_broken, int rc,
			      bool attached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	const struct cred *old_cred;
	struct pcc_inode *pcci;
	u32 gen2;

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	lli->lli_pcc_state &= ~PCC_STATE_FL_ATTACHING;
	if (rc || lease_broken) {
		if (attached && pcci)
			pcc_inode_put(pcci);

		goto out_unlock;
	}

	/* PCC inode may be released due to layout lock revocatioin */
	if (!pcci) {
		rc = -ESTALE;
		goto out_unlock;
	}

	LASSERT(attached);
	rc = pcc_layout_xattr_set(pcci, gen);
	if (rc)
		goto out_put;

	rc = ll_layout_refresh(inode, &gen2);
	if (!rc) {
		if (gen2 == gen) {
			pcc_layout_gen_set(pcci, gen);
		} else {
			CDEBUG(D_CACHE,
			       DFID" layout changed from %d to %d.\n",
			       PFID(ll_inode2fid(inode)), gen, gen2);
			rc = -ESTALE;
			goto out_put;
		}
	}

out_put:
	if (rc) {
		(void) pcc_inode_remove(inode, pcci->pcci_path.dentry);
		pcc_inode_put(pcci);
	}
out_unlock:
	pcc_inode_unlock(inode);
	revert_creds(old_cred);
	return rc;
}

static int pcc_hsm_remove(struct inode *inode)
{
	struct hsm_user_request *hur;
	u32 gen;
	int len;
	int rc;

	rc = ll_layout_restore(inode, 0, OBD_OBJECT_EOF);
	if (rc) {
		CDEBUG(D_CACHE, DFID" RESTORE failure: %d\n",
		       PFID(&ll_i2info(inode)->lli_fid), rc);
		return rc;
	}

	ll_layout_refresh(inode, &gen);

	len = sizeof(struct hsm_user_request) +
	      sizeof(struct hsm_user_item);
	hur = kzalloc(len, GFP_NOFS);
	if (!hur)
		return -ENOMEM;

	hur->hur_request.hr_action = HUA_REMOVE;
	hur->hur_request.hr_archive_id = 0;
	hur->hur_request.hr_flags = 0;
	memcpy(&hur->hur_user_item[0].hui_fid, &ll_i2info(inode)->lli_fid,
	       sizeof(hur->hur_user_item[0].hui_fid));
	hur->hur_user_item[0].hui_extent.offset = 0;
	hur->hur_user_item[0].hui_extent.length = OBD_OBJECT_EOF;
	hur->hur_request.hr_itemcount = 1;
	rc = obd_iocontrol(LL_IOC_HSM_REQUEST, ll_i2sbi(inode)->ll_md_exp,
			   len, hur, NULL);
	if (rc)
		CDEBUG(D_CACHE, DFID" HSM REMOVE failure: %d\n",
		       PFID(&ll_i2info(inode)->lli_fid), rc);

	kfree(hur);
	return rc;
}

int pcc_ioctl_detach(struct inode *inode, u32 opt)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	bool hsm_remove = false;
	int rc = 0;

	pcc_inode_lock(inode);
	pcci = lli->lli_pcc_inode;
	if (!pcci || lli->lli_pcc_state & PCC_STATE_FL_ATTACHING ||
	    !pcc_inode_has_layout(pcci))
		goto out_unlock;

	LASSERT(atomic_read(&pcci->pcci_refcount) > 0);

	if (pcci->pcci_type == LU_PCC_READWRITE) {
		if (opt == PCC_DETACH_OPT_UNCACHE)
			hsm_remove = true;

		__pcc_layout_invalidate(pcci);
		pcc_inode_put(pcci);
	}

out_unlock:
	pcc_inode_unlock(inode);
	if (hsm_remove) {
		const struct cred *old_cred;

		old_cred = override_creds(pcc_super_cred(inode->i_sb));
		rc = pcc_hsm_remove(inode);
		revert_creds(old_cred);
	}

	return rc;
}

int pcc_ioctl_state(struct file *file, struct inode *inode,
		    struct lu_pcc_state *state)
{
	int rc = 0;
	int count;
	char *buf;
	char *path;
	int buf_len = sizeof(state->pccs_path);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct pcc_inode *pcci;

	if (buf_len <= 0)
		return -EINVAL;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (!pcci) {
		state->pccs_type = LU_PCC_NONE;
		goto out_unlock;
	}

	count = atomic_read(&pcci->pcci_refcount);
	if (count == 0) {
		state->pccs_type = LU_PCC_NONE;
		state->pccs_open_count = 0;
		goto out_unlock;
	}

	if (pcc_inode_has_layout(pcci))
		count--;
	if (pccf->pccf_file)
		count--;
	state->pccs_type = pcci->pcci_type;
	state->pccs_open_count = count;
	state->pccs_flags = ll_i2info(inode)->lli_pcc_state;
	path = dentry_path_raw(pcci->pcci_path.dentry, buf, buf_len);
	if (IS_ERR(path)) {
		rc = PTR_ERR(path);
		goto out_unlock;
	}

	if (strlcpy(state->pccs_path, path, buf_len) >= buf_len) {
		rc = -ENAMETOOLONG;
		goto out_unlock;
	}

out_unlock:
	pcc_inode_unlock(inode);
	kfree(buf);
	return rc;
}

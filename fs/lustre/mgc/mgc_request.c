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
 * lustre/mgc/mgc_request.c
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MGC
#define D_MGC D_CONFIG /*|D_WARNING*/

#include <linux/module.h>
#include <linux/random.h>

#include <lprocfs_status.h>
#include <lustre_dlm.h>
#include <lustre_disk.h>
#include <lustre_log.h>
#include <lustre_swab.h>
#include <obd_class.h>

#include "mgc_internal.h"

static int mgc_name2resid(char *name, int len, struct ldlm_res_id *res_id,
			  enum mgs_cfg_type type)
{
	u64 resname = 0;

	if (len > sizeof(resname)) {
		CERROR("name too long: %s\n", name);
		return -EINVAL;
	}
	if (len <= 0) {
		CERROR("missing name: %s\n", name);
		return -EINVAL;
	}
	memcpy(&resname, name, len);

	/* Always use the same endianness for the resid */
	memset(res_id, 0, sizeof(*res_id));
	res_id->name[0] = cpu_to_le64(resname);
	/* XXX: unfortunately, sptlprc and config llog share one lock */
	switch (type) {
	case MGS_CFG_T_CONFIG:
	case MGS_CFG_T_SPTLRPC:
		resname = 0;
		break;
	case MGS_CFG_T_RECOVER:
	case MGS_CFG_T_PARAMS:
		resname = type;
		break;
	default:
		LBUG();
	}
	res_id->name[1] = cpu_to_le64(resname);
	CDEBUG(D_MGC, "log %s to resid %#llx/%#llx (%.8s)\n", name,
	       res_id->name[0], res_id->name[1], (char *)&res_id->name[0]);
	return 0;
}

int mgc_fsname2resid(char *fsname, struct ldlm_res_id *res_id,
		     enum mgs_cfg_type type)
{
	/* fsname is at most 8 chars long, maybe contain "-".
	 * e.g. "lustre", "SUN-000"
	 */
	return mgc_name2resid(fsname, strlen(fsname), res_id, type);
}
EXPORT_SYMBOL(mgc_fsname2resid);

static int mgc_logname2resid(char *logname, struct ldlm_res_id *res_id,
			     enum mgs_cfg_type type)
{
	char *name_end;
	int len;

	/* logname consists of "fsname-nodetype".
	 * e.g. "lustre-MDT0001", "SUN-000-client"
	 * there is an exception: llog "params"
	 */
	name_end = strrchr(logname, '-');
	if (!name_end)
		len = strlen(logname);
	else
		len = name_end - logname;
	return mgc_name2resid(logname, len, res_id, type);
}

/********************** config llog list **********************/
static LIST_HEAD(config_llog_list);
static DEFINE_SPINLOCK(config_list_lock);	/* protects config_llog_list */

/* Take a reference to a config log */
static int config_log_get(struct config_llog_data *cld)
{
	atomic_inc(&cld->cld_refcount);
	CDEBUG(D_INFO, "log %s (%p) refs %d\n", cld->cld_logname, cld,
	       atomic_read(&cld->cld_refcount));
	return 0;
}

/* Drop a reference to a config log.  When no longer referenced,
 * we can free the config log data
 */
static void config_log_put(struct config_llog_data *cld)
{
	if (!cld)
		return;

	CDEBUG(D_INFO, "log %s(%p) refs %d\n", cld->cld_logname, cld,
	       atomic_read(&cld->cld_refcount));
	LASSERT(atomic_read(&cld->cld_refcount) > 0);

	/* spinlock to make sure no item with 0 refcount in the list */
	if (atomic_dec_and_lock(&cld->cld_refcount, &config_list_lock)) {
		list_del(&cld->cld_list_chain);
		spin_unlock(&config_list_lock);

		CDEBUG(D_MGC, "dropping config log %s\n", cld->cld_logname);

		config_log_put(cld->cld_recover);
		config_log_put(cld->cld_params);
		config_log_put(cld->cld_sptlrpc);
		if (cld_is_sptlrpc(cld)) {
			cld->cld_stopping = 1;
			sptlrpc_conf_log_stop(cld->cld_logname);
		}

		class_export_put(cld->cld_mgcexp);
		kfree(cld);
	}
}

/* Find a config log by name */
static
struct config_llog_data *config_log_find(char *logname,
					 struct config_llog_instance *cfg)
{
	struct config_llog_data *cld;
	struct config_llog_data *found = NULL;
	void *instance;

	LASSERT(logname);

	instance = cfg ? cfg->cfg_instance : NULL;
	spin_lock(&config_list_lock);
	list_for_each_entry(cld, &config_llog_list, cld_list_chain) {
		/* check if instance equals */
		if (instance != cld->cld_cfg.cfg_instance)
			continue;

		/* instance may be NULL, should check name */
		if (strcmp(logname, cld->cld_logname) == 0) {
			found = cld;
			config_log_get(found);
			break;
		}
	}
	spin_unlock(&config_list_lock);
	return found;
}

static
struct config_llog_data *do_config_log_add(struct obd_device *obd,
					   char *logname,
					   enum mgs_cfg_type type,
					   struct config_llog_instance *cfg,
					   struct super_block *sb)
{
	struct config_llog_data *cld;
	int rc;

	CDEBUG(D_MGC, "do adding config log %s:%p\n", logname,
	       cfg ? cfg->cfg_instance : NULL);

	cld = kzalloc(sizeof(*cld) + strlen(logname) + 1, GFP_NOFS);
	if (!cld)
		return ERR_PTR(-ENOMEM);

	rc = mgc_logname2resid(logname, &cld->cld_resid, type);
	if (rc) {
		kfree(cld);
		return ERR_PTR(rc);
	}

	strcpy(cld->cld_logname, logname);
	if (cfg)
		cld->cld_cfg = *cfg;
	else
		cld->cld_cfg.cfg_callback = class_config_llog_handler;
	mutex_init(&cld->cld_lock);
	cld->cld_cfg.cfg_last_idx = 0;
	cld->cld_cfg.cfg_flags = 0;
	cld->cld_cfg.cfg_sb = sb;
	cld->cld_type = type;
	atomic_set(&cld->cld_refcount, 1);

	/* Keep the mgc around until we are done */
	cld->cld_mgcexp = class_export_get(obd->obd_self_export);

	if (cld_is_sptlrpc(cld))
		sptlrpc_conf_log_start(logname);

	spin_lock(&config_list_lock);
	list_add(&cld->cld_list_chain, &config_llog_list);
	spin_unlock(&config_list_lock);

	if (cld_is_sptlrpc(cld)) {
		rc = mgc_process_log(obd, cld);
		if (rc && rc != -ENOENT)
			CERROR("failed processing sptlrpc log: %d\n", rc);
	}

	return cld;
}

static struct config_llog_data *
config_recover_log_add(struct obd_device *obd, char *fsname,
		       struct config_llog_instance *cfg,
		       struct super_block *sb)
{
	struct config_llog_instance lcfg = *cfg;
	struct config_llog_data *cld;
	char logname[32];

	/* we have to use different llog for clients and mdts for cmd
	 * where only clients are notified if one of cmd server restarts
	 */
	LASSERT(strlen(fsname) < sizeof(logname) / 2);
	LASSERT(lcfg.cfg_instance);
	scnprintf(logname, sizeof(logname), "%s-cliir", fsname);

	cld = do_config_log_add(obd, logname, MGS_CFG_T_RECOVER, &lcfg, sb);
	return cld;
}

static struct config_llog_data *
config_log_find_or_add(struct obd_device *obd, char *logname,
		       struct super_block *sb, enum mgs_cfg_type type,
		       struct config_llog_instance *cfg)
{
	struct config_llog_instance lcfg = *cfg;
	struct config_llog_data	*cld;

	lcfg.cfg_instance = sb ? (void *)sb : (void *)obd;

	cld = config_log_find(logname, &lcfg);
	if (unlikely(cld))
		return cld;

	return do_config_log_add(obd, logname, type, &lcfg, sb);
}

/** Add this log to the list of active logs watched by an MGC.
 * Active means we're watching for updates.
 * We have one active log per "mount" - client instance or servername.
 * Each instance may be at a different point in the log.
 */
static struct config_llog_data *
config_log_add(struct obd_device *obd, char *logname,
	       struct config_llog_instance *cfg, struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct config_llog_data *cld;
	struct config_llog_data *sptlrpc_cld = NULL;
	struct config_llog_data *params_cld = NULL;
	struct config_llog_data *recover_cld = NULL;
	char seclogname[32];
	char *ptr;
	int rc;

	CDEBUG(D_MGC, "adding config log %s:%p\n", logname, cfg->cfg_instance);

	/*
	 * for each regular log, the depended sptlrpc log name is
	 * <fsname>-sptlrpc. multiple regular logs may share one sptlrpc log.
	 */
	ptr = strrchr(logname, '-');
	if (!ptr || ptr - logname > 8) {
		CERROR("logname %s is too long\n", logname);
		return ERR_PTR(-EINVAL);
	}

	memcpy(seclogname, logname, ptr - logname);
	strcpy(seclogname + (ptr - logname), "-sptlrpc");

	if (cfg->cfg_sub_clds & CONFIG_SUB_SPTLRPC) {
		sptlrpc_cld = config_log_find_or_add(obd, seclogname, NULL,
						     MGS_CFG_T_SPTLRPC, cfg);
		if (IS_ERR(sptlrpc_cld)) {
			CERROR("can't create sptlrpc log: %s\n", seclogname);
			rc = PTR_ERR(sptlrpc_cld);
			goto out_err;
		}
	}

	if (cfg->cfg_sub_clds & CONFIG_SUB_PARAMS) {
		params_cld = config_log_find_or_add(obd, PARAMS_FILENAME, sb,
						    MGS_CFG_T_PARAMS, cfg);
		if (IS_ERR(params_cld)) {
			rc = PTR_ERR(params_cld);
			CERROR("%s: can't create params log: rc = %d\n",
			       obd->obd_name, rc);
			goto out_sptlrpc;
		}
	}

	cld = do_config_log_add(obd, logname, MGS_CFG_T_CONFIG, cfg, sb);
	if (IS_ERR(cld)) {
		CERROR("can't create log: %s\n", logname);
		rc = PTR_ERR(cld);
		goto out_params;
	}

	LASSERT(lsi->lsi_lmd);
	if (!test_bit(LMD_FLG_NOIR, lsi->lsi_lmd->lmd_flags) &&
	    cfg->cfg_sub_clds & CONFIG_SUB_RECOVER) {
		ptr = strrchr(seclogname, '-');
		if (ptr) {
			*ptr = 0;
		} else {
			CERROR("%s: sptlrpc log name not correct, %s: rc = %d\n",
			       obd->obd_name, seclogname, -EINVAL);
			rc = -EINVAL;
			goto out_cld;
		}
		recover_cld = config_recover_log_add(obd, seclogname, cfg, sb);
		if (IS_ERR(recover_cld)) {
			rc = PTR_ERR(recover_cld);
			goto out_cld;
		}
	}

	mutex_lock(&cld->cld_lock);
	cld->cld_recover = recover_cld;
	cld->cld_params = params_cld;
	cld->cld_sptlrpc = sptlrpc_cld;
	mutex_unlock(&cld->cld_lock);

	return cld;

out_cld:
	config_log_put(cld);

out_params:
	config_log_put(params_cld);

out_sptlrpc:
	config_log_put(sptlrpc_cld);

out_err:
	return ERR_PTR(rc);
}

DEFINE_MUTEX(llog_process_lock);

static inline void config_mark_cld_stop_nolock(struct config_llog_data *cld)
{
	spin_lock(&config_list_lock);
	cld->cld_stopping = 1;
	spin_unlock(&config_list_lock);

	CDEBUG(D_INFO, "lockh %#llx\n", cld->cld_lockh.cookie);
	if (!ldlm_lock_addref_try(&cld->cld_lockh, LCK_CR))
		ldlm_lock_decref_and_cancel(&cld->cld_lockh, LCK_CR);
}

static inline void config_mark_cld_stop(struct config_llog_data *cld)
{
	if (cld) {
		mutex_lock(&cld->cld_lock);
		config_mark_cld_stop_nolock(cld);
		mutex_unlock(&cld->cld_lock);
	}
}

/** Stop watching for updates on this log.
 */
static int config_log_end(char *logname, struct config_llog_instance *cfg)
{
	struct config_llog_data *cld;
	struct config_llog_data *cld_sptlrpc = NULL;
	struct config_llog_data *cld_params = NULL;
	struct config_llog_data *cld_recover = NULL;
	int rc = 0;

	cld = config_log_find(logname, cfg);
	if (!cld)
		return -ENOENT;

	mutex_lock(&cld->cld_lock);
	/*
	 * if cld_stopping is set, it means we didn't start the log thus
	 * not owning the start ref. this can happen after previous umount:
	 * the cld still hanging there waiting for lock cancel, and we
	 * remount again but failed in the middle and call log_end without
	 * calling start_log.
	 */
	if (unlikely(cld->cld_stopping)) {
		mutex_unlock(&cld->cld_lock);
		/* drop the ref from the find */
		config_log_put(cld);
		return rc;
	}

	cld_recover = cld->cld_recover;
	cld->cld_recover = NULL;
	cld_params = cld->cld_params;
	cld->cld_params = NULL;
	cld_sptlrpc = cld->cld_sptlrpc;
	cld->cld_sptlrpc = NULL;

	config_mark_cld_stop_nolock(cld);
	mutex_unlock(&cld->cld_lock);

	config_mark_cld_stop(cld_recover);
	config_log_put(cld_recover);
	config_mark_cld_stop(cld_params);
	config_log_put(cld_params);
	/* don't explicitly set cld_stopping on sptlrpc lock here, as other
	 * targets may be active, it will be done in config_log_put if necessary
	 */
	config_log_put(cld_sptlrpc);

	/* drop the ref from the find */
	config_log_put(cld);
	/* drop the start ref */
	config_log_put(cld);

	CDEBUG(D_MGC, "end config log %s (%d)\n", logname ? logname : "client",
	       rc);
	return rc;
}

int lprocfs_mgc_rd_ir_state(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_import *imp;
	struct obd_connect_data *ocd;
	struct config_llog_data *cld;
	int rc = 0;

	with_imp_locked(obd, imp, rc) {
		ocd = &imp->imp_connect_data;

		seq_printf(m, "imperative_recovery: %s\n",
			   OCD_HAS_FLAG(ocd, IMP_RECOV) ? "ENABLED" : "DISABLED");
	}
	if (rc)
		return rc;

	seq_puts(m, "client_state:\n");

	spin_lock(&config_list_lock);
	list_for_each_entry(cld, &config_llog_list, cld_list_chain) {
		if (!cld->cld_recover)
			continue;
		seq_printf(m, "    - { client: %s, nidtbl_version: %u }\n",
			   cld->cld_logname,
			   cld->cld_recover->cld_cfg.cfg_last_idx);
	}
	spin_unlock(&config_list_lock);

	return 0;
}

/* reenqueue any lost locks */
#define RQ_RUNNING	0x01
#define RQ_NOW		0x02
#define RQ_LATER	0x04
#define RQ_STOP		0x08
#define RQ_PRECLEANUP	0x10

static int rq_state;
static wait_queue_head_t rq_waitq;
static DECLARE_COMPLETION(rq_exit);
static DECLARE_COMPLETION(rq_start);

static void do_requeue(struct config_llog_data *cld)
{
	LASSERT(atomic_read(&cld->cld_refcount) > 0);

	/* Do not run mgc_process_log on a disconnected export or an
	 * export which is being disconnected. Take the client
	 * semaphore to make the check non-racy.
	 */
	down_read_nested(&cld->cld_mgcexp->exp_obd->u.cli.cl_sem,
			 OBD_CLI_SEM_MGC);

	if (cld->cld_mgcexp->exp_obd->u.cli.cl_conn_count != 0) {
		int rc;

		CDEBUG(D_MGC, "updating log %s\n", cld->cld_logname);
		rc = mgc_process_log(cld->cld_mgcexp->exp_obd, cld);
		if (rc && rc != -ENOENT)
			CERROR("failed processing log: %d\n", rc);
	} else {
		CDEBUG(D_MGC, "disconnecting, won't update log %s\n",
		       cld->cld_logname);
	}
	up_read(&cld->cld_mgcexp->exp_obd->u.cli.cl_sem);
}

static int mgc_requeue_thread(void *data)
{
	bool first = true;

	CDEBUG(D_MGC, "Starting requeue thread\n");

	/* Keep trying failed locks periodically */
	spin_lock(&config_list_lock);
	rq_state |= RQ_RUNNING;
	while (!(rq_state & RQ_STOP)) {
		struct config_llog_data *cld, *cld_prev;
		int to;

		/* Any new or requeued lostlocks will change the state */
		rq_state &= ~(RQ_NOW | RQ_LATER);
		spin_unlock(&config_list_lock);

		if (first) {
			first = false;
			complete(&rq_start);
		}

		/* Always wait a few seconds to allow the server who
		 * caused the lock revocation to finish its setup, plus some
		 * random so everyone doesn't try to reconnect at once.
		 */
		/* rand is centi-seconds, "to" is in centi-HZ */
		to = mgc_requeue_timeout_min == 0 ? 1 : mgc_requeue_timeout_min;
		to = mgc_requeue_timeout_min * HZ + prandom_u32_max(to * HZ);
		wait_event_idle_timeout(rq_waitq,
					rq_state & (RQ_STOP | RQ_PRECLEANUP),
					to);

		/*
		 * iterate & processing through the list. for each cld, process
		 * its depending sptlrpc cld firstly (if any) and then itself.
		 *
		 * it's guaranteed any item in the list must have
		 * reference > 0; and if cld_lostlock is set, at
		 * least one reference is taken by the previous enqueue.
		 */
		cld_prev = NULL;

		spin_lock(&config_list_lock);
		rq_state &= ~RQ_PRECLEANUP;
		list_for_each_entry(cld, &config_llog_list, cld_list_chain) {
			if (!cld->cld_lostlock || cld->cld_stopping)
				continue;

			/*
			 * hold reference to avoid being freed during
			 * subsequent processing.
			 */
			config_log_get(cld);
			cld->cld_lostlock = 0;
			spin_unlock(&config_list_lock);

			config_log_put(cld_prev);
			cld_prev = cld;

			if (likely(!(rq_state & RQ_STOP))) {
				do_requeue(cld);
				spin_lock(&config_list_lock);
			} else {
				spin_lock(&config_list_lock);
				break;
			}
		}
		spin_unlock(&config_list_lock);
		config_log_put(cld_prev);

		/* Wait a bit to see if anyone else needs a requeue */
		wait_event_idle(rq_waitq, rq_state & (RQ_NOW | RQ_STOP));
		spin_lock(&config_list_lock);
	}

	/* spinlock and while guarantee RQ_NOW and RQ_LATER are not set */
	rq_state &= ~RQ_RUNNING;
	spin_unlock(&config_list_lock);

	complete(&rq_exit);

	CDEBUG(D_MGC, "Ending requeue thread\n");
	return 0;
}

/* Add a cld to the list to requeue. Start the requeue thread if needed.
 * We are responsible for dropping the config log reference from here on out.
 */
static void mgc_requeue_add(struct config_llog_data *cld)
{
	bool wakeup = false;

	CDEBUG(D_INFO, "log %s: requeue (r=%d sp=%d st=%x)\n",
	       cld->cld_logname, atomic_read(&cld->cld_refcount),
	       cld->cld_stopping, rq_state);
	LASSERT(atomic_read(&cld->cld_refcount) > 0);

	/* lets cancel an existent lock to mark cld as "lostlock" */
	CDEBUG(D_INFO, "lockh %#llx\n", cld->cld_lockh.cookie);
	if (!ldlm_lock_addref_try(&cld->cld_lockh, LCK_CR))
		ldlm_lock_decref_and_cancel(&cld->cld_lockh, LCK_CR);

	mutex_lock(&cld->cld_lock);
	spin_lock(&config_list_lock);
	if (!(rq_state & RQ_STOP) && !cld->cld_stopping) {
		cld->cld_lostlock = 1;
		rq_state |= RQ_NOW;
		wakeup = true;
	}
	spin_unlock(&config_list_lock);
	mutex_unlock(&cld->cld_lock);
	if (wakeup)
		wake_up(&rq_waitq);
}

static int mgc_llog_init(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_ctxt *ctxt;
	int rc;

	/* setup only remote ctxt, the local disk context is switched per each
	 * filesystem during mgc_fs_setup()
	 */
	rc = llog_setup(env, obd, &obd->obd_olg, LLOG_CONFIG_REPL_CTXT, obd,
			&llog_client_ops);
	if (rc)
		return rc;

	ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
	LASSERT(ctxt);

	llog_initiator_connect(ctxt);
	llog_ctxt_put(ctxt);

	return 0;
}

static int mgc_llog_fini(const struct lu_env *env, struct obd_device *obd)
{
	struct llog_ctxt *ctxt;

	ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
	if (ctxt)
		llog_cleanup(env, ctxt);

	return 0;
}

static atomic_t mgc_count = ATOMIC_INIT(0);
static int mgc_precleanup(struct obd_device *obd)
{
	int rc = 0;
	int temp;

	if (atomic_dec_and_test(&mgc_count)) {
		LASSERT(rq_state & RQ_RUNNING);
		/* stop requeue thread */
		temp = RQ_STOP;
	} else {
		/* wakeup requeue thread to clean our cld */
		temp = RQ_NOW | RQ_PRECLEANUP;
	}

	spin_lock(&config_list_lock);
	rq_state |= temp;
	spin_unlock(&config_list_lock);
	wake_up(&rq_waitq);

	if (temp & RQ_STOP)
		wait_for_completion(&rq_exit);
	obd_cleanup_client_import(obd);

	rc = mgc_llog_fini(NULL, obd);
	if (rc)
		CERROR("failed to cleanup llogging subsystems\n");

	return rc;
}

static int mgc_cleanup(struct obd_device *obd)
{
	/* COMPAT_146 - old config logs may have added profiles we don't
	 * know about
	 */
	if (atomic_read(&obd->obd_type->typ_refcnt) <= 1)
		/* Only for the last mgc */
		class_del_profiles();

	lprocfs_obd_cleanup(obd);
	ptlrpcd_decref();

	return client_obd_cleanup(obd);
}

static int mgc_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct task_struct *task;
	int rc;

	rc = ptlrpcd_addref();
	if (rc < 0)
		goto err_noref;

	rc = client_obd_setup(obd, lcfg);
	if (rc)
		goto err_decref;

	rc = mgc_llog_init(NULL, obd);
	if (rc) {
		CERROR("failed to setup llogging subsystems\n");
		goto err_cleanup;
	}

	rc = mgc_tunables_init(obd);
	if (rc)
		goto err_sysfs;

	if (atomic_inc_return(&mgc_count) == 1) {
		rq_state = 0;
		init_waitqueue_head(&rq_waitq);

		/* start requeue thread */
		task = kthread_run(mgc_requeue_thread, NULL, "ll_cfg_requeue");
		if (IS_ERR(task)) {
			rc = PTR_ERR(task);
			CERROR("%s: cannot start requeue thread: rc = %d; no more log updates\n",
			       obd->obd_name, rc);
			goto err_sysfs;
		}
		/* rc is the task_struct pointer of mgc_requeue_thread. */
		rc = 0;
		wait_for_completion(&rq_start);
	}

	return rc;

err_sysfs:
	lprocfs_obd_cleanup(obd);
err_cleanup:
	client_obd_cleanup(obd);
err_decref:
	ptlrpcd_decref();
err_noref:
	return rc;
}

/* based on ll_mdc_blocking_ast */
static int mgc_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
			    void *data, int flag)
{
	struct lustre_handle lockh;
	struct config_llog_data *cld = data;
	int rc = 0;

	switch (flag) {
	case LDLM_CB_BLOCKING:
		/* mgs wants the lock, give it up... */
		LDLM_DEBUG(lock, "MGC blocking CB");
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		break;
	case LDLM_CB_CANCELING:
		/* We've given up the lock, prepare ourselves to update. */
		LDLM_DEBUG(lock, "MGC cancel CB");

		CDEBUG(D_MGC, "Lock res " DLDLMRES " (%.8s)\n",
		       PLDLMRES(lock->l_resource),
		       (char *)&lock->l_resource->lr_name.name[0]);

		if (!cld) {
			CDEBUG(D_INFO, "missing data, won't requeue\n");
			break;
		}

		/* held at mgc_process_log(). */
		LASSERT(atomic_read(&cld->cld_refcount) > 0);

		lock->l_ast_data = NULL;
		cld->cld_lockh.cookie = 0;
		/* Are we done with this log? */
		if (cld->cld_stopping) {
			CDEBUG(D_MGC, "log %s: stopping, won't requeue\n",
			       cld->cld_logname);
			config_log_put(cld);
			break;
		}
		/* Make sure not to re-enqueue when the mgc is stopping
		 * (we get called from client_disconnect_export)
		 */
		if (!lock->l_conn_export ||
		    !lock->l_conn_export->exp_obd->u.cli.cl_conn_count) {
			CDEBUG(D_MGC,
			       "log %.8s: disconnecting, won't requeue\n",
			       cld->cld_logname);
			config_log_put(cld);
			break;
		}

		/* Re-enqueue now */
		mgc_requeue_add(cld);
		config_log_put(cld);
		break;
	default:
		LBUG();
	}

	return rc;
}

/* Not sure where this should go... */
/* This is the timeout value for MGS_CONNECT request plus a ping interval, such
 * that we can have a chance to try the secondary MGS if any.
 */
#define  MGC_ENQUEUE_LIMIT (INITIAL_CONNECT_TIMEOUT + (AT_OFF ? 0 : at_min) \
				+ PING_INTERVAL)
#define  MGC_TARGET_REG_LIMIT 10
#define  MGC_SEND_PARAM_LIMIT 10

/* Take a config lock so we can get cancel notifications */
static int mgc_enqueue(struct obd_export *exp, u32 type,
		       union ldlm_policy_data *policy, u32 mode,
		       u64 *flags, void *bl_cb, void *cp_cb, void *gl_cb,
		       void *data, u32 lvb_len, void *lvb_swabber,
		       struct lustre_handle *lockh)
{
	struct config_llog_data *cld = data;
	struct ldlm_enqueue_info einfo = {
		.ei_type	= type,
		.ei_mode	= mode,
		.ei_cb_bl	= mgc_blocking_ast,
		.ei_cb_cp	= ldlm_completion_ast,
	};
	struct ptlrpc_request *req;
	int short_limit = cld_is_sptlrpc(cld);
	int rc;

	if (!exp)
		return -EBADR;

	CDEBUG(D_MGC, "Enqueue for %s (res %#llx)\n", cld->cld_logname,
	       cld->cld_resid.name[0]);

	/* We need a callback for every lockholder, so don't try to
	 * ldlm_lock_match (see rev 1.1.2.11.2.47)
	 */
	req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
					&RQF_LDLM_ENQUEUE, LUSTRE_DLM_VERSION,
					LDLM_ENQUEUE);
	if (!req)
		return -ENOMEM;

	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER, 0);
	ptlrpc_request_set_replen(req);

	/* Limit how long we will wait for the enqueue to complete */
	req->rq_delay_limit = short_limit ? 5 : MGC_ENQUEUE_LIMIT;
	rc = ldlm_cli_enqueue(exp, &req, &einfo, &cld->cld_resid, NULL, flags,
			      NULL, 0, LVB_T_NONE, lockh, 0);
	/* A failed enqueue should still call the mgc_blocking_ast,
	 * where it will be requeued if needed ("grant failed").
	 */
	ptlrpc_req_finished(req);
	return rc;
}

static void mgc_notify_active(struct obd_device *unused)
{
	/* wakeup mgc_requeue_thread to requeue mgc lock */
	spin_lock(&config_list_lock);
	rq_state |= RQ_NOW;
	spin_unlock(&config_list_lock);
	wake_up(&rq_waitq);

	/* TODO: Help the MGS rebuild nidtbl. -jay */
}

/* Send target_reg message to MGS */
static int mgc_target_register(struct obd_export *exp,
			       struct mgs_target_info *mti)
{
	struct ptlrpc_request *req;
	struct mgs_target_info *req_mti, *rep_mti;
	int rc;

	req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
					&RQF_MGS_TARGET_REG, LUSTRE_MGS_VERSION,
					MGS_TARGET_REG);
	if (!req)
		return -ENOMEM;

	req_mti = req_capsule_client_get(&req->rq_pill, &RMF_MGS_TARGET_INFO);
	if (!req_mti) {
		ptlrpc_req_finished(req);
		return -ENOMEM;
	}

	memcpy(req_mti, mti, sizeof(*req_mti));
	ptlrpc_request_set_replen(req);
	CDEBUG(D_MGC, "register %s\n", mti->mti_svname);
	/* Limit how long we will wait for the enqueue to complete */
	req->rq_delay_limit = MGC_TARGET_REG_LIMIT;

	rc = ptlrpc_queue_wait(req);
	if (!rc) {
		rep_mti = req_capsule_server_get(&req->rq_pill,
						 &RMF_MGS_TARGET_INFO);
		if (rep_mti)
			memcpy(mti, rep_mti, sizeof(*rep_mti));
	}
	if (!rc) {
		CDEBUG(D_MGC, "register %s got index = %d\n",
		       mti->mti_svname, mti->mti_stripe_index);
	}
	ptlrpc_req_finished(req);

	return rc;
}

static int mgc_set_info_async(const struct lu_env *env, struct obd_export *exp,
			      u32 keylen, void *key, u32 vallen,
			      void *val, struct ptlrpc_request_set *set)
{
	int rc = -EINVAL;

	/* Turn off initial_recov after we try all backup servers once */
	if (KEY_IS(KEY_INIT_RECOV_BACKUP)) {
		struct obd_import *imp = class_exp2cliimp(exp);
		int value;

		if (vallen != sizeof(int))
			return -EINVAL;
		value = *(int *)val;
		CDEBUG(D_MGC, "InitRecov %s %d/d%d:i%d:r%d:or%d:%s\n",
		       imp->imp_obd->obd_name, value,
		       imp->imp_deactive, imp->imp_invalid,
		       imp->imp_replayable, imp->imp_obd->obd_replayable,
		       ptlrpc_import_state_name(imp->imp_state));
		/* Resurrect the import immediately if
		 * 1. we previously got disconnected,
		 * 2. value > 1 (at the same node with MGS)
		 */
		if (imp->imp_state != LUSTRE_IMP_NEW || value > 1)
			ptlrpc_reconnect_import(imp);
		return 0;
	}
	if (KEY_IS(KEY_MGSSEC)) {
		struct client_obd *cli = &exp->exp_obd->u.cli;
		struct sptlrpc_flavor flvr;

		/*
		 * empty string means using current flavor, if which haven't
		 * been set yet, set it as null.
		 *
		 * if flavor has been set previously, check the asking flavor
		 * must match the existing one.
		 */
		if (vallen == 0) {
			if (cli->cl_flvr_mgc.sf_rpc != SPTLRPC_FLVR_INVALID)
				return 0;
			val = "null";
			vallen = 4;
		}

		rc = sptlrpc_parse_flavor(val, &flvr);
		if (rc) {
			CERROR("invalid sptlrpc flavor %s to MGS\n",
			       (char *)val);
			return rc;
		}

		/*
		 * caller already hold a mutex
		 */
		if (cli->cl_flvr_mgc.sf_rpc == SPTLRPC_FLVR_INVALID) {
			cli->cl_flvr_mgc = flvr;
		} else if (memcmp(&cli->cl_flvr_mgc, &flvr,
				  sizeof(flvr)) != 0) {
			char str[20];

			sptlrpc_flavor2name(&cli->cl_flvr_mgc,
					    str, sizeof(str));
			LCONSOLE_ERROR("asking sptlrpc flavor %s to MGS but currently %s is in use\n",
				       (char *)val, str);
			rc = -EPERM;
		}
		return rc;
	}

	return rc;
}

static int mgc_get_info(const struct lu_env *env, struct obd_export *exp,
			u32 keylen, void *key, u32 *vallen, void *val)
{
	int rc = -EINVAL;

	if (KEY_IS(KEY_CONN_DATA)) {
		struct obd_import *imp = class_exp2cliimp(exp);
		struct obd_connect_data *data = val;

		if (*vallen == sizeof(*data)) {
			*data = imp->imp_connect_data;
			rc = 0;
		}
	}

	return rc;
}

static int mgc_import_event(struct obd_device *obd,
			    struct obd_import *imp,
			    enum obd_import_event event)
{
	LASSERT(imp->imp_obd == obd);
	CDEBUG(D_MGC, "import event %#x\n", event);

	switch (event) {
	case IMP_EVENT_DISCON:
		/* MGC imports should not wait for recovery */
		if (OCD_HAS_FLAG(&imp->imp_connect_data, IMP_RECOV))
			ptlrpc_pinger_ir_down();
		break;
	case IMP_EVENT_INACTIVE:
		break;
	case IMP_EVENT_INVALIDATE: {
		struct ldlm_namespace *ns = obd->obd_namespace;

		ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);
		break;
	}
	case IMP_EVENT_ACTIVE:
		CDEBUG(D_INFO, "%s: Reactivating import\n", obd->obd_name);
		/* Clearing obd_no_recov allows us to continue pinging */
		obd->obd_no_recov = 0;
		mgc_notify_active(obd);
		if (OCD_HAS_FLAG(&imp->imp_connect_data, IMP_RECOV))
			ptlrpc_pinger_ir_up();
		break;
	case IMP_EVENT_OCD:
		break;
	case IMP_EVENT_DEACTIVATE:
	case IMP_EVENT_ACTIVATE:
		break;
	default:
		CERROR("Unknown import event %#x\n", event);
		LBUG();
	}
	return 0;
}

enum {
	CONFIG_READ_NRPAGES_INIT = 1 << (20 - PAGE_SHIFT),
	CONFIG_READ_NRPAGES      = 4
};

static int mgc_apply_recover_logs(struct obd_device *mgc,
				  struct config_llog_data *cld,
				  u64 max_version,
				  void *data, int datalen, bool mne_swab)
{
	struct config_llog_instance *cfg = &cld->cld_cfg;
	struct mgs_nidtbl_entry *entry;
	struct lustre_cfg *lcfg;
	struct lustre_cfg_bufs bufs;
	u64 prev_version = 0;
	char inst[MTI_NAME_MAXLEN + 1];
	char *buf;
	int bufsz;
	int pos;
	int rc = 0;
	int off = 0;
	unsigned long dynamic_nids;

	LASSERT(cfg->cfg_instance);
	LASSERT(cfg->cfg_sb == cfg->cfg_instance);

	/* get dynamic nids setting */
	dynamic_nids = mgc->obd_dynamic_nids;

	pos = snprintf(inst, sizeof(inst), "%px", cfg->cfg_instance);
	if (pos >= sizeof(inst))
		return -E2BIG;

	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	bufsz = PAGE_SIZE;
	pos = 0;

	while (datalen > 0) {
		int entry_len = sizeof(*entry);
		int is_ost;
		struct obd_device *obd;
		struct obd_import *imp;
		char *obdname;
		char *cname;
		char *params;
		char *uuid;
		size_t len;

		rc = -EINVAL;
		if (datalen < sizeof(*entry))
			break;

		entry = (typeof(entry))(data + off);

		/* sanity check */
		if (entry->mne_nid_type != 0) /* only support type 0 for ipv4 */
			break;
		if (entry->mne_nid_count == 0) /* at least one nid entry */
			break;
		if (entry->mne_nid_size != sizeof(lnet_nid_t))
			break;

		entry_len += entry->mne_nid_count * entry->mne_nid_size;
		if (datalen < entry_len) /* must have entry_len at least */
			break;

		/* Keep this swab for normal mixed endian handling. LU-1644 */
		if (mne_swab)
			lustre_swab_mgs_nidtbl_entry(entry);
		if (entry->mne_length > PAGE_SIZE) {
			CERROR("MNE too large (%u)\n", entry->mne_length);
			break;
		}

		if (entry->mne_length < entry_len)
			break;

		off += entry->mne_length;
		datalen -= entry->mne_length;
		if (datalen < 0)
			break;

		if (entry->mne_version > max_version) {
			CERROR("entry index(%lld) is over max_index(%lld)\n",
			       entry->mne_version, max_version);
			break;
		}

		if (prev_version >= entry->mne_version) {
			CERROR("index unsorted, prev %lld, now %lld\n",
			       prev_version, entry->mne_version);
			break;
		}
		prev_version = entry->mne_version;

		/*
		 * Write a string with format "nid::instance" to
		 * lustre/<osc|mdc>/<target>-<osc|mdc>-<instance>/import.
		 */

		is_ost = entry->mne_type == LDD_F_SV_TYPE_OST;
		memset(buf, 0, bufsz);
		obdname = buf;
		pos = 0;

		/* lustre-OST0001-osc-<instance #> */
		strcpy(obdname, cld->cld_logname);
		cname = strrchr(obdname, '-');
		if (!cname) {
			CERROR("mgc %s: invalid logname %s\n",
			       mgc->obd_name, obdname);
			break;
		}

		pos = cname - obdname;
		obdname[pos] = 0;
		pos += sprintf(obdname + pos, "-%s%04x",
				  is_ost ? "OST" : "MDT", entry->mne_index);

		cname = is_ost ? "osc" : "mdc",
		pos += snprintf(obdname + pos, bufsz, "-%s-%s", cname, inst);
		lustre_cfg_bufs_reset(&bufs, obdname);

		/* find the obd by obdname */
		obd = class_name2obd(obdname);
		if (!obd) {
			CDEBUG(D_INFO, "mgc %s: cannot find obdname %s\n",
			       mgc->obd_name, obdname);
			rc = 0;
			/* this is a safe race, when the ost is starting up...*/
			continue;
		}

		/* osc.import = "connection=<Conn UUID>::<target instance>" */
		++pos;
		params = buf + pos;
		pos += sprintf(params, "%s.import=%s", cname, "connection=");
		uuid = buf + pos;

		with_imp_locked(obd, imp, rc) {
			/* iterate all nids to find one */
			/* find uuid by nid */
			/* create import entries if they don't exist */
			rc = client_import_add_nids_to_conn(imp,
							    entry->u.nids,
							    entry->mne_nid_count,
							    (struct obd_uuid *)uuid);
			if (rc == -ENOENT && dynamic_nids) {
				/* create a new connection for this import */
				char *primary_nid =
					libcfs_nid2str(entry->u.nids[0]);
				int prim_nid_len = strlen(primary_nid) + 1;
				struct obd_uuid server_uuid;

				if (prim_nid_len > UUID_MAX)
					goto fail;
				strncpy(server_uuid.uuid, primary_nid,
					prim_nid_len);

				CDEBUG(D_INFO, "Adding a connection for %s\n",
				       primary_nid);

				rc = client_import_dyn_add_conn(imp,
								&server_uuid,
								entry->u.nids[0],
								1);
				if (rc < 0) {
					CERROR("%s: Failed to add new connection with NID '%s' to import: rc = %d\n",
					       obd->obd_name, primary_nid, rc);
					goto fail;
				}
				rc = client_import_add_nids_to_conn(imp,
								    entry->u.nids,
								    entry->mne_nid_count,
								    (struct obd_uuid *)uuid);
				if (rc < 0) {
					CERROR("%s: failed to lookup UUID: rc = %d\n",
					       obd->obd_name, rc);
					goto fail;
				}
			}
fail:;
		}
		if (rc == -ENODEV) {
			/* client does not connect to the OST yet */
			rc = 0;
			continue;
		}

		if (rc < 0 && rc != -ENOSPC) {
			CERROR("mgc: cannot find UUID by nid '%s': rc = %d\n",
			       libcfs_nid2str(entry->u.nids[0]), rc);
			break;
		}

		CDEBUG(D_INFO, "Found UUID '%s' by NID '%s'\n",
		       uuid, libcfs_nid2str(entry->u.nids[0]));

		pos += strlen(uuid);
		pos += sprintf(buf + pos, "::%u", entry->mne_instance);
		LASSERT(pos < bufsz);

		lustre_cfg_bufs_set_string(&bufs, 1, params);

		len = lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen);
		lcfg = kzalloc(len, GFP_NOFS);
		if (!lcfg) {
			rc = -ENOMEM;
			break;
		}
		lustre_cfg_init(lcfg, LCFG_PARAM, &bufs);

		CDEBUG(D_INFO, "ir apply logs %lld/%lld for %s -> %s\n",
		       prev_version, max_version, obdname, params);

		rc = class_process_config(lcfg);
		kfree(lcfg);
		if (rc)
			CDEBUG(D_INFO, "process config for %s error %d\n",
			       obdname, rc);

		/* continue, even one with error */
	}

	kfree(buf);
	return rc;
}

/**
 * This function is called if this client was notified for target restarting
 * by the MGS. A CONFIG_READ RPC is going to send to fetch recovery logs.
 */
static int mgc_process_recover_log(struct obd_device *obd,
				   struct config_llog_data *cld)
{
	struct ptlrpc_request *req = NULL;
	struct config_llog_instance *cfg = &cld->cld_cfg;
	struct mgs_config_body *body;
	struct mgs_config_res *res;
	struct ptlrpc_bulk_desc *desc;
	struct page **pages;
	int nrpages;
	bool eof = true;
	bool mne_swab;
	int i;
	int ealen;
	int rc;

	/* allocate buffer for bulk transfer.
	 * if this is the first time for this mgs to read logs,
	 * CONFIG_READ_NRPAGES_INIT will be used since it will read all logs
	 * once; otherwise, it only reads increment of logs, this should be
	 * small and CONFIG_READ_NRPAGES will be used.
	 */
	nrpages = CONFIG_READ_NRPAGES;
	if (cfg->cfg_last_idx == 0) /* the first time */
		nrpages = CONFIG_READ_NRPAGES_INIT;

	pages = kvmalloc_array(nrpages, sizeof(*pages),
			       GFP_KERNEL | __GFP_ZERO);
	if (!pages) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < nrpages; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i]) {
			rc = -ENOMEM;
			goto out;
		}
	}

again:
	LASSERT(cld_is_recover(cld));
	LASSERT(mutex_is_locked(&cld->cld_lock));
	req = ptlrpc_request_alloc(class_exp2cliimp(cld->cld_mgcexp),
				   &RQF_MGS_CONFIG_READ);
	if (!req) {
		rc = -ENOMEM;
		goto out;
	}

	rc = ptlrpc_request_pack(req, LUSTRE_MGS_VERSION, MGS_CONFIG_READ);
	if (rc)
		goto out;

	/* pack request */
	body = req_capsule_client_get(&req->rq_pill, &RMF_MGS_CONFIG_BODY);
	LASSERT(sizeof(body->mcb_name) > strlen(cld->cld_logname));
	if (strlcpy(body->mcb_name, cld->cld_logname, sizeof(body->mcb_name))
	    >= sizeof(body->mcb_name)) {
		rc = -E2BIG;
		goto out;
	}
	body->mcb_offset = cfg->cfg_last_idx + 1;
	body->mcb_type = cld->cld_type;
	body->mcb_bits = PAGE_SHIFT;
	body->mcb_units = nrpages;

	/* allocate bulk transfer descriptor */
	desc = ptlrpc_prep_bulk_imp(req, nrpages, 1,
				    PTLRPC_BULK_PUT_SINK,
				    MGS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_pin_ops);
	if (!desc) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < nrpages; i++)
		desc->bd_frag_ops->add_kiov_frag(desc, pages[i], 0, PAGE_SIZE);

	ptlrpc_request_set_replen(req);
	rc = ptlrpc_queue_wait(req);
	if (rc)
		goto out;

	res = req_capsule_server_get(&req->rq_pill, &RMF_MGS_CONFIG_RES);
	if (res->mcr_size < res->mcr_offset) {
		rc = -EINVAL;
		goto out;
	}

	/* always update the index even though it might have errors with
	 * handling the recover logs
	 */
	cfg->cfg_last_idx = res->mcr_offset;
	eof = res->mcr_offset == res->mcr_size;

	CDEBUG(D_INFO, "Latest version %lld, more %d.\n",
	       res->mcr_offset, eof == false);

	ealen = sptlrpc_cli_unwrap_bulk_read(req, req->rq_bulk, 0);
	if (ealen < 0) {
		rc = ealen;
		goto out;
	}

	if (ealen > nrpages << PAGE_SHIFT) {
		rc = -EINVAL;
		goto out;
	}

	if (ealen == 0) { /* no logs transferred */
		if (!eof)
			rc = -EINVAL;
		goto out;
	}

	mne_swab = req_capsule_rep_need_swab(&req->rq_pill);

	for (i = 0; i < nrpages && ealen > 0; i++) {
		int rc2;
		void *ptr;

		ptr = kmap(pages[i]);
		rc2 = mgc_apply_recover_logs(obd, cld, res->mcr_offset, ptr,
					     min_t(int, ealen, PAGE_SIZE),
					     mne_swab);
		kunmap(pages[i]);
		if (rc2 < 0) {
			CWARN("Process recover log %s error %d\n",
			      cld->cld_logname, rc2);
			break;
		}

		ealen -= PAGE_SIZE;
	}

out:
	if (req)
		ptlrpc_req_finished(req);

	if (rc == 0 && !eof)
		goto again;

	if (pages) {
		for (i = 0; i < nrpages; i++) {
			if (!pages[i])
				break;
			__free_page(pages[i]);
		}
		kvfree(pages);
	}
	return rc;
}

/* local_only means it cannot get remote llogs */
static int mgc_process_cfg_log(struct obd_device *mgc,
			       struct config_llog_data *cld, int local_only)
{
	struct llog_ctxt *ctxt;
	struct lustre_sb_info *lsi = NULL;
	int rc = 0;
	bool sptlrpc_started = false;
	struct lu_env *env;

	LASSERT(cld);
	LASSERT(mutex_is_locked(&cld->cld_lock));

	/*
	 * local copy of sptlrpc log is controlled elsewhere, don't try to
	 * read it up here.
	 */
	if (cld_is_sptlrpc(cld) && local_only)
		return 0;

	if (cld->cld_cfg.cfg_sb)
		lsi = s2lsi(cld->cld_cfg.cfg_sb);

	env = kzalloc(sizeof(*env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;

	rc = lu_env_init(env, LCT_MG_THREAD);
	if (rc)
		goto out_free;

	ctxt = llog_get_context(mgc, LLOG_CONFIG_REPL_CTXT);
	LASSERT(ctxt);

	if (local_only) /* no local log at client side */ {
		rc = -EIO;
		goto out_pop;
	}

	if (cld_is_sptlrpc(cld)) {
		sptlrpc_conf_log_update_begin(cld->cld_logname);
		sptlrpc_started = true;
	}

	/* logname and instance info should be the same, so use our
	 * copy of the instance for the update.  The cfg_last_idx will
	 * be updated here.
	 */
	rc = class_config_parse_llog(env, ctxt, cld->cld_logname,
				     &cld->cld_cfg);

out_pop:
	__llog_ctxt_put(env, ctxt);

	/*
	 * update settings on existing OBDs.
	 * the logname must be <fsname>-sptlrpc
	 */
	if (sptlrpc_started) {
		LASSERT(cld_is_sptlrpc(cld));
		sptlrpc_conf_log_update_end(cld->cld_logname);
		class_notify_sptlrpc_conf(cld->cld_logname,
					  strlen(cld->cld_logname) -
					  strlen("-sptlrpc"));
	}

	lu_env_fini(env);
out_free:
	kfree(env);
	return rc;
}

static bool mgc_import_in_recovery(struct obd_import *imp)
{
	bool in_recovery = true;

	spin_lock(&imp->imp_lock);
	if (imp->imp_state == LUSTRE_IMP_FULL ||
	    imp->imp_state == LUSTRE_IMP_CLOSED)
		in_recovery = false;
	spin_unlock(&imp->imp_lock);

	return in_recovery;
}

/**
 * Get a configuration log from the MGS and process it.
 *
 * This function is called for both clients and servers to process the
 * configuration log from the MGS. The MGC enqueues a DLM lock on the
 * log from the MGS, and if the lock gets revoked the MGC will be notified
 * by the lock cancellation callback that the config log has changed,
 * and will enqueue another MGS lock on it, and then continue processing
 * the new additions to the end of the log.
 *
 * Since the MGC import is not replayable, if the import is being evicted
 * (rcl == -ESHUTDOWN, \see ptlrpc_import_delay_req()), retry to process
 * the log until recovery is finished or the import is closed.
 *
 * Make a local copy of the log before parsing it if appropriate (non-MGS
 * server) so that the server can start even when the MGS is down.
 *
 * There shouldn't be multiple processes running process_log at once --
 * sounds like badness.  It actually might be fine, as long as they're not
 * trying to update from the same log simultaneously, in which case we
 * should use a per-log semaphore instead of cld_lock.
 *
 * @mgc:	MGC device by which to fetch the configuration log
 * @cld:	log processing state (stored in lock callback data)
 *
 * Returns:	0 on success
 *		negative errno on failure
 */
int mgc_process_log(struct obd_device *mgc, struct config_llog_data *cld)
{
	struct lustre_handle lockh = { 0 };
	u64 flags = LDLM_FL_NO_LRU;
	bool retry = false;
	int rc = 0, rcl;

	LASSERT(cld);

	/* I don't want multiple processes running process_log at once --
	 * sounds like badness.  It actually might be fine, as long as
	 * we're not trying to update from the same log
	 * simultaneously (in which case we should use a per-log sem.)
	 */
restart:
	mutex_lock(&cld->cld_lock);
	if (cld->cld_stopping) {
		mutex_unlock(&cld->cld_lock);
		return 0;
	}

	CFS_FAIL_TIMEOUT(OBD_FAIL_MGC_PAUSE_PROCESS_LOG, 20);

	CDEBUG(D_MGC, "Process log %s:%p from %d\n", cld->cld_logname,
	       cld->cld_cfg.cfg_instance, cld->cld_cfg.cfg_last_idx + 1);

	/* Get the cfg lock on the llog */
	rcl = mgc_enqueue(mgc->u.cli.cl_mgc_mgsexp, LDLM_PLAIN, NULL,
			  LCK_CR, &flags, NULL, NULL, NULL,
			  cld, 0, NULL, &lockh);
	if (rcl == 0) {
		/* Get the cld, it will be released in mgc_blocking_ast. */
		config_log_get(cld);
		rc = ldlm_lock_set_data(&lockh, (void *)cld);
		LASSERT(!lustre_handle_is_used(&cld->cld_lockh));
		LASSERT(rc == 0);
		cld->cld_lockh = lockh;
	} else {
		CDEBUG(D_MGC, "Can't get cfg lock: %d\n", rcl);
		cld->cld_lockh.cookie = 0;

		if (rcl == -ESHUTDOWN &&
		    atomic_read(&mgc->u.cli.cl_mgc_refcount) > 0 && !retry) {
			struct obd_import *imp;

			mutex_unlock(&cld->cld_lock);
			imp = class_exp2cliimp(mgc->u.cli.cl_mgc_mgsexp);

			/*
			 * Let's force the pinger, and wait the import to be
			 * connected, note: since mgc import is non-replayable,
			 * and even the import state is disconnected, it does
			 * not mean the "recovery" is stopped, so we will keep
			 * waitting until timeout or the import state is
			 * FULL or closed
			 */
			ptlrpc_pinger_force(imp);

			wait_event_idle_timeout(imp->imp_recovery_waitq,
						!mgc_import_in_recovery(imp),
						obd_timeout * HZ);

			if (imp->imp_state == LUSTRE_IMP_FULL) {
				retry = true;
				goto restart;
			} else {
				mutex_lock(&cld->cld_lock);
				/* unlock/lock mutex, so check stopping again */
				if (cld->cld_stopping) {
					mutex_unlock(&cld->cld_lock);
					return 0;
				}
				spin_lock(&config_list_lock);
				cld->cld_lostlock = 1;
				spin_unlock(&config_list_lock);
			}
		} else {
			/* mark cld_lostlock so that it will requeue
			 * after MGC becomes available.
			 */
			spin_lock(&config_list_lock);
			cld->cld_lostlock = 1;
			spin_unlock(&config_list_lock);
		}
	}

	if (cld_is_recover(cld)) {
		rc = 0; /* this is not a fatal error for recover log */
		if (!rcl) {
			rc = mgc_process_recover_log(mgc, cld);
			if (rc) {
				CERROR("%s: recover log %s failed: rc = %d not fatal.\n",
				       mgc->obd_name, cld->cld_logname, rc);
				rc = 0;
			}
		}
	} else {
		rc = mgc_process_cfg_log(mgc, cld, rcl != 0);
	}

	CDEBUG(D_MGC, "%s: configuration from log '%s' %sed (%d).\n",
	       mgc->obd_name, cld->cld_logname, rc ? "fail" : "succeed", rc);

	/* Now drop the lock so MGS can revoke it */
	if (!rcl)
		ldlm_lock_decref(&lockh, LCK_CR);

	mutex_unlock(&cld->cld_lock);

	return rc;
}

/** Called from lustre_process_log.
 * LCFG_LOG_START gets the config log from the MGS, processes it to start
 * any services, and adds it to the list logs to watch (follow).
 */
static int mgc_process_config(struct obd_device *obd, u32 len, void *buf)
{
	struct lustre_cfg *lcfg = buf;
	struct config_llog_instance *cfg = NULL;
	char *logname;
	int rc = 0;

	switch (lcfg->lcfg_command) {
	case LCFG_LOV_ADD_OBD: {
		/* Overloading this cfg command: register a new target */
		struct mgs_target_info *mti;

		if (LUSTRE_CFG_BUFLEN(lcfg, 1) !=
		    sizeof(struct mgs_target_info)) {
			rc = -EINVAL;
			goto out;
		}

		mti = (struct mgs_target_info *)lustre_cfg_buf(lcfg, 1);
		CDEBUG(D_MGC, "add_target %s %#x\n",
		       mti->mti_svname, mti->mti_flags);
		rc = mgc_target_register(obd->u.cli.cl_mgc_mgsexp, mti);
		break;
	}
	case LCFG_LOV_DEL_OBD:
		/* Unregister has no meaning at the moment. */
		CERROR("lov_del_obd unimplemented\n");
		rc = -ENXIO;
		break;
	case LCFG_SPTLRPC_CONF: {
		rc = sptlrpc_process_config(lcfg);
		break;
	}
	case LCFG_LOG_START: {
		struct config_llog_data *cld;
		struct super_block *sb;

		logname = lustre_cfg_string(lcfg, 1);
		cfg = (struct config_llog_instance *)lustre_cfg_buf(lcfg, 2);
		sb = *(struct super_block **)lustre_cfg_buf(lcfg, 3);

		CDEBUG(D_MGC, "parse_log %s from %d\n", logname,
		       cfg->cfg_last_idx);

		/* We're only called through here on the initial mount */
		cld = config_log_add(obd, logname, cfg, sb);
		if (IS_ERR(cld)) {
			rc = PTR_ERR(cld);
			break;
		}

		/* COMPAT_146 */
		/* FIXME only set this for old logs!  Right now this forces
		 * us to always skip the "inside markers" check
		 */
		cld->cld_cfg.cfg_flags |= CFG_F_COMPAT146;

		rc = mgc_process_log(obd, cld);
		if (rc == 0 && cld->cld_recover) {
			if (OCD_HAS_FLAG(&obd->u.cli.cl_import->imp_connect_data,
					 IMP_RECOV)) {
				rc = mgc_process_log(obd, cld->cld_recover);
			} else {
				struct config_llog_data *cir;

				mutex_lock(&cld->cld_lock);
				cir = cld->cld_recover;
				cld->cld_recover = NULL;
				mutex_unlock(&cld->cld_lock);
				config_log_put(cir);
			}

			if (rc)
				CERROR("Cannot process recover llog %d\n", rc);
		}

		if (rc == 0 && cld->cld_params) {
			rc = mgc_process_log(obd, cld->cld_params);
			if (rc == -ENOENT) {
				CDEBUG(D_MGC,
				       "There is no params config file yet\n");
				rc = 0;
			}
			/* params log is optional */
			if (rc)
				CERROR(
				       "%s: can't process params llog: rc = %d\n",
				       obd->obd_name, rc);
		}

		break;
	}
	case LCFG_LOG_END: {
		logname = lustre_cfg_string(lcfg, 1);

		if (lcfg->lcfg_bufcount >= 2)
			cfg = (struct config_llog_instance *)lustre_cfg_buf(
				lcfg, 2);
		rc = config_log_end(logname, cfg);
		break;
	}
	default: {
		CERROR("Unknown command: %d\n", lcfg->lcfg_command);
		rc = -EINVAL;
		goto out;
	}
	}
out:
	return rc;
}

static const struct obd_ops mgc_obd_ops = {
	.owner		= THIS_MODULE,
	.setup		= mgc_setup,
	.precleanup	= mgc_precleanup,
	.cleanup	= mgc_cleanup,
	.add_conn	= client_import_add_conn,
	.del_conn	= client_import_del_conn,
	.connect	= client_connect_import,
	.disconnect	= client_disconnect_export,
	.set_info_async	= mgc_set_info_async,
	.get_info	= mgc_get_info,
	.import_event	= mgc_import_event,
	.process_config	= mgc_process_config,
};

static int mgc_param_requeue_timeout_min_set(const char *val,
					     const struct kernel_param *kp)
{
	int rc;
	unsigned int num;

	rc = kstrtouint(val, 0, &num);
	if (rc < 0)
		return rc;
	if (num > 120)
		return -EINVAL;

	mgc_requeue_timeout_min = num;

	return 0;
}

static struct kernel_param_ops param_ops_requeue_timeout_min = {
	.set = mgc_param_requeue_timeout_min_set,
	.get = param_get_uint,
};

#define param_check_requeue_timeout_min(name, p) \
		__param_check(name, p, unsigned int)

unsigned int mgc_requeue_timeout_min = MGC_TIMEOUT_MIN_SECONDS;
module_param_call(mgc_requeue_timeout_min, mgc_param_requeue_timeout_min_set,
		  param_get_uint, &param_ops_requeue_timeout_min, 0644);
MODULE_PARM_DESC(mgc_requeue_timeout_min, "Minimal requeue time to refresh logs");

static int __init mgc_init(void)
{
	int rc;

	rc = libcfs_setup();
	if (rc)
		return rc;

	return class_register_type(&mgc_obd_ops, NULL,
				   LUSTRE_MGC_NAME, NULL);
}

static void /*__exit*/ mgc_exit(void)
{
	class_unregister_type(LUSTRE_MGC_NAME);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Management Client");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(mgc_init);
module_exit(mgc_exit);

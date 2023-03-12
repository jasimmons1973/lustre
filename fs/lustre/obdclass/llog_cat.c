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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/llog_cat.c
 *
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <obd_class.h>

#include "llog_internal.h"

/* Open an existent log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 * We return a lock on the handle to ensure nobody yanks it from us.
 *
 * This takes extra reference on llog_handle via llog_handle_get() and require
 * this reference to be put by caller using llog_handle_put()
 */
static int llog_cat_id2handle(const struct lu_env *env,
			      struct llog_handle *cathandle,
			      struct llog_handle **res,
			      struct llog_logid *logid)
{
	struct llog_handle *loghandle;
	enum llog_flag fmt;
	int rc = 0;

	if (!cathandle)
		return -EBADF;

	fmt = cathandle->lgh_hdr->llh_flags & LLOG_F_EXT_MASK;
	down_write(&cathandle->lgh_lock);
	list_for_each_entry(loghandle, &cathandle->u.chd.chd_head,
			    u.phd.phd_entry) {
		struct llog_logid *cgl = &loghandle->lgh_id;

		if (ostid_id(&cgl->lgl_oi) == ostid_id(&logid->lgl_oi) &&
		    ostid_seq(&cgl->lgl_oi) == ostid_seq(&logid->lgl_oi)) {
			*res = llog_handle_get(loghandle);
			if (!*res) {
				CERROR("%s: log "DFID" refcount is zero!\n",
				       loghandle2name(loghandle),
				       PLOGID(logid));
				continue;
			}
			loghandle->u.phd.phd_cat_handle = cathandle;
			up_write(&cathandle->lgh_lock);
			return rc;
		}
	}
	up_write(&cathandle->lgh_lock);

	rc = llog_open(env, cathandle->lgh_ctxt, &loghandle, logid, NULL,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		CERROR("%s: error opening log id "DFID": rc = %d\n",
		       loghandle2name(cathandle), PLOGID(logid), rc);
		return rc;
	}

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN |
			      LLOG_F_ZAP_WHEN_EMPTY | fmt, NULL);
	if (rc < 0) {
		llog_close(env, loghandle);
		*res = NULL;
		return rc;
	}

	*res = llog_handle_get(loghandle);
	LASSERT(*res);
	down_write(&cathandle->lgh_lock);
	list_add_tail(&loghandle->u.phd.phd_entry, &cathandle->u.chd.chd_head);
	up_write(&cathandle->lgh_lock);

	loghandle->u.phd.phd_cat_handle = cathandle;
	loghandle->u.phd.phd_cookie.lgc_lgl = cathandle->lgh_id;
	loghandle->u.phd.phd_cookie.lgc_index =
				loghandle->lgh_hdr->llh_cat_idx;
	return 0;
}

int llog_cat_close(const struct lu_env *env, struct llog_handle *cathandle)
{
	struct llog_handle *loghandle, *n;

	list_for_each_entry_safe(loghandle, n, &cathandle->u.chd.chd_head,
				 u.phd.phd_entry) {
		/* unlink open-not-created llogs */
		list_del_init(&loghandle->u.phd.phd_entry);
		llog_close(env, loghandle);
	}

	return 0;
}
EXPORT_SYMBOL(llog_cat_close);

static int llog_cat_process_common(const struct lu_env *env,
				   struct llog_handle *cat_llh,
				   struct llog_rec_hdr *rec,
				   struct llog_handle **llhp)
{
	struct llog_logid_rec *lir = container_of(rec, typeof(*lir), lid_hdr);
	int rc;

	if (rec->lrh_type != le32_to_cpu(LLOG_LOGID_MAGIC)) {
		rc = -EINVAL;
		CWARN("%s: invalid record in catalog "DFID": rc = %d\n",
		      loghandle2name(cat_llh), PLOGID(&cat_llh->lgh_id), rc);
		return rc;
	}
	CDEBUG(D_HA,
	       "processing log "DFID" at index %u of catalog "DFID"\n",
	       PLOGID(&lir->lid_id), le32_to_cpu(rec->lrh_index),
	       PLOGID(&cat_llh->lgh_id));

	rc = llog_cat_id2handle(env, cat_llh, llhp, &lir->lid_id);
	if (rc) {
		CWARN("%s: can't find llog handle "DFID": rc = %d\n",
		      loghandle2name(cat_llh), PLOGID(&lir->lid_id),
		      rc);

		return rc;
	}

	return rc;
}

static int llog_cat_process_cb(const struct lu_env *env,
			       struct llog_handle *cat_llh,
			       struct llog_rec_hdr *rec, void *data)
{
	struct llog_process_data *d = data;
	struct llog_handle *llh = NULL;
	int rc;

	/* Skip processing of the logs until startcat */
	if (rec->lrh_index < d->lpd_startcat)
		return 0;

	rc = llog_cat_process_common(env, cat_llh, rec, &llh);
	if (rc)
		goto out;

	if (d->lpd_startidx > 0) {
		struct llog_process_cat_data cd = {
			.lpcd_first_idx = 0,
			.lpcd_last_idx = 0,
			.lpcd_read_mode = LLOG_READ_MODE_NORMAL,
		};

		/* startidx is always associated with a catalog index */
		if (d->lpd_startcat == rec->lrh_index)
			cd.lpcd_first_idx = d->lpd_startidx;

		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  &cd, false);
		/* Continue processing the next log from idx 0 */
		d->lpd_startidx = 0;
	} else {
		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  NULL, false);
	}

out:
	llog_handle_put(env, llh);

	return rc;
}

static int llog_cat_process_or_fork(const struct lu_env *env,
				    struct llog_handle *cat_llh,
				    llog_cb_t cat_cb, llog_cb_t cb,
				    void *data, int startcat,
				    int startidx, bool fork)
{
	struct llog_log_hdr *llh = cat_llh->lgh_hdr;
	struct llog_process_data d;
	struct llog_process_cat_data cd;
	int rc;

	LASSERT(llh->llh_flags & LLOG_F_IS_CAT);
	d.lpd_data = data;
	d.lpd_cb = cb;

	/* default: start from the oldest record */
	d.lpd_startidx = 0;
	d.lpd_startcat = llh->llh_cat_idx + 1;
	cd.lpcd_first_idx = llh->llh_cat_idx;
	cd.lpcd_last_idx = 0;
	cd.lpcd_read_mode = LLOG_READ_MODE_NORMAL;

	if (startcat > 0 && startcat <= llog_max_idx(llh)) {
		/* start from a custom catalog/llog plain indexes*/
		d.lpd_startidx = startidx;
		d.lpd_startcat = startcat;
		cd.lpcd_first_idx = startcat - 1;
	} else if (startcat != 0) {
		CWARN("%s: startcat %d out of range for catlog "DFID"\n",
		      loghandle2name(cat_llh), startcat,
		      PLOGID(&cat_llh->lgh_id));
		return -EINVAL;
	}

	startcat = d.lpd_startcat;

	/* if startcat <= lgh_last_idx, we only need to process the first part
	 * of the catalog (from startcat).
	 */
	if (llog_cat_is_wrapped(cat_llh) && startcat > cat_llh->lgh_last_idx) {
		int cat_idx_origin = llh->llh_cat_idx;

		CWARN("%s: catlog " DFID " crosses index zero\n",
		      loghandle2name(cat_llh),
		      PLOGID(&cat_llh->lgh_id));

		/* processing the catalog part at the end */
		rc = llog_process_or_fork(env, cat_llh, cat_cb, &d, &cd, fork);
		if (rc)
			return rc;

		/* Reset the startcat because it has already reached catalog
		 * bottom.
		 * lgh_last_idx value could be increased during processing. So
		 * we process the remaining of catalog entries to be sure.
		 */
		d.lpd_startcat = 1;
		d.lpd_startidx = 0;
		cd.lpcd_first_idx = 0;
		cd.lpcd_last_idx = max(cat_idx_origin, cat_llh->lgh_last_idx);
	} else if (llog_cat_is_wrapped(cat_llh)) {
		/* only process 1st part -> stop before reaching 2sd part */
		cd.lpcd_last_idx = llh->llh_cat_idx;
	}

	/* processing the catalog part at the beginning */
	rc = llog_process_or_fork(env, cat_llh, cat_cb, &d, &cd, fork);

	return rc;
}

/**
 * Process catalog records with a callback
 *
 * @note
 * If "starcat = 0", this is the default processing. "startidx" argument is
 * ignored and processing begin from the oldest record.
 * If "startcat > 0", this is a custom starting point. Processing begin with
 * the llog plain defined in the catalog record at index "startcat". The first
 * llog plain record to process is at index "startidx + 1".
 *
 * @env		Lustre environnement
 * @cat_llh	Catalog llog handler
 * @cb		Callback executed for each records (in llog plain files)
 * @data	Callback data argument
 * @startcat	Catalog index of the llog plain to start with.
 * @startidx	Index of the llog plain to start processing. The first
 *		record to process is at startidx + 1.
 *
 * RETURN	0 processing successfully completed
 *		LLOG_PROC_BREAK processing was stopped by the callback.
 *		-errno on error.
 */
int llog_cat_process(const struct lu_env *env, struct llog_handle *cat_llh,
		     llog_cb_t cb, void *data, int startcat, int startidx)
{
	return llog_cat_process_or_fork(env, cat_llh, llog_cat_process_cb, cb,
					data, startcat, startidx, false);
}
EXPORT_SYMBOL(llog_cat_process);

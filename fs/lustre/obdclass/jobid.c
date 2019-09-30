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
 * Copyright (c) 2011, 2014, Intel Corporation.
 *
 * Copyright 2017 Cray Inc, all rights reserved.
 * Author: Ben Evans.
 *
 */

#define DEBUG_SUBSYSTEM S_RPC
#include <linux/user_namespace.h>
#ifdef HAVE_UIDGID_HEADER
#include <linux/uidgid.h>
#endif

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>

char obd_jobid_var[JOBSTATS_JOBID_VAR_MAX_LEN + 1] = JOBSTATS_DISABLE;
char obd_jobid_node[LUSTRE_JOBID_SIZE + 1];

/* Get jobid of current process from stored variable or calculate
 * it from pid and user_id.
 *
 * Historically this was also done by reading the environment variable
 * stored in between the "env_start" & "env_end" of task struct.
 * This is now deprecated.
 */

int lustre_get_jobid(char *jobid)
{
	char tmp_jobid[LUSTRE_JOBID_SIZE] = { 0 };

	/* Jobstats isn't enabled */
	if (strcmp(obd_jobid_var, JOBSTATS_DISABLE) == 0)
		goto out_cache_jobid;

	/* Use process name + fsuid as jobid */
	if (strcmp(obd_jobid_var, JOBSTATS_PROCNAME_UID) == 0) {
		snprintf(tmp_jobid, LUSTRE_JOBID_SIZE, "%s.%u",
			 current->comm,
			 from_kuid(&init_user_ns, current_fsuid()));
		goto out_cache_jobid;
	}

	/* Whole node dedicated to single job */
	if (strcmp(obd_jobid_var, JOBSTATS_NODELOCAL) == 0) {
		strcpy(tmp_jobid, obd_jobid_node);
		goto out_cache_jobid;
	}

	return -ENOENT;

out_cache_jobid:
	/* Only replace the job ID if it changed. */
	if (strcmp(jobid, tmp_jobid) != 0)
		strcpy(jobid, tmp_jobid);

	return 0;
}
EXPORT_SYMBOL(lustre_get_jobid);

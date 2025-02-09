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
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_req_layout.h>

#include "ptlrpc_internal.h"

DEFINE_MUTEX(ptlrpc_startup);
static int ptlrpc_active;

int ptlrpc_inc_ref(void)
{
	int rc = 0;

	mutex_lock(&ptlrpc_startup);
	if (ptlrpc_active++ == 0) {
		rc = ptlrpc_init_portals();
		if (!rc) {
			rc = ptlrpc_start_pinger();
			if (rc)
				ptlrpc_exit_portals();
		}
		if (rc)
			ptlrpc_active--;
	}
	mutex_unlock(&ptlrpc_startup);
	return rc;
}
EXPORT_SYMBOL(ptlrpc_inc_ref);

void ptlrpc_dec_ref(void)
{
	mutex_lock(&ptlrpc_startup);
	if (--ptlrpc_active == 0) {
		ptlrpc_stop_pinger();
		ptlrpc_exit_portals();
	}
	mutex_unlock(&ptlrpc_startup);
}
EXPORT_SYMBOL(ptlrpc_dec_ref);

static int __init ptlrpc_init(void)
{
	int rc, cleanup_phase = 0;

	lustre_assert_wire_constants();
#if RS_DEBUG
	spin_lock_init(&ptlrpc_rs_debug_lock);
#endif
	mutex_init(&ptlrpc_all_services_mutex);
	mutex_init(&pinger_mutex);
	mutex_init(&ptlrpcd_mutex);
	ptlrpc_init_xid();
	lustre_msg_early_size_init();

	rc = libcfs_setup();
	if (rc)
		return rc;

	rc = req_layout_init();
	if (rc)
		return rc;

	rc = ptlrpc_hr_init();
	if (rc)
		return rc;

	cleanup_phase = 1;
	rc = ptlrpc_request_cache_init();
	if (rc)
		goto cleanup;

	cleanup_phase = 3;

	rc = ptlrpc_connection_init();
	if (rc)
		goto cleanup;

	cleanup_phase = 5;
	rc = ldlm_init();
	if (rc)
		goto cleanup;

	cleanup_phase = 6;
	rc = sptlrpc_init();
	if (rc)
		goto cleanup;

	cleanup_phase = 7;
	rc = ptlrpc_nrs_init();
	if (rc)
		goto cleanup;

	cleanup_phase = 8;
	rc = tgt_mod_init();
	if (rc)
		goto cleanup;
	return 0;

cleanup:
	switch (cleanup_phase) {
	case 8:
		ptlrpc_nrs_fini();
		fallthrough;
	case 7:
		sptlrpc_fini();
		fallthrough;
	case 6:
		ldlm_exit();
		fallthrough;
	case 5:
		ptlrpc_connection_fini();
		fallthrough;
	case 3:
		ptlrpc_request_cache_fini();
		fallthrough;
	case 1:
		ptlrpc_hr_fini();
		req_layout_fini();
		fallthrough;
	default:
		break;
	}

	return rc;
}

static void __exit ptlrpc_exit(void)
{
	tgt_mod_exit();
	ptlrpc_nrs_fini();
	sptlrpc_fini();
	ldlm_exit();
	ptlrpc_request_cache_fini();
	ptlrpc_hr_fini();
	ptlrpc_connection_fini();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Request Processor and Lock Management");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);

/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2015, Cray Inc. All Rights Reserved.
 *
 * Copyright (c) 2015, Intel Corporation.
 */
/*
 *
 * Network Request Scheduler (NRS) Delay policy
 *
 */

#ifndef _LUSTRE_NRS_DELAY_H
#define _LUSTRE_NRS_DELAY_H

/* \name delay
 *
 * Delay policy
 * @{
 */

/**
 * Private data structure for the delay policy
 */
struct nrs_delay_data {
	struct ptlrpc_nrs_resource	 delay_res;

	/**
	 * Delayed requests are stored in this binheap until they are
	 * removed for handling.
	 */
	struct binheap			*delay_binheap;

	/**
	 * Minimum service time
	 */
	u32				 min_delay;

	/**
	 * Maximum service time
	 */
	u32				 max_delay;

	/**
	 * We'll delay this percent of requests
	 */
	u32				 delay_pct;
};

struct nrs_delay_req {
	/**
	 * This is the time at which a request becomes eligible for handling
	 */
	time64_t	req_start_time;
};

#define NRS_CTL_DELAY_RD_MIN PTLRPC_NRS_CTL_POL_SPEC_01
#define NRS_CTL_DELAY_WR_MIN PTLRPC_NRS_CTL_POL_SPEC_02
#define NRS_CTL_DELAY_RD_MAX PTLRPC_NRS_CTL_POL_SPEC_03
#define NRS_CTL_DELAY_WR_MAX PTLRPC_NRS_CTL_POL_SPEC_04
#define NRS_CTL_DELAY_RD_PCT PTLRPC_NRS_CTL_POL_SPEC_05
#define NRS_CTL_DELAY_WR_PCT PTLRPC_NRS_CTL_POL_SPEC_06

/** @} delay */

#endif

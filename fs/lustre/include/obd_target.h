// SPDX-License-Identifier: GPL-2.0
/* GPL HEADER START
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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __OBD_TARGET_H
#define __OBD_TARGET_H
#include <lprocfs_status.h>

/* Generic subset of tgts */
struct lu_tgt_pool {
	__u32		   *op_array;	/* array of index of
					 * lov_obd->lov_tgts
					 */
	unsigned int	    op_count;	/* number of tgts in the array */
	unsigned int	    op_size;	/* allocated size of op_array */
	struct rw_semaphore op_rw_sem;	/* to protect lu_tgt_pool use */
};

int tgt_pool_init(struct lu_tgt_pool *op, unsigned int count);
int tgt_pool_add(struct lu_tgt_pool *op, __u32 idx, unsigned int min_count);
int tgt_pool_remove(struct lu_tgt_pool *op, __u32 idx);
int tgt_pool_free(struct lu_tgt_pool *op);
int tgt_check_index(int idx, struct lu_tgt_pool *osts);
int tgt_pool_extend(struct lu_tgt_pool *op, unsigned int min_count);

#endif /* __OBD_TARGET_H */

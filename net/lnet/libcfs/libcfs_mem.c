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
 * GPL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: liang@whamcloud.com
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/libcfs/libcfs_cpu.h>
#include <linux/slab.h>
#include <linux/mm.h>

struct cfs_var_array {
	unsigned int		va_count;	/* # of buffers */
	unsigned int		va_size;	/* size of each var */
	struct cfs_cpt_table	*va_cptab;	/* cpu partition table */
	void			*va_ptrs[0];	/* buffer addresses */
};

/*
 * free per-cpu data, see more detail in cfs_percpt_free
 */
void
cfs_percpt_free(void *vars)
{
	struct cfs_var_array *arr;
	int i;

	arr = container_of(vars, struct cfs_var_array, va_ptrs[0]);

	for (i = 0; i < arr->va_count; i++)
		kfree(arr->va_ptrs[i]);

	kvfree(arr);
}
EXPORT_SYMBOL(cfs_percpt_free);

/*
 * allocate per cpu-partition variables, returned value is an array of pointers,
 * variable can be indexed by CPU partition ID, i.e:
 *
 *	arr = cfs_percpt_alloc(cfs_cpu_pt, size);
 *	then caller can access memory block for CPU 0 by arr[0],
 *	memory block for CPU 1 by arr[1]...
 *	memory block for CPU N by arr[N]...
 *
 * cacheline aligned.
 */
void *
cfs_percpt_alloc(struct cfs_cpt_table *cptab, unsigned int size)
{
	struct cfs_var_array *arr;
	int count;
	int i;

	count = cfs_cpt_number(cptab);

	arr = kvzalloc(offsetof(struct cfs_var_array, va_ptrs[count]),
		       GFP_KERNEL);
	if (!arr)
		return NULL;

	size = L1_CACHE_ALIGN(size);
	arr->va_size = size;
	arr->va_count = count;
	arr->va_cptab = cptab;

	for (i = 0; i < count; i++) {
		arr->va_ptrs[i] = kzalloc_node(size, GFP_KERNEL,
					       cfs_cpt_spread_node(cptab, i));
		if (!arr->va_ptrs[i]) {
			cfs_percpt_free((void *)&arr->va_ptrs[0]);
			return NULL;
		}
	}

	return (void *)&arr->va_ptrs[0];
}
EXPORT_SYMBOL(cfs_percpt_alloc);

/*
 * return number of CPUs (or number of elements in per-cpu data)
 * according to cptab of @vars
 */
int
cfs_percpt_number(void *vars)
{
	struct cfs_var_array *arr;

	arr = container_of(vars, struct cfs_var_array, va_ptrs[0]);

	return arr->va_count;
}
EXPORT_SYMBOL(cfs_percpt_number);

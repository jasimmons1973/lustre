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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/include/libcfs/libcfs_string.h
 *
 * Generic string manipulation functions.
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 */

#ifndef __LIBCFS_STRING_H__
#define __LIBCFS_STRING_H__

#include <linux/mm.h>

/* libcfs_string.c */
/* Convert a text string to a bitmask */
int cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
		 int *oldmask, int minmask, int allmask, int defmask);

/* trim leading and trailing space characters */
char *cfs_firststr(char *str, size_t size);

/**
 * Structure to represent NULL-less strings.
 */
struct cfs_lstr {
	char			*ls_str;
	int			ls_len;
};

/*
 * Structure to represent \<range_expr\> token of the syntax.
 */
struct cfs_range_expr {
	/*
	 * Link to cfs_expr_list::el_exprs.
	 */
	struct list_head	re_link;
	u32			re_lo;
	u32			re_hi;
	u32			re_stride;
};

struct cfs_expr_list {
	struct list_head	el_link;
	struct list_head	el_exprs;
};

int cfs_gettok(struct cfs_lstr *next, char delim, struct cfs_lstr *res);
int cfs_str2num_check(char *str, int nob, unsigned int *num,
		      unsigned int min, unsigned int max);
int cfs_expr_list_match(u32 value, struct cfs_expr_list *expr_list);
int cfs_expr_list_values(struct cfs_expr_list *expr_list,
			 int max, u32 **values);
void cfs_expr_list_free(struct cfs_expr_list *expr_list);
int cfs_expr_list_parse(char *str, int len, unsigned int min, unsigned int max,
			struct cfs_expr_list **elpp);
void cfs_expr_list_free(struct cfs_expr_list *expr_list);
void cfs_expr_list_free_list(struct list_head *list);

#endif

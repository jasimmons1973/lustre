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
 * String manipulation functions.
 *
 * libcfs/libcfs/libcfs_string.c
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 */

#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/libcfs/libcfs.h>
#include <linux/libcfs/libcfs_string.h>

/* Convert a text string to a bitmask */
int cfs_str2mask(const char *str, const char *(*bit2str)(int bit),
		 int *oldmask, int minmask, int allmask, int defmask)
{
	const char *debugstr;
	char op = '\0';
	int newmask = minmask, i, len, found = 0;

	/* <str> must be a list of tokens separated by whitespace or comma,
	 * and optionally an operator ('+' or '-').  If an operator
	 * appears first in <str>, '*oldmask' is used as the starting point
	 * (relative), otherwise minmask is used (absolute).  An operator
	 * applies to all following tokens up to the next operator.
	 */
	while (*str != '\0') {
		while (isspace(*str) || *str == ',')
			str++;
		if (*str == '\0')
			break;
		if (*str == '+' || *str == '-') {
			op = *str++;
			if (!found)
				/* only if first token is relative */
				newmask = *oldmask;
			while (isspace(*str))
				str++;
			if (*str == '\0')  /* trailing op */
				return -EINVAL;
		}

		/* find token length */
		len = 0;
		while (str[len] != '\0' && !isspace(str[len]) &&
		       str[len] != '+' && str[len] != '-' && str[len] != ',')
			len++;

		/* match token */
		found = 0;
		for (i = 0; i < 32; i++) {
			debugstr = bit2str(i);
			if (debugstr && strlen(debugstr) == len &&
			    !strncasecmp(str, debugstr, len)) {
				if (op == '-')
					newmask &= ~BIT(i);
				else
					newmask |= BIT(i);
				found = 1;
				break;
			}
		}
		if (!found && len == 3 &&
		    !strncasecmp(str, "ALL", len)) {
			if (op == '-')
				newmask = minmask;
			else
				newmask = allmask;
			found = 1;
		}
		if (!found && strcasecmp(str, "DEFAULT") == 0) {
			if (op == '-')
				newmask = (newmask & ~defmask) | minmask;
			else if (op == '+')
				newmask |= defmask;
			else
				newmask = defmask;
			found = 1;
		}
		if (!found) {
			CWARN("unknown mask '%.*s'.\n"
			      "mask usage: [+|-]<all|type> ...\n", len, str);
			return -EINVAL;
		}
		str += len;
	}

	*oldmask = newmask;
	return 0;
}

/**
 * Extracts tokens from strings.
 *
 * Looks for @a delim in string @next, sets @res to point to
 * substring before the delimiter, sets @next right after the found
 * delimiter.
 *
 * Return:	1 if @ res points to a string of non-whitespace characters
 *		0 otherwise
 */
int
cfs_gettok(struct cfs_lstr *next, char delim, struct cfs_lstr *res)
{
	char *end;

	if (!next->ls_str)
		return 0;

	/* skip leading white spaces */
	while (next->ls_len) {
		if (!isspace(*next->ls_str))
			break;
		next->ls_str++;
		next->ls_len--;
	}

	if (!next->ls_len) /* whitespaces only */
		return 0;

	if (*next->ls_str == delim) {
		/* first non-writespace is the delimiter */
		return 0;
	}

	res->ls_str = next->ls_str;
	end = memchr(next->ls_str, delim, next->ls_len);
	if (!end) {
		/* there is no the delimeter in the string */
		end = next->ls_str + next->ls_len;
		next->ls_str = NULL;
		next->ls_len = 0;
	} else {
		next->ls_str = end + 1;
		next->ls_len -= (end - res->ls_str + 1);
	}

	/* skip ending whitespaces */
	while (--end != res->ls_str) {
		if (!isspace(*end))
			break;
	}

	res->ls_len = end - res->ls_str + 1;
	return 1;
}
EXPORT_SYMBOL(cfs_gettok);

/**
 * Converts string to integer.
 *
 * Accepts decimal and hexadecimal number recordings.
 *
 * Return:	1 if first @nob chars of @str convert to decimal or
 *		hexadecimal integer in the range [ @min, @max ]
 *		0 otherwise
 */
int
cfs_str2num_check(char *str, int nob, unsigned int *num,
		  unsigned int min, unsigned int max)
{
	bool all_numbers = true;
	char *endp, cache;
	int rc;

	/**
	 * kstrouint can only handle strings composed
	 * of only numbers. We need to scan the string
	 * passed in for the first non-digit character
	 * and end the string at that location. If we
	 * don't find any non-digit character we still
	 * need to place a '\0' at position nob since
	 * we are not interested in the rest of the
	 * string which is longer than nob in size.
	 * After we are done the character at the
	 * position we placed '\0' must be restored.
	 */
	for (endp = str; endp < str + nob; endp++) {
		if (!isdigit(*endp)) {
			all_numbers = false;
			break;
		}
	}
	cache = *endp;
	*endp = '\0';

	rc = kstrtouint(str, 10, num);
	*endp = cache;
	if (rc || !all_numbers)
		return 0;

	return (*num >= min && *num <= max);
}
EXPORT_SYMBOL(cfs_str2num_check);

/**
 * Parses \<range_expr\> token of the syntax. If @bracketed is false,
 * @src should only have a single token which can be \<number\> or  \*
 *
 * Return:	pointer to allocated range_expr and initialized
 * range_expr::re_lo, range_expr::re_hi and range_expr:re_stride if
 * @src parses to
 * \<number\> |
 * \<number\> '-' \<number\> |
 * \<number\> '-' \<number\> '/' \<number\>
 *
 * Return	0 will be returned if it can be parsed, otherwise -EINVAL or
 *		-ENOMEM will be returned.
 */
static int
cfs_range_expr_parse(struct cfs_lstr *src, unsigned int min, unsigned int max,
		     int bracketed, struct cfs_range_expr **expr)
{
	struct cfs_range_expr *re;
	struct cfs_lstr tok;

	re = kzalloc(sizeof(*re), GFP_NOFS);
	if (!re)
		return -ENOMEM;

	if (src->ls_len == 1 && src->ls_str[0] == '*') {
		re->re_lo = min;
		re->re_hi = max;
		re->re_stride = 1;
		goto out;
	}

	if (cfs_str2num_check(src->ls_str, src->ls_len,
			      &re->re_lo, min, max)) {
		/* <number> is parsed */
		re->re_hi = re->re_lo;
		re->re_stride = 1;
		goto out;
	}

	if (!bracketed || !cfs_gettok(src, '-', &tok))
		goto failed;

	if (!cfs_str2num_check(tok.ls_str, tok.ls_len,
			       &re->re_lo, min, max))
		goto failed;

	/* <number> - */
	if (cfs_str2num_check(src->ls_str, src->ls_len,
			      &re->re_hi, min, max)) {
		/* <number> - <number> is parsed */
		re->re_stride = 1;
		goto out;
	}

	/* go to check <number> '-' <number> '/' <number> */
	if (cfs_gettok(src, '/', &tok)) {
		if (!cfs_str2num_check(tok.ls_str, tok.ls_len,
				       &re->re_hi, min, max))
			goto failed;

		/* <number> - <number> / ... */
		if (cfs_str2num_check(src->ls_str, src->ls_len,
				      &re->re_stride, min, max)) {
			/* <number> - <number> / <number> is parsed */
			goto out;
		}
	}

out:
	*expr = re;
	return 0;

failed:
	kfree(re);
	return -EINVAL;
}

/**
 * Matches value (@value) against ranges expression list @expr_list.
 *
 * Return:	1 if @value matches
 *		0 otherwise
 */
int
cfs_expr_list_match(u32 value, struct cfs_expr_list *expr_list)
{
	struct cfs_range_expr *expr;

	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		if (value >= expr->re_lo && value <= expr->re_hi &&
		    !((value - expr->re_lo) % expr->re_stride))
			return 1;
	}

	return 0;
}
EXPORT_SYMBOL(cfs_expr_list_match);

/**
 * Convert express list (@expr_list) to an array of all matched values
 *
 * Return:	N is total number of all matched values
 *		0 if expression list is empty
 *		< 0 for failure
 */
int
cfs_expr_list_values(struct cfs_expr_list *expr_list, int max, u32 **valpp)
{
	struct cfs_range_expr *expr;
	u32 *val;
	int count = 0;
	int i;

	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		for (i = expr->re_lo; i <= expr->re_hi; i++) {
			if (!((i - expr->re_lo) % expr->re_stride))
				count++;
		}
	}

	if (!count) /* empty expression list */
		return 0;

	if (count > max) {
		CERROR("Number of values %d exceeds max allowed %d\n",
		       max, count);
		return -EINVAL;
	}

	val = kvmalloc_array(count, sizeof(val[0]), GFP_KERNEL | __GFP_ZERO);
	if (!val)
		return -ENOMEM;

	count = 0;
	list_for_each_entry(expr, &expr_list->el_exprs, re_link) {
		for (i = expr->re_lo; i <= expr->re_hi; i++) {
			if (!((i - expr->re_lo) % expr->re_stride))
				val[count++] = i;
		}
	}

	*valpp = val;
	return count;
}
EXPORT_SYMBOL(cfs_expr_list_values);

/**
 * Frees cfs_range_expr structures of @expr_list.
 */
void
cfs_expr_list_free(struct cfs_expr_list *expr_list)
{
	struct cfs_range_expr *expr;

	while ((expr = list_first_entry_or_null(&expr_list->el_exprs,
						struct cfs_range_expr,
						re_link)) != NULL) {
		list_del(&expr->re_link);
		kfree(expr);
	}

	kfree(expr_list);
}
EXPORT_SYMBOL(cfs_expr_list_free);

/**
 * Parses \<cfs_expr_list\> token of the syntax.
 *
 * Return:	0 if @str parses to \<number\> | \<expr_list\>
 *		-errno otherwise
 */
int
cfs_expr_list_parse(char *str, int len, unsigned int min, unsigned int max,
		    struct cfs_expr_list **elpp)
{
	struct cfs_expr_list *expr_list;
	struct cfs_range_expr *expr;
	struct cfs_lstr	src;
	int rc;

	expr_list = kzalloc(sizeof(*expr_list), GFP_NOFS);
	if (!expr_list)
		return -ENOMEM;

	src.ls_str = str;
	src.ls_len = len;

	INIT_LIST_HEAD(&expr_list->el_exprs);

	if (src.ls_str[0] == '[' &&
	    src.ls_str[src.ls_len - 1] == ']') {
		src.ls_str++;
		src.ls_len -= 2;

		rc = -EINVAL;
		while (src.ls_str) {
			struct cfs_lstr tok;

			if (!cfs_gettok(&src, ',', &tok)) {
				rc = -EINVAL;
				break;
			}

			rc = cfs_range_expr_parse(&tok, min, max, 1, &expr);
			if (rc)
				break;

			list_add_tail(&expr->re_link, &expr_list->el_exprs);
		}
	} else {
		rc = cfs_range_expr_parse(&src, min, max, 0, &expr);
		if (!rc)
			list_add_tail(&expr->re_link, &expr_list->el_exprs);
	}

	if (rc)
		cfs_expr_list_free(expr_list);
	else
		*elpp = expr_list;

	return rc;
}
EXPORT_SYMBOL(cfs_expr_list_parse);

/**
 * Frees cfs_expr_list structures of @list.
 *
 * For each struct cfs_expr_list structure found on @list it frees
 * range_expr list attached to it and frees the cfs_expr_list itself.
 */
void
cfs_expr_list_free_list(struct list_head *list)
{
	struct cfs_expr_list *el;

	while ((el = list_first_entry_or_null(list, struct cfs_expr_list,
					      el_link)) != NULL) {
		list_del(&el->el_link);
		cfs_expr_list_free(el);
	}
}
EXPORT_SYMBOL(cfs_expr_list_free_list);

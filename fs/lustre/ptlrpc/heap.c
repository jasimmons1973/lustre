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
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2011 Intel Corporation
 */
/*
 * fs/lustre/ptlrpc/heap.c
 *
 * Author: Eric Barton	<eeb@whamcloud.com>
 *	   Liang Zhen	<liang@whamcloud.com>
 */
/** \addtogroup heap
 *
 * @{
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/libcfs/libcfs_cpu.h>
#include <lustre_net.h>
#include "heap.h"

#define CBH_ALLOC(ptr, h)						      \
do {									      \
	if (h->cbh_cptab) {						      \
		if ((h)->cbh_flags & CBH_FLAG_ATOMIC_GROW) {		      \
			ptr = kzalloc_node(CBH_NOB, GFP_ATOMIC,		      \
					   cfs_cpt_spread_node(h->cbh_cptab,  \
							       h->cbh_cptid));\
		} else {						      \
			ptr = kzalloc_node(CBH_NOB, GFP_KERNEL,		      \
					   cfs_cpt_spread_node(h->cbh_cptab,  \
							       h->cbh_cptid));\
		}							      \
	} else {							      \
		if ((h)->cbh_flags & CBH_FLAG_ATOMIC_GROW)		      \
			ptr = kzalloc(CBH_NOB, GFP_ATOMIC);		      \
		else							      \
			ptr = kzalloc(CBH_NOB, GFP_KERNEL);		      \
	}								      \
} while (0)

#define CBH_FREE(ptr)	kfree(ptr)

/**
 * Grows the capacity of a binary heap so that it can handle a larger number of
 * \e struct cfs_binheap_node objects.
 *
 * \param[in] h The binary heap
 *
 * \retval 0	   Successfully grew the heap
 * \retval -ENOMEM OOM error
 */
static int
cfs_binheap_grow(struct cfs_binheap *h)
{
	struct cfs_binheap_node ***frag1 = NULL;
	struct cfs_binheap_node  **frag2;
	int hwm = h->cbh_hwm;

	/* need a whole new chunk of pointers */
	LASSERT((h->cbh_hwm & CBH_MASK) == 0);

	if (hwm == 0) {
		/* first use of single indirect */
		CBH_ALLOC(h->cbh_elements1, h);
		if (!h->cbh_elements1)
			return -ENOMEM;

		goto out;
	}

	hwm -= CBH_SIZE;
	if (hwm < CBH_SIZE * CBH_SIZE) {
		/* not filled double indirect */
		CBH_ALLOC(frag2, h);
		if (!frag2)
			return -ENOMEM;

		if (hwm == 0) {
			/* first use of double indirect */
			CBH_ALLOC(h->cbh_elements2, h);
			if (!h->cbh_elements2) {
				CBH_FREE(frag2);
				return -ENOMEM;
			}
		}

		h->cbh_elements2[hwm >> CBH_SHIFT] = frag2;
		goto out;
	}

	hwm -= CBH_SIZE * CBH_SIZE;
#if (CBH_SHIFT * 3 < 32)
	if (hwm >= CBH_SIZE * CBH_SIZE * CBH_SIZE) {
		/* filled triple indirect */
		return -ENOMEM;
	}
#endif
	CBH_ALLOC(frag2, h);
	if (!frag2)
		return -ENOMEM;

	if (((hwm >> CBH_SHIFT) & CBH_MASK) == 0) {
		/* first use of this 2nd level index */
		CBH_ALLOC(frag1, h);
		if (!frag1) {
			CBH_FREE(frag2);
			return -ENOMEM;
		}
	}

	if (hwm == 0) {
		/* first use of triple indirect */
		CBH_ALLOC(h->cbh_elements3, h);
		if (!h->cbh_elements3) {
			CBH_FREE(frag2);
			CBH_FREE(frag1);
			return -ENOMEM;
		}
	}

	if (frag1) {
		LASSERT(!h->cbh_elements3[hwm >> (2 * CBH_SHIFT)]);
		h->cbh_elements3[hwm >> (2 * CBH_SHIFT)] = frag1;
	} else {
		frag1 = h->cbh_elements3[hwm >> (2 * CBH_SHIFT)];
		LASSERT(frag1);
	}

	frag1[(hwm >> CBH_SHIFT) & CBH_MASK] = frag2;

 out:
	h->cbh_hwm += CBH_SIZE;
	return 0;
}

/**
 * Creates and initializes a binary heap instance.
 *
 * \param[in] ops   The operations to be used
 * \param[in] flags The heap flags
 * \parm[in]  count The initial heap capacity in # of elements
 * \param[in] arg   An optional private argument
 * \param[in] cptab The CPT table this heap instance will operate over
 * \param[in] cptid The CPT id of \a cptab this heap instance will operate over
 *
 * \retval valid-pointer A newly-created and initialized binary heap object
 * \retval NULL		 error
 */
struct cfs_binheap *
cfs_binheap_create(struct cfs_binheap_ops *ops, unsigned int flags,
		   unsigned int count, void *arg, struct cfs_cpt_table *cptab,
		   int cptid)
{
	struct cfs_binheap *h;

	LASSERT(ops);
	LASSERT(ops->hop_compare);
	if (cptab) {
		LASSERT(cptid == CFS_CPT_ANY ||
		       (cptid >= 0 && cptid < cfs_cpt_number(cptab)));

		h = kzalloc_node(sizeof(*h), GFP_KERNEL,
				 cfs_cpt_spread_node(cptab, cptid));
	} else {
		h = kzalloc(sizeof(*h), GFP_KERNEL);
	}
	if (!h)
		return NULL;

	h->cbh_ops	  = ops;
	h->cbh_nelements  = 0;
	h->cbh_hwm	  = 0;
	h->cbh_private	  = arg;
	h->cbh_flags	  = flags & (~CBH_FLAG_ATOMIC_GROW);
	h->cbh_cptab	  = cptab;
	h->cbh_cptid	  = cptid;

	while (h->cbh_hwm < count) { /* preallocate */
		if (cfs_binheap_grow(h) != 0) {
			cfs_binheap_destroy(h);
			return NULL;
		}
	}

	h->cbh_flags |= flags & CBH_FLAG_ATOMIC_GROW;

	return h;
}
EXPORT_SYMBOL(cfs_binheap_create);

/**
 * Releases all resources associated with a binary heap instance.
 *
 * Deallocates memory for all indirection levels and the binary heap object
 * itself.
 *
 * \param[in] h The binary heap object
 */
void
cfs_binheap_destroy(struct cfs_binheap *h)
{
	int idx0;
	int idx1;
	int n;

	LASSERT(h);

	n = h->cbh_hwm;

	if (n > 0) {
		CBH_FREE(h->cbh_elements1);
		n -= CBH_SIZE;
	}

	if (n > 0) {
		for (idx0 = 0; idx0 < CBH_SIZE && n > 0; idx0++) {
			CBH_FREE(h->cbh_elements2[idx0]);
			n -= CBH_SIZE;
		}

		CBH_FREE(h->cbh_elements2);
	}

	if (n > 0) {
		for (idx0 = 0; idx0 < CBH_SIZE && n > 0; idx0++) {

			for (idx1 = 0; idx1 < CBH_SIZE && n > 0; idx1++) {
				CBH_FREE(h->cbh_elements3[idx0][idx1]);
				n -= CBH_SIZE;
			}

			CBH_FREE(h->cbh_elements3[idx0]);
		}

		CBH_FREE(h->cbh_elements3);
	}

	kfree(h);
}
EXPORT_SYMBOL(cfs_binheap_destroy);

/**
 * Obtains a double pointer to a heap element, given its index into the binary
 * tree.
 *
 * \param[in] h	  The binary heap instance
 * \param[in] idx The requested node's index
 *
 * \retval valid-pointer A double pointer to a heap pointer entry
 */
static struct cfs_binheap_node **
cfs_binheap_pointer(struct cfs_binheap *h, unsigned int idx)
{
	if (idx < CBH_SIZE)
		return &(h->cbh_elements1[idx]);

	idx -= CBH_SIZE;
	if (idx < CBH_SIZE * CBH_SIZE)
		return &(h->cbh_elements2[idx >> CBH_SHIFT][idx & CBH_MASK]);

	idx -= CBH_SIZE * CBH_SIZE;
	return &(h->cbh_elements3[idx >> (2 * CBH_SHIFT)]
				 [(idx >> CBH_SHIFT) & CBH_MASK]
				 [idx & CBH_MASK]);
}

/**
 * Obtains a pointer to a heap element, given its index into the binary tree.
 *
 * \param[in] h	  The binary heap
 * \param[in] idx The requested node's index
 *
 * \retval valid-pointer The requested heap node
 * \retval NULL		 Supplied index is out of bounds
 */
struct cfs_binheap_node *
cfs_binheap_find(struct cfs_binheap *h, unsigned int idx)
{
	if (idx >= h->cbh_nelements)
		return NULL;

	return *cfs_binheap_pointer(h, idx);
}
EXPORT_SYMBOL(cfs_binheap_find);

/**
 * Moves a node upwards, towards the root of the binary tree.
 *
 * \param[in] h The heap
 * \param[in] e The node
 *
 * \retval 1 The position of \a e in the tree was changed at least once
 * \retval 0 The position of \a e in the tree was not changed
 */
static int
cfs_binheap_bubble(struct cfs_binheap *h, struct cfs_binheap_node *e)
{
	unsigned int	     cur_idx = e->chn_index;
	struct cfs_binheap_node **cur_ptr;
	unsigned int	     parent_idx;
	struct cfs_binheap_node **parent_ptr;
	int		     did_sth = 0;

	cur_ptr = cfs_binheap_pointer(h, cur_idx);
	LASSERT(*cur_ptr == e);

	while (cur_idx > 0) {
		parent_idx = (cur_idx - 1) >> 1;

		parent_ptr = cfs_binheap_pointer(h, parent_idx);
		LASSERT((*parent_ptr)->chn_index == parent_idx);

		if (h->cbh_ops->hop_compare(*parent_ptr, e))
			break;

		(*parent_ptr)->chn_index = cur_idx;
		*cur_ptr = *parent_ptr;
		cur_ptr = parent_ptr;
		cur_idx = parent_idx;
		did_sth = 1;
	}

	e->chn_index = cur_idx;
	*cur_ptr = e;

	return did_sth;
}

/**
 * Moves a node downwards, towards the last level of the binary tree.
 *
 * \param[in] h The heap
 * \param[in] e The node
 *
 * \retval 1 The position of \a e in the tree was changed at least once
 * \retval 0 The position of \a e in the tree was not changed
 */
static int
cfs_binheap_sink(struct cfs_binheap *h, struct cfs_binheap_node *e)
{
	unsigned int	     n = h->cbh_nelements;
	unsigned int	     child_idx;
	struct cfs_binheap_node **child_ptr;
	struct cfs_binheap_node  *child;
	unsigned int	     child2_idx;
	struct cfs_binheap_node **child2_ptr;
	struct cfs_binheap_node  *child2;
	unsigned int	     cur_idx;
	struct cfs_binheap_node **cur_ptr;
	int		     did_sth = 0;

	cur_idx = e->chn_index;
	cur_ptr = cfs_binheap_pointer(h, cur_idx);
	LASSERT(*cur_ptr == e);

	while (cur_idx < n) {
		child_idx = (cur_idx << 1) + 1;
		if (child_idx >= n)
			break;

		child_ptr = cfs_binheap_pointer(h, child_idx);
		child = *child_ptr;

		child2_idx = child_idx + 1;
		if (child2_idx < n) {
			child2_ptr = cfs_binheap_pointer(h, child2_idx);
			child2 = *child2_ptr;

			if (h->cbh_ops->hop_compare(child2, child)) {
				child_idx = child2_idx;
				child_ptr = child2_ptr;
				child = child2;
			}
		}

		LASSERT(child->chn_index == child_idx);

		if (h->cbh_ops->hop_compare(e, child))
			break;

		child->chn_index = cur_idx;
		*cur_ptr = child;
		cur_ptr = child_ptr;
		cur_idx = child_idx;
		did_sth = 1;
	}

	e->chn_index = cur_idx;
	*cur_ptr = e;

	return did_sth;
}

/**
 * Sort-inserts a node into the binary heap.
 *
 * \param[in] h The heap
 * \param[in] e The node
 *
 * \retval 0	Element inserted successfully
 * \retval != 0 error
 */
int
cfs_binheap_insert(struct cfs_binheap *h, struct cfs_binheap_node *e)
{
	struct cfs_binheap_node **new_ptr;
	unsigned int	     new_idx = h->cbh_nelements;
	int		     rc;

	if (new_idx == h->cbh_hwm) {
		rc = cfs_binheap_grow(h);
		if (rc != 0)
			return rc;
	}

	if (h->cbh_ops->hop_enter) {
		rc = h->cbh_ops->hop_enter(h, e);
		if (rc != 0)
			return rc;
	}

	e->chn_index = new_idx;
	new_ptr = cfs_binheap_pointer(h, new_idx);
	h->cbh_nelements++;
	*new_ptr = e;

	cfs_binheap_bubble(h, e);

	return 0;
}
EXPORT_SYMBOL(cfs_binheap_insert);

/**
 * Removes a node from the binary heap.
 *
 * \param[in] h The heap
 * \param[in] e The node
 */
void
cfs_binheap_remove(struct cfs_binheap *h, struct cfs_binheap_node *e)
{
	unsigned int	     n = h->cbh_nelements;
	unsigned int	     cur_idx = e->chn_index;
	struct cfs_binheap_node **cur_ptr;
	struct cfs_binheap_node  *last;

	LASSERT(cur_idx != CBH_POISON);
	LASSERT(cur_idx < n);

	cur_ptr = cfs_binheap_pointer(h, cur_idx);
	LASSERT(*cur_ptr == e);

	n--;
	last = *cfs_binheap_pointer(h, n);
	h->cbh_nelements = n;
	if (last == e)
		return;

	last->chn_index = cur_idx;
	*cur_ptr = last;
	cfs_binheap_relocate(h, *cur_ptr);

	e->chn_index = CBH_POISON;
	if (h->cbh_ops->hop_exit)
		h->cbh_ops->hop_exit(h, e);
}
EXPORT_SYMBOL(cfs_binheap_remove);

/**
 * Relocate a node in the binary heap.
 * Should be called whenever a node's values
 * which affects its ranking are changed.
 *
 * \param[in] h The heap
 * \param[in] e The node
 */
void
cfs_binheap_relocate(struct cfs_binheap *h, struct cfs_binheap_node *e)
{
	if (!cfs_binheap_bubble(h, e))
		cfs_binheap_sink(h, e);
}
EXPORT_SYMBOL(cfs_binheap_relocate);
/** @} heap */

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
 * Copyright (c) 2017, DDN Storage Corporation.
 */
/*
 *
 * Persistent Client Cache
 *
 * Author: Li Xi <lixi@ddn.com>
 */

#ifndef LLITE_PCC_H
#define LLITE_PCC_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <uapi/linux/lustre/lustre_user.h>

extern struct kmem_cache *pcc_inode_slab;

#define LPROCFS_WR_PCC_MAX_CMD 4096

/* User/Group/Project ID */
struct pcc_match_id {
	u32			pmi_id;
	struct list_head	pmi_linkage;
};

/* wildcard file name */
struct pcc_match_fname {
	char			*pmf_name;
	struct list_head	 pmf_linkage;
};

enum pcc_field {
	PCC_FIELD_UID,
	PCC_FIELD_GID,
	PCC_FIELD_PROJID,
	PCC_FIELD_FNAME,
	PCC_FIELD_MAX
};

struct pcc_expression {
	enum pcc_field		pe_field;
	struct list_head	pe_cond;
	struct list_head	pe_linkage;
};

struct pcc_conjunction {
	/* link to disjunction */
	struct list_head	pc_linkage;
	/* list of logical conjunction */
	struct list_head	pc_expressions;
};

/**
 * Match rule for auto PCC-cached files.
 */
struct pcc_match_rule {
	char			*pmr_conds_str;
	struct list_head	 pmr_conds;
};

struct pcc_matcher {
	u32		 pm_uid;
	u32		 pm_gid;
	u32		 pm_projid;
	struct qstr	*pm_name;
};

struct pcc_dataset {
	u32			pccd_rwid;	 /* Archive ID */
	u32			pccd_roid;	 /* Readonly ID */
	struct pcc_match_rule	pccd_rule;	 /* Match rule */
	u32			pccd_rwonly:1, /* Only use as RW-PCC */
				pccd_roonly:1; /* Only use as RO-PCC */
	char			pccd_pathname[PATH_MAX]; /* full path */
	struct path		pccd_path;	 /* Root path */
	struct list_head	pccd_linkage;  /* Linked to pccs_datasets */
	atomic_t		pccd_refcount; /* Reference count */
};

struct pcc_super {
	/* Protect pccs_datasets */
	spinlock_t		 pccs_lock;
	/* List of datasets */
	struct list_head	 pccs_datasets;
	/* creds of process who forced instantiation of super block */
	const struct cred	*pccs_cred;
};

struct pcc_inode {
	struct ll_inode_info	*pcci_lli;
	/* Cache path on local file system */
	struct path		 pcci_path;
	/*
	 * If reference count is 0, then the cache is not inited, if 1, then
	 * no one is using it.
	 */
	atomic_t		 pcci_refcount;
	/* Whether readonly or readwrite PCC */
	enum lu_pcc_type	 pcci_type;
	/* Whether the inode attr is cached locally */
	bool			 pcci_attr_valid;
	/* Layout generation */
	u32			 pcci_layout_gen;
	/*
	 * How many IOs are on going on this cached object. Layout can be
	 * changed only if there is no active IO.
	 */
	atomic_t		 pcci_active_ios;
	/* Waitq - wait for PCC I/O completion. */
	wait_queue_head_t	 pcci_waitq;
};

struct pcc_file {
	/* Opened cache file */
	struct file		*pccf_file;
	/* Whether readonly or readwrite PCC */
	enum lu_pcc_type	 pccf_type;
};

enum pcc_cmd_type {
	PCC_ADD_DATASET = 0,
	PCC_DEL_DATASET,
	PCC_CLEAR_ALL,
};

struct pcc_cmd {
	enum pcc_cmd_type			 pccc_cmd;
	char					*pccc_pathname;
	union {
		struct pcc_cmd_add {
			u32			 pccc_rwid;
			u32			 pccc_roid;
			struct list_head	 pccc_conds;
			char			*pccc_conds_str;
		} pccc_add;
		struct pcc_cmd_del {
			u32			 pccc_pad;
		} pccc_del;
	} u;
};

int pcc_super_init(struct pcc_super *super);
void pcc_super_fini(struct pcc_super *super);
int pcc_cmd_handle(char *buffer, unsigned long count,
		   struct pcc_super *super);
int pcc_super_dump(struct pcc_super *super, struct seq_file *m);
int pcc_readwrite_attach(struct file *file, struct inode *inode,
			 u32 arch_id);
int pcc_readwrite_attach_fini(struct file *file, struct inode *inode,
			      u32 gen, bool lease_broken, int rc,
			      bool attached);
int pcc_ioctl_detach(struct inode *inode);
int pcc_ioctl_state(struct file *file, struct inode *inode,
		    struct lu_pcc_state *state);
void pcc_file_init(struct pcc_file *pccf);
int pcc_file_open(struct inode *inode, struct file *file);
void pcc_file_release(struct inode *inode, struct file *file);
ssize_t pcc_file_read_iter(struct kiocb *iocb, struct iov_iter *iter,
			   bool *cached);
ssize_t pcc_file_write_iter(struct kiocb *iocb, struct iov_iter *iter,
			    bool *cached);
int pcc_inode_getattr(struct inode *inode, bool *cached);
int pcc_inode_setattr(struct inode *inode, struct iattr *attr, bool *cached);
ssize_t pcc_file_splice_read(struct file *in_file, loff_t *ppos,
			     struct pipe_inode_info *pipe, size_t count,
			     unsigned int flags, bool *cached);
int pcc_fsync(struct file *file, loff_t start, loff_t end,
	      int datasync, bool *cached);
int pcc_file_mmap(struct file *file, struct vm_area_struct *vma, bool *cached);
void pcc_vm_open(struct vm_area_struct *vma);
void pcc_vm_close(struct vm_area_struct *vma);
int pcc_fault(struct vm_area_struct *mva, struct vm_fault *vmf, bool *cached);
int pcc_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
		     bool *cached);
int pcc_inode_create(struct super_block *sb, struct pcc_dataset *dataset,
		     struct lu_fid *fid, struct dentry **pcc_dentry);
int pcc_inode_create_fini(struct pcc_dataset *dataset, struct inode *inode,
			   struct dentry *pcc_dentry);
struct pcc_dataset *pcc_dataset_match_get(struct pcc_super *super,
					  struct pcc_matcher *matcher);
void pcc_dataset_put(struct pcc_dataset *dataset);
void pcc_inode_free(struct inode *inode);
void pcc_layout_invalidate(struct inode *inode);

#endif /* LLITE_PCC_H */

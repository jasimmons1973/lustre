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
 * Copyright (c) 2020 Intel Corporation.
 */
/*
 * Foreign symlink implementation.
 *
 * Methods in this source file allow to construct a relative path from the
 * LOV/LMV foreign content, to complement it with a prefix, and then to
 * expose it to the VFS as a symlink destination.
 * The default/internal mechanism simply takes the full foreign free string
 * as the relative path, and for more complex internal formats an upcall has
 * been implemented to provide format's details (presently just in terms of
 * constant strings and substrings positions in EA, but this can be enhanced)
 * to llite layer.
 */

#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/version.h>
#define DEBUG_SUBSYSTEM S_LLITE

#include "llite_internal.h"

/* allocate space for "/<prefix>/<suffix>'\0'" and copy prefix in,
 * returns start position for suffix in *destname
 * must be called with ll_foreign_symlink_sem locked for read, to
 * protect against sbi->ll_foreign_symlink_prefix change
 * on output, provides position where to start prefix complement
 */
static int foreign_symlink_alloc_and_copy_prefix(struct ll_sb_info *sbi,
						 struct inode *inode,
						 char **destname,
						 size_t suffix_size)
{
	size_t prefix_size, full_size;

	/* allocate enough for "/<prefix>/<suffix>'\0'" */
	prefix_size = sbi->ll_foreign_symlink_prefix_size - 1;
	full_size = suffix_size + prefix_size + 3;
	if (full_size > PATH_MAX) {
		CERROR("%s: inode "DFID": resolved destination path too long\n",
		       sbi->ll_fsname, PFID(ll_inode2fid(inode)));
		return -EINVAL;
	}
	*destname = kzalloc(full_size, GFP_KERNEL);
	if (!*destname)
		return -ENOMEM;

	memcpy(*destname + 1, sbi->ll_foreign_symlink_prefix,
	       prefix_size);
	(*destname)[0] = '/';
	(*destname)[prefix_size + 1] = '/';

	return prefix_size + 2;
}

/* if no upcall registered, default foreign symlink parsing method
 * is to use the full lfm_value as a relative path to complement
 * foreign_prefix
 */
static int ll_foreign_symlink_default_parse(struct ll_sb_info *sbi,
					    struct inode *inode,
					    struct lov_foreign_md *lfm,
					    char **destname)
{
	int suffix_pos;

	down_read(&sbi->ll_foreign_symlink_sem);
	suffix_pos = foreign_symlink_alloc_and_copy_prefix(sbi, inode,
							   destname,
							   lfm->lfm_length);
	up_read(&sbi->ll_foreign_symlink_sem);

	if (suffix_pos < 0)
		return suffix_pos;

	memcpy(*destname + suffix_pos, lfm->lfm_value,
	       lfm->lfm_length);
	(*destname)[suffix_pos + lfm->lfm_length] = '\0';

	return 0;
}

/* if an upcall has been registered, foreign symlink will be
 * constructed as per upcall provided format
 * presently we only support a serie of constant strings and sub-strings
 * to be taken from lfm_value content
 */
static int ll_foreign_symlink_upcall_parse(struct ll_sb_info *sbi,
					   struct inode *inode,
					   struct lov_foreign_md *lfm,
					   char **destname)
{
	int pos = 0, suffix_pos = -1, items_size = 0;
	struct ll_foreign_symlink_upcall_item *foreign_symlink_items =
			sbi->ll_foreign_symlink_upcall_items;
	int i = 0, rc = 0;

	down_read(&sbi->ll_foreign_symlink_sem);

	/* compute size of relative path of destination path
	 * could be done once during upcall items/infos reading
	 * and stored as new ll_sb_info field
	 */
	for (i = 0; i < sbi->ll_foreign_symlink_upcall_nb_items; i++) {
		switch (foreign_symlink_items[i].type) {
		case STRING_TYPE:
			items_size += foreign_symlink_items[i].size;
			break;
		case POSLEN_TYPE:
			items_size += foreign_symlink_items[i].len;
			break;
		case EOB_TYPE:
			/* should be the last item */
			break;
		default:
			CERROR("%s: unexpected type '%u' found in items\n",
			       sbi->ll_fsname, foreign_symlink_items[i].type);
			rc = -EINVAL;
			goto failed;
		}
	}

	suffix_pos = foreign_symlink_alloc_and_copy_prefix(sbi, inode, destname,
							   items_size);
	if (suffix_pos < 0) {
		rc = suffix_pos;
		goto failed;
	}

	/* rescan foreign_symlink_items[] to create faked symlink dest path */
	i = 0;
	while (foreign_symlink_items[i].type != EOB_TYPE) {
		if (foreign_symlink_items[i].type == STRING_TYPE) {
			memcpy(*destname + suffix_pos + pos,
			       foreign_symlink_items[i].string,
			       foreign_symlink_items[i].size);
			pos += foreign_symlink_items[i].size;
		} else if (foreign_symlink_items[i].type == POSLEN_TYPE) {
			if (lfm->lfm_length < foreign_symlink_items[i].pos +
					      foreign_symlink_items[i].len) {
				CERROR("%s:  "DFID" foreign EA too short to find (%u,%u) item\n",
				       sbi->ll_fsname,
				       PFID(ll_inode2fid(inode)),
				       foreign_symlink_items[i].pos,
				       foreign_symlink_items[i].len);
				rc = -EINVAL;
				goto failed;
			}
			memcpy(*destname + suffix_pos + pos,
			       lfm->lfm_value + foreign_symlink_items[i].pos,
			       foreign_symlink_items[i].len);
			pos += foreign_symlink_items[i].len;
		} else {
			CERROR("%s: unexpected type '%u' found in items\n",
			       sbi->ll_fsname, foreign_symlink_items[i].type);
			rc = -EINVAL;
			goto failed;
		}
		i++;
	}
failed:
	up_read(&sbi->ll_foreign_symlink_sem);

	if (rc != 0 && suffix_pos >= 0) {
		kvfree(*destname);
		*destname = NULL;
	}

	return rc;
}

static int ll_foreign_symlink_parse(struct ll_sb_info *sbi,
				    struct inode *inode,
				    struct lov_foreign_md *lfm,
				    char **destname)
{
	int rc;

	/* if no user-land upcall registered, assuming whole free field
	 * of foreign LOV is relative path of faked symlink destination,
	 * to be completed by prefix
	 */
	if (!(sbi->ll_flags & LL_SBI_FOREIGN_SYMLINK_UPCALL))
		rc = ll_foreign_symlink_default_parse(sbi, inode, lfm,
						      destname);
	else /* upcall is available */
		rc = ll_foreign_symlink_upcall_parse(sbi, inode, lfm,
						     destname);
	return rc;
}

/* Don't need lli_size_mutex locked as LOV/LMV are EAs
 * and should not be stored in data blocks
 */
static int ll_foreign_readlink_internal(struct inode *inode, char **symname)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct lov_foreign_md *lfm = NULL;
	char *destname = NULL;
	size_t lfm_size = 0;
	int rc;

	if (S_ISREG(inode->i_mode)) {
		struct cl_object *obj = lli->lli_clob;
		struct cl_layout cl = {
			.cl_buf.lb_len = 0, /* to get real size */
		};
		struct lu_env *env;
		u16 refcheck;

		if (!obj) {
			CERROR("%s: inode "DFID": can not get layout, no cl_object\n",
			       sbi->ll_fsname, PFID(ll_inode2fid(inode)));
			rc = -EINVAL;
			goto failed;
		}

		env = cl_env_get(&refcheck);
		if (IS_ERR(env))
			return PTR_ERR(env);
		/* get layout size */
		rc = cl_object_layout_get(env, obj, &cl);
		if (rc <= 0) {
			CERROR("%s: inode "DFID": error trying to get layout size : %d\n",
			       sbi->ll_fsname, PFID(ll_inode2fid(inode)), rc);
			cl_env_put(env, &refcheck);
			return rc;
		}
		lfm = kzalloc(rc, GFP_KERNEL);
		if (!lfm) {
			CERROR("%s: inode "DFID": can not allocate enough mem to get layout\n",
			       sbi->ll_fsname, PFID(ll_inode2fid(inode)));
			cl_env_put(env, &refcheck);
			return -ENOMEM;
		}
		cl.cl_buf.lb_len = rc;
		cl.cl_buf.lb_buf = lfm;
		/* get layout */
		rc = cl_object_layout_get(env, obj, &cl);
		if (rc <= 0) {
			CERROR("%s: inode "DFID": error trying to get layout : %d\n",
			       sbi->ll_fsname, PFID(ll_inode2fid(inode)), rc);
			kfree(lfm);
			cl_env_put(env, &refcheck);
			return rc;
		}
		lfm_size = cl.cl_buf.lb_len;
		cl_env_put(env, &refcheck);
	} else if (S_ISDIR(inode->i_mode)) {
		down_read(&lli->lli_lsm_sem);

		/* should be casted lmv_foreign_md, but it is ok as both foreign LOV
		 * and LMV formats are identical, and then we also only need
		 * one set of parsing routines for both foreign files and dirs!
		 */
		lfm = (struct lov_foreign_md *)(lli->lli_lsm_md);
		if (lfm) {
			CDEBUG(D_INFO, "%s: inode "DFID": LMV cached found\n",
			       sbi->ll_fsname, PFID(ll_inode2fid(inode)));
		} else {
			CERROR("%s: inode "DFID": cannot get layout, no LMV cached\n",
			       sbi->ll_fsname, PFID(ll_inode2fid(inode)));
			rc = -EINVAL;
			goto failed;
		}
	} else {
		CERROR("%s: inode "DFID": not a regular file nor directory\n",
		       sbi->ll_fsname, PFID(ll_inode2fid(inode)));
		rc = -EINVAL;
		goto failed;
	}

	/* XXX no assert nor double check of magic, length and type ? */

	rc = ll_foreign_symlink_parse(sbi, inode, lfm, &destname);
failed:
	if (S_ISDIR(inode->i_mode))
		up_read(&lli->lli_lsm_sem);

	if (S_ISREG(inode->i_mode) && lfm)
		kfree(lfm);

	if (!rc) {
		*symname = destname;
		CDEBUG(D_INFO,
		       "%s: inode "DFID": faking symlink to dest '%s'\n",
		       sbi->ll_fsname, PFID(ll_inode2fid(inode)), destname);
	}

	return rc;
}

static void ll_foreign_put_link(void *cookie)
{
	/* to avoid allocating an unnecessary big buffer, and since ways to
	 * build the symlink path from foreign LOV/LMV can be multiple and
	 * not constant. So it size is not known and we need to use
	 * strlen(cookie)+1 to determine its size and to avoid false positive
	 * to be reported by memory leak check code
	 */
	kvfree(cookie);
}

static const char *ll_foreign_get_link(struct dentry *dentry,
				       struct inode *inode,
				       struct delayed_call *done)
{
	char *symname = NULL;
	int rc;

	CDEBUG(D_VFSTRACE, "VFS Op\n");
	if (!dentry)
		return ERR_PTR(-ECHILD);
	rc = ll_foreign_readlink_internal(inode, &symname);

	/*
	 * symname must be freed when we are done
	 *
	 * XXX we may avoid the need to do so if we use
	 * lli_symlink_name cache to retain symname and
	 * let ll_clear_inode free it...
	 */
	set_delayed_call(done, ll_foreign_put_link, symname);
	return rc ? ERR_PTR(rc) : symname;
}

/*
 * Should only be called for already in-use/cache foreign dir inode
 * when foreign fake-symlink behaviour has been enabled afterward
 */
static struct dentry *ll_foreign_dir_lookup(struct inode *parent,
					 struct dentry *dentry,
					 unsigned int flags)
{
	CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s, dir="DFID"(%p)\n",
	       dentry->d_name.len, dentry->d_name.name,
	       PFID(ll_inode2fid(parent)), parent);

	return ERR_PTR(-ENODATA);
}

static bool has_same_mount_namespace(struct ll_sb_info *sbi)
{
	int rc;

	rc = (sbi->ll_mnt.mnt == current->fs->root.mnt);
	if (!rc)
		LCONSOLE_WARN("%s: client mount %s and '%s.%d' not in same mnt-namespace\n",
			      sbi->ll_fsname, sbi->ll_kset.kobj.name,
			      current->comm, current->pid);

	return rc;
}

ssize_t foreign_symlink_enable_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%d\n",
			!!(sbi->ll_flags & LL_SBI_FOREIGN_SYMLINK));
}

/*
 * XXX
 * There should be already in-use/cached inodes of foreign files/dirs who
 * will not-be/continue-to-be handled as fake-symlink, depending if
 * feature is being enabled/disabled, until being revalidated.
 * Also, does it require sbi->ll_lock protection ?
 */
ssize_t foreign_symlink_enable_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	if (!has_same_mount_namespace(sbi))
		return -EINVAL;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	if (val)
		sbi->ll_flags |= LL_SBI_FOREIGN_SYMLINK;
	else
		sbi->ll_flags &= ~LL_SBI_FOREIGN_SYMLINK;

	return count;
}

ssize_t foreign_symlink_prefix_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	ssize_t size;

	down_read(&sbi->ll_foreign_symlink_sem);
	size = snprintf(buf, PAGE_SIZE, "%s\n", sbi->ll_foreign_symlink_prefix);
	up_read(&sbi->ll_foreign_symlink_sem);

	return size;
}

ssize_t foreign_symlink_prefix_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	char *new, *old;
	size_t new_len, old_len;

	if (!has_same_mount_namespace(sbi))
		return -EINVAL;

	/* XXX strip buffer of any CR/LF,space,... ?? */

	/* check buffer looks like a valid absolute path */
	if (*buffer != '/') {
		CERROR("foreign symlink prefix must be an absolute path\n");
		return -EINVAL;
	}
	new_len = strnlen(buffer, count);
	if (new_len < count)
		CDEBUG(D_INFO, "NUL byte found in %zu bytes\n", count);
	if (new_len > PATH_MAX) {
		CERROR("%s: foreign symlink prefix length %zu > PATH_MAX\n",
		       sbi->ll_fsname, new_len);
		return -EINVAL;
	}
	new = kzalloc(new_len + 1, GFP_KERNEL);
	if (!new) {
		CERROR("%s: can not allocate space for foreign path prefix\n",
		       sbi->ll_fsname);
		return -ENOSPC;
	}

	down_write(&sbi->ll_foreign_symlink_sem);
	old_len = sbi->ll_foreign_symlink_prefix_size;
	old = sbi->ll_foreign_symlink_prefix;
	memcpy(new, buffer, new_len);
	*(new + new_len) = '\0';

	sbi->ll_foreign_symlink_prefix = new;
	sbi->ll_foreign_symlink_prefix_size = new_len + 1;
	up_write(&sbi->ll_foreign_symlink_sem);

	kfree(old);

	return new_len;
}

ssize_t foreign_symlink_upcall_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	ssize_t size;
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	down_read(&sbi->ll_foreign_symlink_sem);
	size = snprintf(buf, PAGE_SIZE, "%s\n", sbi->ll_foreign_symlink_upcall);
	up_read(&sbi->ll_foreign_symlink_sem);

	return size;
}

ssize_t foreign_symlink_upcall_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	char *old = NULL, *new = NULL;
	size_t new_len;

	if (!has_same_mount_namespace(sbi))
		return -EINVAL;

	/* XXX strip buffer of any CR/LF,space,... ?? */

	/* check buffer looks like a valid absolute path */
	if (*buffer != '/' && strcmp(buffer, "none")) {
		CERROR("foreign symlink upcall must be an absolute path\n");
		return -EINVAL;
	}
	new_len = strnlen(buffer, count);
	if (new_len < count)
		CDEBUG(D_INFO, "NULL byte found in %zu bytes\n", count);
	if (new_len > PATH_MAX) {
		CERROR("%s: foreign symlink upcall path length %zu > PATH_MAX\n",
		       sbi->ll_fsname, new_len);
		return -EINVAL;
	}

	new = kzalloc(new_len + 1, GFP_KERNEL);
	if (!new) {
		CERROR("%s: can not allocate space for foreign symlink upcall path\n",
		       sbi->ll_fsname);
		return -ENOSPC;
	}
	memcpy(new, buffer, new_len);
	*(new + new_len) = '\0';

	down_write(&sbi->ll_foreign_symlink_sem);
	old = sbi->ll_foreign_symlink_upcall;

	sbi->ll_foreign_symlink_upcall = new;
	/* LL_SBI_FOREIGN_SYMLINK_UPCALL will be set by
	 * foreign_symlink_upcall_info_store() upon valid being provided
	 * by upcall
	 * XXX there is a potential race if there are multiple concurent
	 * attempts to set upcall path and execution occur in different
	 * order, we may end up using the format provided by a different
	 * upcall than the one set in ll_foreign_symlink_upcall
	 */
	sbi->ll_flags &= ~LL_SBI_FOREIGN_SYMLINK_UPCALL;
	up_write(&sbi->ll_foreign_symlink_sem);

	if (strcmp(new, "none")) {
		char *argv[] = {
			  [0] = new,
			  /* sbi sysfs object name */
			  [1] = (char *)sbi->ll_kset.kobj.name,
			  [2] = NULL
		};
		char *envp[] = {
			  [0] = "HOME=/",
			  [1] = "PATH=/sbin:/usr/sbin",
			  [2] = NULL
		};
		int rc;

		rc = call_usermodehelper(new, argv, envp, UMH_WAIT_EXEC);
		if (rc < 0)
			CERROR("%s: error invoking foreign symlink upcall %s: rc %d\n",
			       sbi->ll_fsname, new, rc);
		else
			CDEBUG(D_INFO, "%s: invoked upcall %s\n",
			       sbi->ll_fsname, new);
	}

	kvfree(old);

	return new_len;
}

/* foreign_symlink_upcall_info_store() stores format items in
 * foreign_symlink_items[], and foreign_symlink_upcall_parse()
 * uses it to parse each foreign symlink LOV/LMV EAs
 */
ssize_t foreign_symlink_upcall_info_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct ll_foreign_symlink_upcall_item items[MAX_NB_UPCALL_ITEMS], *item;
	struct ll_foreign_symlink_upcall_item *new_items, *old_items;
	size_t remaining = count;
	int nb_items = 0, old_nb_items, i, rc = 0;

	if (!has_same_mount_namespace(sbi))
		return -EINVAL;

	/* parse buffer to check validity of infos and fill symlink format
	 * descriptors
	 */

	if (count % sizeof(u32) != 0) {
		CERROR("%s: invalid size '%zu' of infos buffer returned by foreign symlink upcall\n",
		       sbi->ll_fsname, count);
		return -EINVAL;
	}

	/* evaluate number of items provided */
	while (remaining > 0) {
		item = (struct ll_foreign_symlink_upcall_item *)
				&buffer[count - remaining];
		switch (item->type) {
		case STRING_TYPE: {
			/* a constant string following */
			if (item->size >= remaining -
			    offsetof(struct ll_foreign_symlink_upcall_item,
				     bytestring) - sizeof(item->type)) {
				/* size of string must not overflow remaining
				 * bytes minus EOB_TYPE item
				 */
				CERROR("%s: constant string too long in infos buffer returned by foreign symlink upcall\n",
				       sbi->ll_fsname);
				rc = -EINVAL;
				goto failed;
			}
			items[nb_items].string = kzalloc(item->size,
							 GFP_KERNEL);
			if (!items[nb_items].string) {
				CERROR("%s: constant string allocation has failed for constant string of size %zu\n",
				       sbi->ll_fsname, item->size);
				rc = -ENOMEM;
				goto failed;
			}
			memcpy(items[nb_items].string,
			       item->bytestring, item->size);
			items[nb_items].size = item->size;
			/* string items to fit on u32 boundary */
			remaining = remaining - STRING_ITEM_SZ(item->size);
			break;
		}
		case POSLEN_TYPE: {
			/* a tuple (pos,len) following to delimit a sub-string
			 * in lfm_value
			 */
			items[nb_items].pos = item->pos;
			items[nb_items].len = item->len;
			remaining -= POSLEN_ITEM_SZ;
			break;
		}
		case EOB_TYPE:
			if (remaining != sizeof(item->type)) {
				CERROR("%s: early end of infos buffer returned by foreign symlink upcall\n",
				       sbi->ll_fsname);
				rc = -EINVAL;
				goto failed;
			}
			remaining -= sizeof(item->type);
			break;
		default:
			CERROR("%s: wrong type '%u' encountered at pos %zu , with %zu remaining bytes, in infos buffer returned by foreign symlink upcall\n",
			       sbi->ll_fsname, (u32)buffer[count - remaining],
			       count - remaining, remaining);
			rc = -EINVAL;
			goto failed;
		}

		items[nb_items].type = item->type;
		nb_items++;
		if (nb_items >= MAX_NB_UPCALL_ITEMS) {
			CERROR("%s: too many items in infos buffer returned by foreign symlink upcall\n",
			       sbi->ll_fsname);
			rc = -EINVAL;
			goto failed;
		}
	}
	/* valid format has been provided by foreign symlink user upcall */
	new_items = kvmalloc_array(nb_items,
				   sizeof(struct ll_foreign_symlink_upcall_item),
				   GFP_KERNEL);
	if (!new_items) {
		CERROR("%s: constant string allocation has failed for constant string of size %zu\n",
		       sbi->ll_fsname, nb_items *
			sizeof(struct ll_foreign_symlink_upcall_item));
		rc = -ENOMEM;
		goto failed;
	}
	for (i = 0; i < nb_items; i++)
		*((struct ll_foreign_symlink_upcall_item *)new_items + i) =
			items[i];

	down_write(&sbi->ll_foreign_symlink_sem);
	old_items = sbi->ll_foreign_symlink_upcall_items;
	old_nb_items = sbi->ll_foreign_symlink_upcall_nb_items;
	sbi->ll_foreign_symlink_upcall_items = new_items;
	sbi->ll_foreign_symlink_upcall_nb_items = nb_items;
	sbi->ll_flags |= LL_SBI_FOREIGN_SYMLINK_UPCALL;
	up_write(&sbi->ll_foreign_symlink_sem);

	/* free old_items */
	if (old_items) {
		for (i = 0 ; i < old_nb_items; i++)
			if (old_items[i].type == STRING_TYPE)
				kfree(old_items[i].string);

		kvfree(old_items);
	}

failed:
	/* clean items[] and free any strings */
	if (rc != 0) {
		for (i = 0; i < nb_items; i++) {
			switch (items[i].type) {
			case STRING_TYPE:
				kfree(items[i].string);
				items[i].string = NULL;
				items[i].size = 0;
				break;
			case POSLEN_TYPE:
				items[i].pos = 0;
				items[i].len = 0;
				break;
			case EOB_TYPE:
				break;
			default:
				CERROR("%s: wrong '%u'type encountered in foreign symlink upcall items\n",
				       sbi->ll_fsname, items[i].type);
				rc = -EINVAL;
				goto failed;
			}
			items[i].type = 0;
		}
	}

	return rc == 0 ? count : rc;
}

static int ll_foreign_symlink_getattr(const struct path *path, struct kstat *stat,
				      u32 request_mask, unsigned int flags)
{
	return ll_getattr_dentry(path->dentry, stat, request_mask, flags,
				 true);
}

const struct inode_operations ll_foreign_file_symlink_inode_operations = {
	.setattr	= ll_setattr,
	.get_link	= ll_foreign_get_link,
	.getattr	= ll_foreign_symlink_getattr,
	.permission	= ll_inode_permission,
	.listxattr	= ll_listxattr,
};

const struct inode_operations ll_foreign_dir_symlink_inode_operations = {
	.lookup		= ll_foreign_dir_lookup,
	.setattr	= ll_setattr,
	.get_link	= ll_foreign_get_link,
	.getattr	= ll_foreign_symlink_getattr,
	.permission	= ll_inode_permission,
	.listxattr	= ll_listxattr,
};

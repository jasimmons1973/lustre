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

#ifndef LLITE_FOREIGN_SYMLINK_H
#define LLITE_FOREIGN_SYMLINK_H

/* llite/llite_foreign_symlink.c */
ssize_t foreign_symlink_enable_show(struct kobject *kobj,
				    struct attribute *attr, char *buf);
ssize_t foreign_symlink_enable_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count);
ssize_t foreign_symlink_prefix_show(struct kobject *kobj,
				    struct attribute *attr, char *buf);
ssize_t foreign_symlink_prefix_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count);
ssize_t foreign_symlink_upcall_show(struct kobject *kobj,
				    struct attribute *attr, char *buf);
ssize_t foreign_symlink_upcall_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count);
ssize_t foreign_symlink_upcall_info_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count);
extern const struct inode_operations ll_foreign_file_symlink_inode_operations;
extern const struct inode_operations ll_foreign_dir_symlink_inode_operations;

#endif /* LLITE_FOREIGN_SYMLINK_H */

# SPDX-License-Identifier: GPL-2.0
ccflags-y += -I$(srctree)/$(src)/../include

obj-$(CONFIG_LUSTRE_FS) += lustre.o
lustre-y := dcache.o dir.o file.o llite_lib.o llite_nfs.o \
	    rw.o rw26.o namei.o symlink.o llite_mmap.o \
	    xattr.o xattr_cache.o xattr_security.o \
	    super25.o statahead.o glimpse.o lcommon_cl.o lcommon_misc.o \
	    vvp_dev.o vvp_page.o vvp_io.o vvp_object.o \
	    llite_foreign.o llite_foreign_symlink.o \
	    lproc_llite.o pcc.o

lustre-$(CONFIG_LUSTRE_FS_POSIX_ACL) += acl.o
lustre-$(CONFIG_FS_ENCRYPTION)	     += crypto.o

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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/libcfs/debug.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 *
 */

# define DEBUG_SUBSYSTEM S_LNET

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/libcfs/libcfs_string.h>
#include <linux/kthread.h>
#include <linux/stacktrace.h>
#include <linux/utsname.h>
#include "tracefile.h"

static char debug_file_name[1024];

unsigned int libcfs_subsystem_debug = LIBCFS_S_DEFAULT;
EXPORT_SYMBOL(libcfs_subsystem_debug);
module_param(libcfs_subsystem_debug, int, 0644);
MODULE_PARM_DESC(libcfs_subsystem_debug, "Lustre kernel debug subsystem mask");

unsigned int libcfs_debug = LIBCFS_D_DEFAULT;
EXPORT_SYMBOL(libcfs_debug);
module_param(libcfs_debug, int, 0644);
MODULE_PARM_DESC(libcfs_debug, "Lustre kernel debug mask");

static int libcfs_param_debug_mb_set(const char *val,
				     const struct kernel_param *kp)
{
	int rc;
	unsigned int num;

	rc = kstrtouint(val, 0, &num);
	if (rc < 0)
		return rc;

	num = cfs_trace_set_debug_mb(num);

	*((unsigned int *)kp->arg) = num;
	num = cfs_trace_get_debug_mb();
	if (num)
		/* This value is more precise */
		*((unsigned int *)kp->arg) = num;

	return 0;
}

/* While debug_mb setting look like unsigned int, in fact
 * it needs quite a bunch of extra processing, so we define special
 * debug_mb parameter type with corresponding methods to handle this case
 */
static const struct kernel_param_ops param_ops_debug_mb = {
	.set		= libcfs_param_debug_mb_set,
	.get		= param_get_uint,
};

#define param_check_debug_mb(name, p) \
		__param_check(name, p, unsigned int)

static unsigned int libcfs_debug_mb;
module_param(libcfs_debug_mb, debug_mb, 0644);
MODULE_PARM_DESC(libcfs_debug_mb, "Total debug buffer size.");

unsigned int libcfs_printk = D_CANTMASK;
module_param(libcfs_printk, uint, 0644);
MODULE_PARM_DESC(libcfs_printk, "Lustre kernel debug console mask");

unsigned int libcfs_console_ratelimit = 1;
module_param(libcfs_console_ratelimit, uint, 0644);
MODULE_PARM_DESC(libcfs_console_ratelimit, "Lustre kernel debug console ratelimit (0 to disable)");

static int param_set_delay_minmax(const char *val,
				  const struct kernel_param *kp,
				  long min, long max)
{
	long d;
	int sec;
	int rc;

	rc = kstrtoint(val, 0, &sec);
	if (rc)
		return -EINVAL;

	d = sec * HZ / 100;
	if (d < min || d > max)
		return -EINVAL;

	*((unsigned int *)kp->arg) = d;

	return 0;
}

static int param_get_delay(char *buffer, const struct kernel_param *kp)
{
	unsigned int d = *(unsigned int *)kp->arg;

	param_get_byte(buffer, kp);
	return sprintf(buffer, "%lu%c", jiffies_to_msecs(d * 10) / MSEC_PER_SEC,
		       strnchr(buffer, PAGE_SIZE, '\n') ? '\n' : '\0');
}

unsigned int libcfs_console_max_delay;
unsigned int libcfs_console_min_delay;

static int param_set_console_max_delay(const char *val,
				       const struct kernel_param *kp)
{
	return param_set_delay_minmax(val, kp,
				      libcfs_console_min_delay, INT_MAX);
}

static const struct kernel_param_ops param_ops_console_max_delay = {
	.set		= param_set_console_max_delay,
	.get		= param_get_delay,
};

#define param_check_console_max_delay(name, p) \
		__param_check(name, p, unsigned int)

module_param(libcfs_console_max_delay, console_max_delay, 0644);
MODULE_PARM_DESC(libcfs_console_max_delay, "Lustre kernel debug console max delay (jiffies)");

static int param_set_console_min_delay(const char *val,
				       const struct kernel_param *kp)
{
	return param_set_delay_minmax(val, kp,
				      1, libcfs_console_max_delay);
}

static const struct kernel_param_ops param_ops_console_min_delay = {
	.set		= param_set_console_min_delay,
	.get		= param_get_delay,
};

#define param_check_console_min_delay(name, p) \
		__param_check(name, p, unsigned int)

module_param(libcfs_console_min_delay, console_min_delay, 0644);
MODULE_PARM_DESC(libcfs_console_min_delay, "Lustre kernel debug console min delay (jiffies)");

static int param_set_uint_minmax(const char *val,
				 const struct kernel_param *kp,
				 unsigned int min, unsigned int max)
{
	unsigned int num;
	int ret;

	if (!val)
		return -EINVAL;

	ret = kstrtouint(val, 0, &num);
	if (ret < 0 || num < min || num > max)
		return -EINVAL;

	*((unsigned int *)kp->arg) = num;
	return 0;
}

static int param_set_uintpos(const char *val, const struct kernel_param *kp)
{
	return param_set_uint_minmax(val, kp, 1, -1);
}

static const struct kernel_param_ops param_ops_uintpos = {
	.set		= param_set_uintpos,
	.get		= param_get_uint,
};

#define param_check_uintpos(name, p) \
		__param_check(name, p, unsigned int)

unsigned int libcfs_console_backoff = CDEBUG_DEFAULT_BACKOFF;
module_param(libcfs_console_backoff, uintpos, 0644);
MODULE_PARM_DESC(libcfs_console_backoff, "Lustre kernel debug console backoff factor");

unsigned int libcfs_debug_binary = 1;

unsigned int libcfs_stack = 3 * THREAD_SIZE / 4;
EXPORT_SYMBOL(libcfs_stack);

unsigned int libcfs_catastrophe;
EXPORT_SYMBOL(libcfs_catastrophe);

unsigned int libcfs_watchdog_ratelimit = 300;
EXPORT_SYMBOL(libcfs_watchdog_ratelimit);

unsigned int libcfs_panic_on_lbug = 1;
module_param(libcfs_panic_on_lbug, uint, 0644);
MODULE_PARM_DESC(libcfs_panic_on_lbug, "Lustre kernel panic on LBUG");

static DECLARE_COMPLETION(debug_complete);

/* We need to pass a pointer here, but elsewhere this must be a const */
char *libcfs_debug_file_path = LIBCFS_DEBUG_FILE_PATH_DEFAULT;
EXPORT_SYMBOL(libcfs_debug_file_path);
module_param(libcfs_debug_file_path, charp, 0644);
MODULE_PARM_DESC(libcfs_debug_file_path,
		 "Path for dumping debug logs, set 'NONE' to prevent log dumping");

int libcfs_panic_in_progress;

/* libcfs_debug_token2mask() expects the returned string in lower-case */
static const char *libcfs_debug_subsys2str(int subsys)
{
	static const char *const libcfs_debug_subsystems[] =
		LIBCFS_DEBUG_SUBSYS_NAMES;

	if (subsys >= ARRAY_SIZE(libcfs_debug_subsystems))
		return NULL;

	return libcfs_debug_subsystems[subsys];
}

/* libcfs_debug_token2mask() expects the returned string in lower-case */
static const char *libcfs_debug_dbg2str(int debug)
{
	static const char * const libcfs_debug_masks[] =
		LIBCFS_DEBUG_MASKS_NAMES;

	if (debug >= ARRAY_SIZE(libcfs_debug_masks))
		return NULL;

	return libcfs_debug_masks[debug];
}

int
libcfs_debug_mask2str(char *str, int size, int mask, int is_subsys)
{
	const char *(*fn)(int bit) = is_subsys ? libcfs_debug_subsys2str :
						 libcfs_debug_dbg2str;
	int len = 0;
	const char *token;
	int i;

	if (!mask) {			/* "0" */
		if (size > 0)
			str[0] = '0';
		len = 1;
	} else {				/* space-separated tokens */
		for (i = 0; i < 32; i++) {
			if ((mask & BIT(i)) == 0)
				continue;

			token = fn(i);
			if (!token)		/* unused bit */
				continue;

			if (len > 0) {		/* separator? */
				if (len < size)
					str[len] = ' ';
				len++;
			}

			while (*token) {
				if (len < size)
					str[len] = *token;
				token++;
				len++;
			}
		}
	}

	/* terminate 'str' */
	if (len < size)
		str[len] = 0;
	else
		str[size - 1] = 0;

	return len;
}

int
libcfs_debug_str2mask(int *mask, const char *str, int is_subsys)
{
	const char *(*fn)(int bit) = is_subsys ? libcfs_debug_subsys2str :
						 libcfs_debug_dbg2str;
	int m = 0;
	int matched;
	int n;
	int t;

	/* Allow a number for backwards compatibility */

	for (n = strlen(str); n > 0; n--)
		if (!isspace(str[n - 1]))
			break;
	matched = n;
	t = sscanf(str, "%i%n", &m, &matched);
	if (t >= 1 && matched == n) {
		/* don't print warning for lctl set_param debug=0 or -1 */
		if (m && m != -1)
			CWARN("You are trying to use a numerical value for the mask - this will be deprecated in a future release.\n");
		*mask = m;
		return 0;
	}

	return cfs_str2mask(str, fn, mask, is_subsys ? 0 : D_CANTMASK, ~0,
			    is_subsys ? LIBCFS_S_DEFAULT : LIBCFS_D_DEFAULT);
}

char lnet_debug_log_upcall[1024] = "/usr/lib/lustre/lnet_debug_log_upcall";

/**
 * Upcall function once a Lustre log has been dumped.
 *
 * @file	path of the dumped log
 */
static void libcfs_run_debug_log_upcall(char *file)
{
	char *argv[3];
	int rc;
	static const char * const envp[] = {
		"HOME=/",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
		NULL
	};

	argv[0] = lnet_debug_log_upcall;

	LASSERTF(file, "called on a null filename\n");
	argv[1] = file; /* only need to pass the path of the file */

	argv[2] = NULL;

	rc = call_usermodehelper(argv[0], argv, (char **)envp, 1);
	if (rc < 0 && rc != -ENOENT) {
		CERROR("Error %d invoking LNET debug log upcall %s %s; check /sys/kernel/debug/lnet/debug_log_upcall\n",
		       rc, argv[0], argv[1]);
	} else {
		CDEBUG(D_HA, "Invoked LNET debug log upcall %s %s\n",
		       argv[0], argv[1]);
	}
}

/**
 * Dump Lustre log to ::debug_file_path by calling tracefile_dump_all_pages()
 */
static void libcfs_debug_dumplog_internal(void *arg)
{
	static time64_t last_dump_time;
	time64_t current_time;

	current_time = ktime_get_real_seconds();

	if (strncmp(libcfs_debug_file_path, "NONE", 4) != 0 &&
	    current_time > last_dump_time) {
		last_dump_time = current_time;
		snprintf(debug_file_name, sizeof(debug_file_name) - 1,
			 "%s.%lld.%ld", libcfs_debug_file_path,
			 (s64)current_time, (uintptr_t)arg);
		pr_alert("LustreError: dumping log to %s\n", debug_file_name);
		cfs_tracefile_dump_all_pages(debug_file_name);
		libcfs_run_debug_log_upcall(debug_file_name);
	}
}

static int libcfs_debug_dumplog_thread(void *arg)
{
	libcfs_debug_dumplog_internal(arg);
	complete(&debug_complete);
	return 0;
}

static DEFINE_MUTEX(libcfs_debug_dumplog_lock);

void libcfs_debug_dumplog(void)
{
	struct task_struct *dumper;

	if (mutex_trylock(&libcfs_debug_dumplog_lock) == 0)
		return;

	/* If a previous call was interrupted, debug_complete->done
	 * might be elevated, and so we won't actually wait here.
	 * So we reinit the completion to ensure we wait for
	 * one thread to complete, though it might not be the one
	 * we start if there are overlaping thread.
	 */
	init_completion(&debug_complete);
	dumper = kthread_run(libcfs_debug_dumplog_thread,
			     (void *)(long)current->pid,
			     "libcfs_debug_dumper");
	set_current_state(TASK_INTERRUPTIBLE);
	if (IS_ERR(dumper))
		pr_err("LustreError: cannot start log dump thread: rc = %ld\n",
		       PTR_ERR(dumper));
	else
		wait_for_completion_interruptible(&debug_complete);

	mutex_unlock(&libcfs_debug_dumplog_lock);
}
EXPORT_SYMBOL(libcfs_debug_dumplog);

/* coverity[+kill] */
void __noreturn lbug_with_loc(struct libcfs_debug_msg_data *msgdata)
{
	libcfs_catastrophe = 1;
	libcfs_debug_msg(msgdata, "LBUG\n");

	if (in_interrupt()) {
		panic("LBUG in interrupt.\n");
		/* not reached */
	}

	libcfs_debug_dumpstack(NULL);
	if (libcfs_panic_on_lbug)
		panic("LBUG");
	else
		libcfs_debug_dumplog();
	set_current_state(TASK_UNINTERRUPTIBLE);
	while (1)
		schedule();
}
EXPORT_SYMBOL(lbug_with_loc);

#ifdef CONFIG_STACKTRACE

#define MAX_ST_ENTRIES 100
static DEFINE_SPINLOCK(st_lock);

static void libcfs_call_trace(struct task_struct *tsk)
{
	static unsigned long entries[MAX_ST_ENTRIES];
#ifdef CONFIG_ARCH_STACKWALK
	unsigned int nr_entries;

	spin_lock(&st_lock);
	pr_info("Pid: %d, comm: %.20s %s %s\n", tsk->pid, tsk->comm,
		init_utsname()->release, init_utsname()->version);
	pr_info("Call Trace:\n");
	nr_entries = stack_trace_save_tsk(tsk, entries,
					  MAX_ST_ENTRIES, 0);
	stack_trace_print(entries, nr_entries, 0);
	spin_unlock(&st_lock);
#else /* !CONFIG_STACKTRACE */
	struct stack_trace trace;

	trace.nr_entries = 0;
	trace.max_entries = MAX_ST_ENTRIES;
	trace.entries = entries;
	trace.skip = 0;

	spin_lock(&st_lock);
	pr_info("Pid: %d, comm: %.20s %s %s\n", tsk->pid, tsk->comm,
		init_utsname()->release, init_utsname()->version);
	pr_info("Call Trace:\n");
	save_stack_trace_tsk(tsk, &trace);
	stack_trace_print(entries, nr_entries, 0);
	spin_unlock(&st_lock);
#endif
}
#endif /* !CONFIG_STACKTRACE */

void libcfs_debug_dumpstack(struct task_struct *tsk)
{
	libcfs_call_trace(tsk ?: current);
}
EXPORT_SYMBOL(libcfs_debug_dumpstack);

static int panic_notifier(struct notifier_block *self, unsigned long unused1,
			  void *unused2)
{
	if (libcfs_panic_in_progress)
		return 0;

	libcfs_panic_in_progress = 1;
	mb();

#ifdef CONFIG_LNET_DUMP_ON_PANIC
	/* This is currently disabled because it spews far too much to the
	 * console on the rare cases it is ever triggered.
	 */
	if (in_interrupt())
		cfs_trace_debug_print();
	else
		libcfs_debug_dumplog_internal((void *)(long)current->pid);
#endif
	return 0;
}

static struct notifier_block libcfs_panic_notifier = {
	.notifier_call		= panic_notifier,
	.next			= NULL,
	.priority		= 10000,
};

static void libcfs_register_panic_notifier(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
				       &libcfs_panic_notifier);
}

static void libcfs_unregister_panic_notifier(void)
{
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &libcfs_panic_notifier);
}

int libcfs_debug_init(unsigned long bufsize)
{
	unsigned int max = libcfs_debug_mb;
	int rc = 0;

	if (libcfs_console_max_delay <= 0 || /* not set by user or */
	    libcfs_console_min_delay <= 0 || /* set to invalid values */
	    libcfs_console_min_delay >= libcfs_console_max_delay) {
		libcfs_console_max_delay = CDEBUG_DEFAULT_MAX_DELAY;
		libcfs_console_min_delay = CDEBUG_DEFAULT_MIN_DELAY;
	}

	/* If libcfs_debug_mb is uninitialized then just make the
	 * total buffers smp_num_cpus * TCD_MAX_PAGES
	 */
	if (max < num_possible_cpus())
		max = TCD_MAX_PAGES;
	else
		max <<= (20 - PAGE_SHIFT);

	rc = cfs_tracefile_init(max);
	if (rc)
		return rc;

	libcfs_register_panic_notifier();
	kernel_param_lock(THIS_MODULE);
	libcfs_debug_mb = cfs_trace_get_debug_mb();
	kernel_param_unlock(THIS_MODULE);
	return rc;
}

int libcfs_debug_cleanup(void)
{
	libcfs_unregister_panic_notifier();
	kernel_param_lock(THIS_MODULE);
	cfs_tracefile_exit();
	kernel_param_unlock(THIS_MODULE);
	return 0;
}

int libcfs_debug_clear_buffer(void)
{
	cfs_trace_flush_pages();
	return 0;
}

/* Debug markers, although printed by S_LNET should not be marked as such. */
#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_UNDEFINED
int libcfs_debug_mark_buffer(const char *text)
{
	CDEBUG(D_TRACE,
	       "***************************************************\n");
	LCONSOLE(D_WARNING, "DEBUG MARKER: %s\n", text);
	CDEBUG(D_TRACE,
	       "***************************************************\n");

	return 0;
}

#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_LNET

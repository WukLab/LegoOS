/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "pc-manager: " fmt

#include <lego/slab.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>
#include <lego/syscalls.h>

#include "processor.h"

#ifndef CONFIG_FIT
static void p_test(void)
{
	char *buf;
	int fd;

	buf = kmalloc(8192, GFP_KERNEL);

	fd = sys_open("/proc/stat", 0, 0);
	sys_read(fd, buf, 8192);
	pr_info("fd: %d buf: \n%s\n", fd, buf);
	sys_close(fd);

	memset(buf, 0, 8192);
	fd = sys_open("/sys/devices/system/cpu/online", 0, 0);
	sys_read(fd, buf, 8192);
	pr_info("fd: %d buf: \n%s\n", fd, buf);
	sys_close(fd);

	kfree(buf);
}
#endif

#define MAX_INIT_ARGS	CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS	CONFIG_INIT_ENV_ARG_LIMIT

/* http://c-faq.com/decl/spiral.anderson.html */
static const char *argv_init[MAX_INIT_ARGS+2];
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
 
static int procmgmt(void *unused)
{
	const char *init_filename;

	init_filename = "/root/yilun/benchmark";
	argv_init[0] = init_filename;
	argv_init[1] = "--graph=/root/yilun/test.pb";

	return do_execve(init_filename,
		(const char *const *)argv_init,
		(const char *const *)envp_init);
}

static void run_global_thread(void)
{
	/*
	 * Must use kernel_thread instead of global_kthread_run
	 * because that one will call do_exit inside. So do_execve
	 * will not have any effect.
	 */
	kernel_thread(procmgmt, NULL, CLONE_GLOBAL_THREAD); 
}

#ifdef CONFIG_CHECKPOINT
void __init checkpoint_init(void);
#else
static inline void checkpoint_init(void) { }
#endif

/**
 * processor_component_init
 *
 * Initiliaze all processor component contained subsystems.
 * System will just panic if any of them failed.
 */
void __init processor_component_init(void)
{
	pcache_init();

	/* Create checkpointing restore thread */
	checkpoint_init();

	/*
	 * This is the first user-program we run
	 */
	run_global_thread();

	pr_info("pc-manager running...\n");

#ifndef CONFIG_FIT
	pr_info("Test start...\n");
	p_test();
	pr_info("Test end...\n");
	hlt();
#endif
}

#ifndef CONFIG_CHECKPOINT
SYSCALL_DEFINE1(checkpoint_process, pid_t, pid)
{
	printk_once("Checkpoint is not configured!\n");
	return -ENOSYS;
}
#endif

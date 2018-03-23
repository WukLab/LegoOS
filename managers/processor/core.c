/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "Processor: " fmt

#include <lego/slab.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/syscalls.h>
#include <processor/processor.h>

#include "processor.h"

#define MAX_INIT_ARGS	CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS	CONFIG_INIT_ENV_ARG_LIMIT

/* http://c-faq.com/decl/spiral.anderson.html */
static const char *argv_init[MAX_INIT_ARGS+2];
const char *envp_init[MAX_INIT_ENVS+2] =
{
	"HOME=/",
	"TERM=linux",
	"LANG=en_US.UTF-8",
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin",
	"USER=root",
	"PWD=/",
	NULL,
};
 
static int procmgmt(void *unused)
{
	const char *init_filename;

	/*
	 * Use the correct name if a real storage node is used.
	 * If CONFIG_USE_RAMFS is set, then filename does not matter anyway.
	 */
	init_filename = "/root/ys/LegoOS/usr/exe.o";
	argv_init[0] = init_filename;

	return do_execve(init_filename,
		(const char *const *)argv_init,
		(const char *const *)envp_init);
}

static void run_global_thread(void)
{
	pid_t pid;

	/*
	 * Must use kernel_thread instead of global_kthread_run
	 * because that one will call do_exit inside. So do_execve
	 * will not have any effect.
	 */
	pid = kernel_thread(procmgmt, NULL, CLONE_GLOBAL_THREAD); 
	if (pid < 0)
		panic("Fail to run the initial user process.");
}

#ifdef CONFIG_CHECKPOINT
void __init checkpoint_init(void);
#else
static inline void checkpoint_init(void) { }
#endif

/**
 * processor_manager_init
 *
 * Initiliaze all processor manager contained subsystems.
 * System will just panic if any of them failed.
 */
void __init processor_manager_init(void)
{
	pcache_post_init();

#ifndef CONFIG_FIT
	pr_info("Network is not compiled. Halt.");
	while (1)
		hlt();
#endif

	/* Create checkpointing restore thread */
	checkpoint_init();

	/*
	 * This is the first user-program we run
	 */
	run_global_thread();

	manager_state = MANAGER_UP;
	pr_info("Processor manager is running.\n");
}

/*
 * Early init before buddy allocator is up,
 * so we are free to use memblock.
 */
void __init processor_manager_early_init(void)
{
	pcache_early_init();
}

#ifndef CONFIG_CHECKPOINT
SYSCALL_DEFINE1(checkpoint_process, pid_t, pid)
{
	printk_once("Checkpoint is not configured!\n");
	return -ENOSYS;
}
#endif

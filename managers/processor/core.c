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
#include <processor/zerofill.h>
#include <processor/processor.h>
#include <processor/distvm.h>
#include <processor/vnode.h>

#include <monitor/gpm_handler.h>

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
	int vid;

	/*
	 * Use the correct name if a real storage node is used.
	 * If CONFIG_USE_RAMFS is set, then filename does not matter anyway.
	 */
	init_filename = "/root/yutong/lego/usr/exe.o";
	argv_init[0] = init_filename;

	/* 
	 * request vid
	 */
	vid = request_vnode();
	WARN_ON(vid < 0);
	current->pm_data.virtual_node = vid_find_vnode(vid);

	/*
	 * It's strace has not been established yet
	 * Because previously it has PF_KTHREAD set
	 */
	__fork_processor_strace(current);

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

#ifdef CONFIG_GPM_HANDLER
static inline void init_gpm_handler(void)
{
	struct task_struct *ret;

	ret = kthread_run(gpm_handler, NULL, "gpm_handler");
	if (IS_ERR_OR_NULL(ret))
		panic("Fail to create gpm handler thread");
}
#else
static inline void init_gpm_handler(void) { }
#endif

static inline void common_header_check(void)
{
#define CHK(type, member)	\
	BUILD_BUG_ON((offsetof(type, member) % COMMON_HEADER_ALIGNMENT) != 0)

	CHK(struct p2m_replica_msg, log);

#undef CHK
}

/**
 * processor_manager_init
 *
 * Initiliaze all processor manager contained subsystems.
 * System will just panic if any of them failed.
 */
void __init processor_manager_init(void)
{
	common_header_check();
	pcache_post_init();
	pcache_zerofill_notify_init();

#ifndef CONFIG_FIT
	pr_info("Network is not compiled. Halt.");
	while (1)
		hlt();
#endif

#ifdef CONFIG_VMA_PROCESSOR_UNITTEST
	prcsr_vma_unit_test();
#endif
	
	gpm_handler_init();

	/* Create checkpointing restore thread */
	checkpoint_init();

	/*
	 * This is the first user-program we run
	 */
	run_global_thread();

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

void watchdog_print(void)
{

}

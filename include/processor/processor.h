/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PROCESSOR_H_
#define _LEGO_PROCESSOR_PROCESSOR_H_

#include <lego/sched.h>
#include <lego/signal.h>
#include <generated/unistd_64.h>
#include <lego/comp_common.h>	/* must come at last */

#include <processor/processor_types.h>
#include <processor/node.h>

#ifdef CONFIG_COMP_PROCESSOR

void __init kick_off_user(void);
void __init processor_manager_early_init(void);
void __init processor_manager_init(void);
int __init pcache_range_register(u64 start, u64 size);

/* Callback for fork() to initialize processor_manager data */
void fork_processor_data(struct task_struct *, struct task_struct *, unsigned long clone_flags);

int pcache_handle_fault(struct mm_struct *mm,
			unsigned long address, unsigned long flags);

void pcache_process_exit(struct task_struct *tsk);
void pcache_thread_exit(struct task_struct *tsk);

#ifdef CONFIG_CHECKPOINT
int checkpoint_thread(struct task_struct *);
#else
static inline int checkpoint_thread(struct task_struct *tsk) { return 0; }
#endif

int do_execve(const char *filename,
	      const char * const *argv,
	      const char * const *envp);

void open_stdio_files(void);

#else
/*
 * !CONFIG_COMP_PROCESSOR
 * Provide some empty function prototypes.
 */

static inline void pcache_process_exit(struct task_struct *tsk) { }
static inline void pcache_thread_exit(struct task_struct *tsk) { }

static inline void kick_off_user(void) { }
static inline void processor_manager_init(void) { }
static inline void processor_manager_early_init(void) { }
static inline void fork_processor_data(struct task_struct *s, struct task_struct *t, unsigned long f) { }

static inline int pcache_range_register(u64 start, u64 size)
{
	return 0;
}

static inline int
pcache_handle_fault(struct mm_struct *mm, unsigned long address, unsigned long flags)
{
	BUG();
}

static inline int checkpoint_thread(struct task_struct *tsk)
{
	BUG();
}

static inline int do_execve(const char *filename, const char * const *argv,
			    const char * const *envp)
{
	BUG();
}

#endif /* CONFIG_COMP_PROCESSOR */

#ifdef CONFIG_PROFILING_BOOT_RPC
void rpc_profile(void);
void wait_rpc_profile(void);
#else
static inline void rpc_profile(void) { }
static inline void wait_rpc_profile(void) { }
#endif

#endif /* _LEGO_PROCESSOR_PROCESSOR_H_ */

/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SCHED_H_
#define _LEGO_SCHED_H_

#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/thread_info.h>

#include <lego/mm.h>
#include <lego/magic.h>
#include <lego/types.h>

/*
 * Clone Flags:
 */
#define CLONE_VM		0x00000100	/* set if VM shared between processes */
#define CLONE_FS		0x00000200	/* set if fs info shared between processes */
#define CLONE_FILES		0x00000400	/* set if open files shared between processes */
#define CLONE_SIGHAND		0x00000800	/* set if signal handlers and blocked signals shared */
#define CLONE_PTRACE		0x00002000	/* set if we want to let tracing continue on the child too */
#define CLONE_PARENT		0x00008000	/* set if we want to have the same parent as the cloner */
#define CLONE_THREAD		0x00010000	/* Same thread group? */

/* Task command name length */
#define TASK_COMM_LEN 16

struct task_struct {
	/* -1 unrunnable, 0 runnable, >0 stopped */
	volatile long state;

	/* kernel mode stack */
	void *stack;

	char comm[TASK_COMM_LEN];

	pid_t pid;
	pid_t tgid;

	struct mm_struct *mm, *active_mm;

	struct thread_struct thread;
};

union thread_union {
	struct thread_info thread_info;
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

#define task_thread_info(task)	((struct thread_info *)((task)->stack))
#define task_stack_page(task)	((void *)((task)->stack))

/*
 * Return the address of the last usable long on the stack.
 *
 * When the stack grows down, this is just above the thread
 * info struct. Going any lower will corrupt the thread_info.
 */
static inline unsigned long *end_of_stack(struct task_struct *p)
{
	return (unsigned long *)(task_thread_info(p) + 1);
}

static inline int kstack_end(void *addr)
{
	/* Reliable end of stack detection: */
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}

extern union thread_union init_thread_union;
extern struct task_struct init_task;

void show_call_trace(struct task_struct *task, struct pt_regs *regs);
void show_stack_content(struct task_struct *task, struct pt_regs *regs);
void show_general_task_info(struct task_struct *task);
void show_regs(struct pt_regs *regs);

/**
 * dump_stack	-	Dump the current stack
 *
 * By default, this function will just dump the *current* process's stack
 * and registers. If we have further requirement, e.g. dump *another* process's
 * stack, then we need to look back and improve this guy.
 */
static inline void dump_stack(void)
{
	show_general_task_info(current);
	show_stack_content(current, NULL);
	show_call_trace(current, NULL);
}

/* Scheduler clock - returns current time in nanosec units */
unsigned long long sched_clock(void);

pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags);

#endif /* _LEGO_SCHED_H_ */

/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
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
#include <asm/thread_info.h>

#include <lego/types.h>

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
};

union thread_union {
	struct thread_info thread_info;
	unsigned long stack[THREAD_SIZE/sizeof(long)];
};

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

static inline void dump_stack(void)
{
	show_general_task_info(current);
	show_stack_content(current, NULL);
	show_call_trace(current, NULL);
}

static inline void *task_stack_page(const struct task_struct *task)
{
	return task->stack;
}

#endif /* _LEGO_SCHED_H_ */

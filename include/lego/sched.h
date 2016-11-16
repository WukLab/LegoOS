/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * Task/Process Management Definitions and Helpers
 */

#ifndef _LEGO_SCHED_H_
#define _LEGO_SCHED_H_

#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/thread_info.h>

/* Task command name length */
#define TASK_COMM_LEN 16

struct task_struct {
	/* -1 unrunnable, 0 runnable, >0 stopped */
	volatile long state;

	/* kernel mode stack */
	void *stack;

	char comm[TASK_COMM_LEN];

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

extern void show_regs(struct pt_regs *regs);

#endif /* _LEGO_SCHED_H_ */

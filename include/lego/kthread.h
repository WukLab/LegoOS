/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_KTHREAD_H_
#define _LEGO_KTHREAD_H_

#include <lego/err.h>
#include <lego/sched.h>

int kthreadd(void *unused);
extern struct task_struct *kthreadd_task;

__printf(5, 6)
struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
					   void *data,
					   int node,
					   unsigned int flags,
					   const char namefmt[], ...);

/**
 * kthread_create - create a kthread on the current node
 * @threadfn: the function to run in the thread
 * @data: data pointer for @threadfn()
 * @flags: extra for clone, normally just pass 0!
 * @namefmt: printf-style format string for the thread name
 * @...: arguments for @namefmt.
 *
 * This macro will create a kthread on the current node, leaving it in
 * the stopped state.  This is just a helper for kthread_create_on_node();
 * see the documentation there for more details.
 */
#define kthread_create(threadfn, data, flags, namefmt, arg...) \
	kthread_create_on_node(threadfn, data, NUMA_NO_NODE, flags, namefmt, ##arg)

/**
 * kthread_run - create and wake a thread.
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @namefmt: printf-style name for the thread.
 *
 * Description: Convenient wrapper for kthread_create() followed by
 * wake_up_process().  Returns the kthread or ERR_PTR(-ENOMEM).
 */
#define kthread_run(threadfn, data, namefmt, ...)				\
({										\
	struct task_struct *__k							\
		= kthread_create(threadfn, data, 0, namefmt, ## __VA_ARGS__);	\
	if (!IS_ERR(__k))							\
		wake_up_process(__k);						\
	__k;									\
})

#define kthread_run_flags(threadfn, data, flags, namefmt, ...)			\
({										\
	struct task_struct *__k							\
		= kthread_create(threadfn, data, flags, namefmt, ## __VA_ARGS__);\
	if (!IS_ERR(__k))							\
		wake_up_process(__k);						\
	__k;									\
})

/**
 * kthread_create_on_cpu - Create a cpu bound kthread
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @cpu: The cpu on which the thread should be bound,
 * @namefmt: printf-style name for the thread. Format is restricted
 *	     to "name.*%u". Code fills in cpu number.
 *
 * Description: This helper function creates and names a kernel thread
 * The thread will be woken and put into park mode.
 */
struct task_struct *kthread_create_on_cpu(int (*threadfn)(void *data),
					  void *data, unsigned int cpu,
					  const char *namefmt);

bool kthread_should_stop(void);
bool kthread_should_park(void);
int kthread_park(struct task_struct *k);
void kthread_unpark(struct task_struct *k);
void kthread_bind(struct task_struct *p, unsigned int cpu);
void kthread_parkme(void);
int kthread_stop(struct task_struct *k);

/**
 * global_kthread_run
 *
 * Create a global-visible lego thread.
 * The creation will contact remote memory component.
 */
#define global_kthread_run(threadfn, data, namefmt, ...) \
	kthread_run_flags(threadfn, data, CLONE_GLOBAL_THREAD, namefmt, ## __VA_ARGS__)

#endif /* _LEGO_KTHREAD_H_ */

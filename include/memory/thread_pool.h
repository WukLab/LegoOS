/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _MEM_THREAD_POOL_H_
#define _MEM_THREAD_POOL_H_

#include <lego/list.h>
#include <lego/spinlock.h>
#include <lego/comp_common.h>

#define MAX_RXBUF_SIZE	(PAGE_SIZE * 20)

void handle_bad_request(struct common_header *hdr, u64 desc);
void handle_p2m_test(void *payload, u64 desc, struct common_header *hdr);

#ifndef CONFIG_MEM_THREAD_POOL
struct info_struct {
	unsigned long 		desc;
	char msg[MAX_RXBUF_SIZE];
};
#else
/* MEM_THREAD_POOL is turned on */
struct _info_padding {
	char _x[0];
} __aligned(PAGE_SIZE);

#define INFO_PADDING(name)	struct _info_padding name

struct info_struct {
	unsigned long		desc;
	unsigned long 		numbuf;	/* the buffer number id */
	atomic_t		used;	/* the buffer is in used */
	struct list_head	queue;	/* list_head on a thread waiting queue */
	INFO_PADDING(_PAD_1);		/* padding for one page */
	char msg[MAX_RXBUF_SIZE];
};

#define MAX_NR_RXBUFS		16

#define NR_GENERIC_WORKERS	CONFIG_NR_GENERIC_WORKERS
#define NR_IO_WORKERS		CONFIG_NR_IO_WORKERS
#define NR_WORKERS		(NR_GENERIC_WORKERS + NR_IO_WORKERS)

struct mem_worker_struct {
	struct list_head	head;		/* head of thread waiting queue */
	spinlock_t		lock;		/* lock to protect this thead waiting queue */
	unsigned long		num_worker;	/* the worker number id */
} ____cacheline_aligned;

static inline void
enqueue_thread(struct mem_worker_struct *worker, struct info_struct *info)
{
	atomic_set(&info->used, 1);
	spin_lock(&worker->lock);
	list_add_tail(&info->queue, &worker->head);
	spin_unlock(&worker->lock);
}

static inline struct info_struct *
next_info_entry(struct info_struct *info)
{
	struct info_struct *next;

	BUG_ON(info->numbuf >= MAX_NR_RXBUFS);
	
	if (likely(info->numbuf < MAX_NR_RXBUFS - 1))
		next = info + 1;
	else
		next = info - (MAX_NR_RXBUFS - 1);
	
	return next;
}

static inline void __clear_info_msg(struct info_struct *info)
{
	memset(&info->msg, 0, MAX_RXBUF_SIZE);
}

static inline void __init_info(struct info_struct *info, unsigned nr_info)
{
	struct info_struct *curr = info;
	unsigned nr_remaining = nr_info;

	while (nr_remaining) {
		__clear_info_msg(curr);
		curr->numbuf= nr_info - nr_remaining;
		atomic_set(&curr->used, 0);
		INIT_LIST_HEAD(&curr->queue);
		curr++;
		nr_remaining--;
	}
}

static inline void __init_mem_worker_struct(struct mem_worker_struct *worker)
{
	INIT_LIST_HEAD(&worker->head);
	spin_lock_init(&worker->lock);
}

static inline void
__init_worker_structs(struct mem_worker_struct *workers, unsigned nr_workers)
{
	struct mem_worker_struct *curr = workers;
	unsigned nr_remaining = nr_workers;

	while (nr_remaining) {
		__init_mem_worker_struct(curr);
		curr->num_worker = nr_workers - nr_remaining;
		curr++;
		nr_remaining--;
	}
}

static inline struct mem_worker_struct *
next_generic_worker(struct mem_worker_struct *curr_generic_worker)
{
	struct mem_worker_struct *next;

	BUG_ON(curr_generic_worker->num_worker >= NR_GENERIC_WORKERS);
	
	if (curr_generic_worker->num_worker < NR_GENERIC_WORKERS - 1)
		next = curr_generic_worker + 1;
	else
		next = curr_generic_worker - (NR_GENERIC_WORKERS - 1);
	
	return next;
}

int generic_worker_func(void *passed);
int io_worker_func(void *passed);
#endif /* CONFIG_MEM_THREAD_POOL */

#endif /* _MEM_THREAD_POOL_H_ */

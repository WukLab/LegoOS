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
#include <lego/sched.h>
#include <lego/spinlock.h>
#include <lego/comp_common.h>

#define MAX_RXBUF_SIZE	(PAGE_SIZE * 20)

#define THPOOL_RX_SIZE	(PAGE_SIZE * 32)
#define THPOOL_TX_SIZE	(PAGE_SIZE * 32)

/* TODO: use IB macro */
#define NR_THPOOL_BUFFER	(4*24)

#define NR_THPOOL_WORKERS	CONFIG_THPOOL_NR_WORKERS

/*
 * This structure describes a worker thread.
 * @nr_queued: how many work have been queued
 * @work: the list of work to do
 * @lock: protect list operations
 */
struct thpool_worker {
	/*
	 * This counter is updated while the list
	 * is updated. And they are updated under @lock.
	 * Thus a simple int will do.
	 */
	int			nr_queued;
	unsigned long		flags;
	struct list_head	work_head;
	spinlock_t		lock;
	struct task_struct	*task;
} ____cacheline_aligned;

#ifdef CONFIG_DEBUG_THPOOL
#define THPOOL_WORKER_INHANDLER		0x1UL

static inline int thpool_worker_in_handler(struct thpool_worker *tw)
{
	return tw->flags & THPOOL_WORKER_INHANDLER;
}

static inline void set_thpool_worker_in_handler(struct thpool_worker *tw)
{
	tw->flags |= THPOOL_WORKER_INHANDLER;
}

static inline void clear_thpool_worker_in_handler(struct thpool_worker *tw)
{
	tw->flags &= ~THPOOL_WORKER_INHANDLER;
}
#else
static inline int thpool_worker_in_handler(struct thpool_worker *tw) { return 0; }
static inline void set_thpool_worker_in_handler(struct thpool_worker *tw) { }
static inline void clear_thpool_worker_in_handler(struct thpool_worker *tw) { }
#endif /* CONFIG_DEBUG_THPOOL */

static inline int nr_queued_thpool_worker(struct thpool_worker *tw)
{
	return tw->nr_queued;
}

static inline void inc_queued_thpool_worker(struct thpool_worker *tw)
{
	tw->nr_queued++;
}

static inline void dec_queued_thpool_worker(struct thpool_worker *tw)
{
	tw->nr_queued--;
}

struct thpool_padding {
	char x[0];
} __aligned(PAGE_SIZE);
#define THPOOL_PADDING(name)	struct thpool_padding name

struct thpool_buffer {
	unsigned long		desc;
	unsigned long		flags;
	struct list_head	next;

	THPOOL_PADDING(_pad1);

	char			rx[THPOOL_RX_SIZE];
	char			tx[THPOOL_TX_SIZE];
};

enum thpool_buffer_flags {
	THPOOL_BUFFER_used,

	NR_THPOOL_BUFFER_FLAGS,
};

#define TEST_THPOOL_BUFFER_FLAGS(uname, lname)				\
static inline int ThpoolBuffer##uname(const struct thpool_buffer *p)	\
{									\
	return test_bit(THPOOL_BUFFER_##lname, &p->flags);		\
}

#define SET_THPOOL_BUFFER_FLAGS(uname, lname)				\
static inline void SetThpoolBuffer##uname(struct thpool_buffer *p)	\
{									\
	set_bit(THPOOL_BUFFER_##lname, &p->flags);			\
}

#define __SET_THPOOL_BUFFER_FLAGS(uname, lname)				\
static inline void __SetThpoolBuffer##uname(struct thpool_buffer *p)	\
{									\
	__set_bit(THPOOL_BUFFER_##lname, &p->flags);			\
}

#define CLEAR_THPOOL_BUFFER_FLAGS(uname, lname)				\
static inline void ClearThpoolBuffer##uname(struct thpool_buffer *p)	\
{									\
	clear_bit(THPOOL_BUFFER_##lname, &p->flags);			\
}

#define __CLEAR_THPOOL_BUFFER_FLAGS(uname, lname)			\
static inline void __ClearThpoolBuffer##uname(struct thpool_buffer *p)	\
{									\
	__clear_bit(THPOOL_BUFFER_##lname, &p->flags);			\
}

#define THPOOL_BUFFER_FLAGS(uname, lname)				\
	TEST_THPOOL_BUFFER_FLAGS(uname, lname)				\
	SET_THPOOL_BUFFER_FLAGS(uname, lname)				\
	CLEAR_THPOOL_BUFFER_FLAGS(uname, lname)				\
	__SET_THPOOL_BUFFER_FLAGS(uname, lname)				\
	__CLEAR_THPOOL_BUFFER_FLAGS(uname, lname)

THPOOL_BUFFER_FLAGS(Used, used)

static inline void *thpool_buffer_rx(struct thpool_buffer *tb)
{
	return tb->rx;
}

static inline void *thpool_buffer_tx(struct thpool_buffer *tb)
{
	return tb->tx;
}

void handle_bad_request(struct common_header *hdr, u64 desc);
void handle_p2m_test(void *payload, u64 desc, struct common_header *hdr);

#endif /* _MEM_THREAD_POOL_H_ */

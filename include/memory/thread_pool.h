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

struct thpool_buffer;

struct tw_padding {
	char x[0];
} ____cacheline_aligned;
#define TW_PADDING(name)	struct tw_padding name

/* This structure describes a worker thread */
struct thpool_worker {
	/*
	 * This counter is updated while the list
	 * is updated. And they are updated under @lock.
	 * Thus a simple int will do.
	 *
	 * Besides, the top three fields will always be
	 * updated together, so aggregate them into one
	 * standalone cache line.
	 */
	int			cpu;
	int			nr_queued;
	spinlock_t		lock;
	struct list_head	work_head;
	struct task_struct	*task;
	TW_PADDING(_pad1);

	/* for debug usage */
	unsigned long		nr_handled;
	unsigned long		total_queuing_delay_ns;
	int			max_nr_queued;
	unsigned long		flags;
	struct thpool_buffer	*wip_buffer;
} ____cacheline_aligned;

static inline void set_cpu_thpool_worker(struct thpool_worker *tw, int cpu)
{
	tw->cpu = cpu;
}

static inline int cpu_thpool_worker(struct thpool_worker *tw)
{
	return tw->cpu;
}

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

struct tb_padding {
	char x[0];
} __aligned(PAGE_SIZE);
#define THPOOL_PADDING(name)	struct tb_padding name

struct thpool_buffer {
	unsigned long		desc;
	unsigned long		flags;
	unsigned long		time_enqueue_ns;
	unsigned long		time_dequeue_ns;
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

#ifdef CONFIG_COUNTER_THPOOL
#define THPOOL_WORKER_INHANDLER		0x1UL
static inline int thpool_worker_in_handler(struct thpool_worker *tw)
{
	return tw->flags & THPOOL_WORKER_INHANDLER;
}

static inline void set_in_handler_thpool_worker(struct thpool_worker *tw)
{
	tw->flags |= THPOOL_WORKER_INHANDLER;
}

static inline void clear_in_handler_thpool_worker(struct thpool_worker *tw)
{
	tw->flags &= ~THPOOL_WORKER_INHANDLER;
}

static inline int max_queued_thpool_worker(struct thpool_worker *tw)
{
	return tw->max_nr_queued;
}

static inline void update_max_queued_thpool_worker(struct thpool_worker *tw)
{
	if (tw->nr_queued > tw->max_nr_queued)
		tw->max_nr_queued = tw->nr_queued;
}

static inline void
set_wip_buffer_thpool_worker(struct thpool_worker *tw, struct thpool_buffer *tb)
{
	tw->wip_buffer = tb;
}

static inline void clear_wip_buffer_thpool_worker(struct thpool_worker *tw)
{
	tw->wip_buffer = NULL;
}

static inline struct thpool_buffer *
wip_buffer_thpool_worker(struct thpool_worker *tw)
{
	return tw->wip_buffer;
}

/* Queuing delay */
static inline void thpool_buffer_enqueue_time(struct thpool_buffer *tb)
{
	tb->time_enqueue_ns = sched_clock();
}

static inline void thpool_buffer_dequeue_time(struct thpool_buffer *tb)
{
	tb->time_dequeue_ns = sched_clock();
}

static inline unsigned long thpool_buffer_queuing_delay(struct thpool_buffer *tb)
{
	return tb->time_dequeue_ns - tb->time_enqueue_ns;
}

static inline void add_thpool_worker_total_queuing(struct thpool_worker *tw, unsigned long diff_ns)
{
	tw->total_queuing_delay_ns += diff_ns;
}

static inline void inc_thpool_worker_nr_handled(struct thpool_worker *tw)
{
	tw->nr_handled++;
}

#else
static inline int thpool_worker_in_handler(struct thpool_worker *tw) { return 0; }
static inline void set_in_handler_thpool_worker(struct thpool_worker *tw) { }
static inline void clear_in_handler_thpool_worker(struct thpool_worker *tw) { }
static inline int max_queued_thpool_worker(struct thpool_worker *tw) { return 0; }
static inline void update_max_queued_thpool_worker(struct thpool_worker *tw) { }
static inline void
set_wip_buffer_thpool_worker(struct thpool_worker *tw, struct thpool_buffer *tb) { }
static inline void clear_wip_buffer_thpool_worker(struct thpool_worker *tw) { }
static inline struct thpool_buffer *
wip_buffer_thpool_worker(struct thpool_worker *tw) { return NULL; }

/* Queuing delay */
static inline unsigned long thpool_buffer_queuing_delay(struct thpool_buffer *tb) { return 0; }
static inline void thpool_buffer_dequeue_time(struct thpool_buffer *tb) { }
static inline void thpool_buffer_enqueue_time(struct thpool_buffer *tb) { }
static inline void add_thpool_worker_total_queuing(struct thpool_worker *tw, unsigned long diff_ns) { }

static inline void inc_thpool_worker_nr_handled(struct thpool_worker *tw) { }
#endif /* CONFIG_COUNTER_THPOOL */

#endif /* _MEM_THREAD_POOL_H_ */

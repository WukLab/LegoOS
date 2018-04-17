/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/slab.h>
#include <lego/delay.h>
#include <lego/kernel.h>
#include <lego/printk.h>
#include <lego/jiffies.h>
#include <lego/kthread.h>
#include <lego/memblock.h>
#include <lego/fit_ibapi.h>
#include <lego/completion.h>
#include <lego/comp_storage.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/loader.h>
#include <memory/distvm.h>
#include <memory/thread_pool.h>
#include <memory/pgcache.h>

#include <monitor/gmm_handler.h>

#ifdef CONFIG_DEBUG_THPOOL_PRINT
#define thpool_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void thpool_debug(const char *fmt, ...) { }
#endif

void handle_bad_request(struct common_header *hdr, u64 desc)
{
	u32 retbuf;

	pr_warn("Unknown: opcode: %u, from node: %u\n",
		hdr->opcode, hdr->src_nid);

	retbuf = RET_EPERM;
	ibapi_reply_message(&retbuf, 4, desc);
}

void handle_p2m_test(void *payload, u64 desc, struct common_header *hdr)
{
	int retbuf = RET_OKAY;

	pr_info("%s(): from node: %u", __func__, hdr->src_nid);
	ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
}

struct thpool_worker thpool_worker_map[NR_THPOOL_WORKERS];
static int TW_HEAD __cacheline_aligned;
static DEFINE_COMPLETION(thpool_init_completion);

/*
 * Pre-allocated thpool buffer
 * TB_HEAD points the current available buffer
 */
static int TB_HEAD __cacheline_aligned;
static struct thpool_buffer *thpool_buffer_map __read_mostly;

static inline int thpool_worker_id(struct thpool_worker *worker)
{
	return worker - thpool_worker_map;
}

static inline int thpool_buffer_ix(struct thpool_buffer *buffer)
{
	return buffer - thpool_buffer_map;
}

static inline void
enqueue_tail_thpool_worker(struct thpool_worker *worker, struct thpool_buffer *buffer)
{
	spin_lock(&worker->lock);
	list_add_tail(&buffer->next, &worker->work_head);
	/*
	 * This is not necessary but will do no harm.
	 * Since we are running on x86 TSO.
	 *
	 * We want to make sure the update of above list
	 * fields can be _seen_ by others before the counter
	 * is seen by others. Because the worker thread check
	 * the counter first, then check/dequeue list.
	 */
	smp_wmb();
	inc_queued_thpool_worker(worker);
	update_max_queued_thpool_worker(worker);
	spin_unlock(&worker->lock);
}

static inline struct thpool_buffer *
__dequeue_head_thpool_worker(struct thpool_worker *worker)
{
	struct thpool_buffer *buffer;

	buffer = list_entry(worker->work_head.next, struct thpool_buffer, next);
	list_del(&buffer->next);
	dec_queued_thpool_worker(worker);

	return buffer;
}

static inline struct thpool_buffer *
alloc_thpool_buffer(void)
{
	struct thpool_buffer *tb;
	int idx;

	idx = TB_HEAD % NR_THPOOL_BUFFER;
	tb = thpool_buffer_map + idx;
	TB_HEAD++;

	/*
	 * Buffer allocation is a simple ring.
	 * If the warning is triggered, it basically means:
	 * - buffer is not big enough
	 * - handler are too slow
	 */
	WARN_ON(ThpoolBufferUsed(tb));

	__SetThpoolBufferUsed(tb);
	return tb;
}

/*
 * Choose a worker based on request types
 */
static inline struct thpool_worker *
select_thpool_worker(struct thpool_buffer *r)
{
	struct thpool_worker *tw;
	int idx;

	idx = TW_HEAD % NR_THPOOL_WORKERS;
	tw = thpool_worker_map + idx;
	TW_HEAD++;
	return tw;
}

static void __thpool_worker(struct thpool_worker *worker,
			    struct thpool_buffer *buffer)
{
	unsigned long desc;
	void *msg;
	void *payload;
	struct common_header *hdr;
	void *tx;

	tx = thpool_buffer_tx(buffer);
	msg = thpool_buffer_rx(buffer);
	desc = buffer->desc;
	hdr = to_common_header(msg);
	payload = to_payload(msg);

	/*
	 * BIG FAT NOTE:
	 * 1) Handler MUST call reply message
	 * 2) Handler CAN NOT free payload and hdr
	 * 3) Handler SHOULD NOT call exit()
	 */
	switch (hdr->opcode) {
/* PCACHE */
	case P2M_PCACHE_MISS:
		handle_p2m_pcache_miss(msg, desc, tx);
		break;
	case P2M_PCACHE_FLUSH:
		handle_p2m_flush_one(msg, desc);
		break;
	case P2M_PCACHE_ZEROFILL:
		handle_p2m_zerofill(msg, desc, tx);
		break;

/* clflush REPLICA */
	case P2M_PCACHE_REPLICA:
		handle_p2m_replica(msg, desc);
		break;

/* SYSCALL */
	case P2M_READ:
		handle_p2m_read(payload, desc, hdr);
		break;

	case P2M_WRITE:
		handle_p2m_write(payload, desc, hdr);
		break;

#ifdef CONFIG_MEM_PAGE_CACHE
	case P2M_LSEEK:
		handle_p2m_lseek(payload, desc, hdr);
		break;
	
	case P2M_RENAME:
		handle_p2m_rename(payload, desc, hdr);
		break;

	case P2M_STAT:
		handle_p2m_stat(payload, desc, hdr);
		break;
#endif

	case P2M_CLOSE:
		handle_p2m_close(payload, desc, hdr);
		break;

	case P2M_MMAP:
		handle_p2m_mmap(payload, desc, hdr, tx);
		break;

	case P2M_MPROTECT:
		handle_p2m_mprotect(payload, desc, hdr);
		break;

	case P2M_MUNMAP:
		handle_p2m_munmap(payload, desc, hdr);
		break;

	case P2M_MREMAP:
		handle_p2m_mremap(payload, desc, hdr);
		break;

	case P2M_BRK:
		handle_p2m_brk(payload, desc, hdr);
		break;

	case P2M_MSYNC:
		handle_p2m_msync(payload, desc, hdr);
		break;

	case P2M_FORK:
		handle_p2m_fork(payload, desc, hdr);
		break;

	case P2M_EXECVE:
		handle_p2m_execve(payload, desc, hdr);
		break;

	case P2M_CHECKPOINT:
		handle_p2m_checkpint(payload, desc, hdr);
		break;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
/* DISTRIBUTED VMA */
	case M2M_MMAP:
		handle_m2m_mmap(payload, desc, hdr);
		break;

	case M2M_MUNMAP:
		handle_m2m_munmap(payload, desc, hdr);
		break;

	case M2M_FINDVMA:
		handle_m2m_findvma(payload, desc, hdr);
		break;

	case M2M_MREMAP_GROW:
		handle_m2m_mremap_grow(payload, desc, hdr);
		break;

	case M2M_MREMAP_MOVE:
		handle_m2m_mremap_move(payload, desc, hdr);
		break;

	case M2M_MREMAP_MOVE_SPLIT:
		handle_m2m_mremap_move_split(payload, desc, hdr);
		break;

	case M2M_FORK:
		handle_m2m_fork(payload, desc, hdr);
		break;
#endif

#ifdef CONFIG_GMM
	case M2MM_STATUS_REPORT:
		handle_m2mm_status_report(desc, hdr);
		break;
#endif

/* TEST */
	case P2M_TEST:
		handle_p2m_test(payload, desc, hdr);
		break;

	default:
		handle_bad_request(hdr, desc);
	}
}

/*
 * The worker thread.
 * We do what master told us to do.
 */
static int thpool_worker_func(void *_worker)
{
	struct thpool_worker *worker = _worker;
	struct thpool_buffer *buffer;

	pr_info("thpool: CPU%2d %s worker_id: %d UP\n",
		smp_processor_id(), current->comm, thpool_worker_id(worker));
	complete(&thpool_init_completion);
	set_cpu_thpool_worker(worker, smp_processor_id());

	while (1) {
		/* Check comments on enqueue */
		while (!nr_queued_thpool_worker(worker))
			cpu_relax();

		spin_lock(&worker->lock);
		while (!list_empty(&worker->work_head)) {
			buffer = __dequeue_head_thpool_worker(worker);
			spin_unlock(&worker->lock);

			set_in_handler_thpool_worker(worker);
			set_wip_buffer_thpool_worker(worker, buffer);
			__thpool_worker(worker, buffer);
			clear_wip_buffer_thpool_worker(worker);
			clear_in_handler_thpool_worker(worker);

			__ClearThpoolBufferUsed(buffer);

			spin_lock(&worker->lock);
		}
		spin_unlock(&worker->lock);
	}
	BUG();
	return 0;
}

#define THPOOL_IB_PORT	(0)

unsigned long nr_thpool_reqs;

/*
 * The thread pool polling thread. This is the only thread that is
 * doing ibapi_receive_message. We do not do any handling here.
 * All requests are offloaded to workers. Good to be a master, huh?
 */
static int thpool_polling(void *unused)
{
	struct thpool_buffer *buffer;
	struct thpool_worker *worker;
	int retlen;

	pr_info("thpool: CPU%2d %s UP\n",
		smp_processor_id(), current->comm);
	complete(&thpool_init_completion);

	while (1) {
		buffer = alloc_thpool_buffer();

		/* Wait until message comes in */
		retlen = ibapi_receive_message(THPOOL_IB_PORT,
				buffer->rx, THPOOL_RX_SIZE, &buffer->desc);

		nr_reqs++;
		if (retlen >= THPOOL_RX_SIZE)
			panic("%d %lu", retlen, THPOOL_RX_SIZE);

		worker = select_thpool_worker(buffer);
		enqueue_tail_thpool_worker(worker, buffer);

		nr_thpool_reqs++;
	}
	BUG();
	return 0;
}

/* Create worker and polling threads */
void __init thpool_init(void)
{
	int i;
	struct task_struct *p;
	struct thpool_worker *worker;

	TW_HEAD = 0;
	for (i = 0; i < NR_THPOOL_WORKERS; i++) {
		worker = &thpool_worker_map[i];

		worker->nr_queued = 0;
		worker->max_nr_queued = 0;
		worker->flags = 0;
		INIT_LIST_HEAD(&worker->work_head);
		spin_lock_init(&worker->lock);

		init_completion(&thpool_init_completion);

		p = kthread_run(thpool_worker_func, worker, "thpool-worker%d", i);
		if (IS_ERR(p))
			panic("fail to create thpool-workder%d", i);

		wait_for_completion(&thpool_init_completion);
		worker->task = p;
	}

	init_completion(&thpool_init_completion);
	p = kthread_run(thpool_polling, NULL, "thpool-polling");
	if (IS_ERR(p))
		panic("Fail to create mc thread");
	wait_for_completion(&thpool_init_completion);
}

void __init memory_component_init(void)
{
#ifndef CONFIG_FIT
	pr_info("Network is not compiled. Halt.");
	while (1)
		hlt();
#endif

	/* Register exec binary handlers */
	exec_init();
	thpool_init();

#ifdef CONFIG_VMA_MEMORY_UNITTEST
	mem_vma_unittest();
#endif
	pr_info("Memory: manager is up and running.\n");
}

/*
 * Allocate the thread pool buffer array
 * before buddy allocator is up.
 */
void __init memory_manager_early_init(void)
{
	u64 size;
	int i;

	size = NR_THPOOL_BUFFER * sizeof(struct thpool_buffer);

	thpool_buffer_map = memblock_virt_alloc(size, PAGE_SIZE);
	if (!thpool_buffer_map)
		panic("Unable to allocate thpool buffer array!");

	TB_HEAD = 0;
	memset(thpool_buffer_map, 0, size);
	for (i = 0; i < NR_THPOOL_BUFFER; i++) {
		struct thpool_buffer *tb;

		tb = thpool_buffer_map + i;
		INIT_LIST_HEAD(&tb->next);
	}

	pr_debug("Memory: thpool_buffer [%p - %#Lx] %Lx bytes nr:%d size:%zu\n",
		thpool_buffer_map, (unsigned long)(thpool_buffer_map) + size, size,
		NR_THPOOL_BUFFER, sizeof(struct thpool_buffer));
}

struct hb_cached {
	struct thpool_buffer *wip_buffer;
	unsigned long last_updated_jiffies;
};

static struct hb_cached hb_cached_data[NR_THPOOL_WORKERS];

static inline void report_stucked_worker(int idx, struct thpool_worker *tw)
{
	void *rx;
	struct common_header *hdr;
	struct thpool_buffer *wip_buffer;
	int cpu;

	cpu = cpu_thpool_worker(tw);
	wip_buffer = wip_buffer_thpool_worker(tw);
	rx = thpool_buffer_rx(wip_buffer);
	hdr = rx;

	pr_info("hb: worker[%d] CPU%2d stucked\n", idx, cpu);
	pr_info("hb:  common_header [op=%#x src_nid:%d]\n", hdr->opcode, hdr->src_nid);
	cpu_dumpstack(cpu);

	if (hdr->opcode == P2M_PCACHE_MISS) {
		struct p2m_pcache_miss_msg *msg = rx;

		pr_info("hb:  msg [pid=%u,tgid=%u,flags=%#x,vaddr=%#Lx]\n",
			msg->pid, msg->tgid, msg->flags, msg->missing_vaddr);
	}
}

static inline void ht_check_worker(int i, struct thpool_worker *tw, struct hb_cached *cached)
{
	if (!max_queued_thpool_worker(tw)) {
		cached->wip_buffer = NULL;
		cached->last_updated_jiffies = jiffies;
		return;
	}

	if (wip_buffer_thpool_worker(tw) != cached->wip_buffer) {
		cached->wip_buffer = wip_buffer_thpool_worker(tw);
		cached->last_updated_jiffies = jiffies;
	} else {
		if ((jiffies - cached->last_updated_jiffies) < 20 * HZ)
			return;

		if (!wip_buffer_thpool_worker(tw))
			return;
		report_stucked_worker(i, tw);
	}
}

void watchdog_print(void)
{
	int i;
	struct thpool_worker *tw;

	for (i = 0; i < NR_THPOOL_WORKERS; i++) {
		tw = thpool_worker_map + i;
<<<<<<< HEAD
		pr_info("hb: worker[%d] max_nr_queued=%d nr_queued=%d in_handler=%s nr_reqs=%lu\n",
			i, max_queued_thpool_worker(tw), tw->nr_queued,
			thpool_worker_in_handler(tw) ? "yes" : "no", nr_thpool_reqs);
=======
		pr_info("hb: worker[%d] max_nr_queued=%d nr_queued=%d in_handler=%s nr_req=%lu\n",
			i, max_queued_thpool_worker(tw), tw->nr_queued,
			thpool_worker_in_handler(tw) ? "yes" : "no", nr_reqs);
>>>>>>> [Add] temporary: counter at M

		ht_check_worker(i, tw, &hb_cached_data[i]);
	}
}

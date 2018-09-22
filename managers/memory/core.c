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
#include <lego/profile.h>
#include <lego/sysinfo.h>
#include <lego/memblock.h>
#include <lego/fit_ibapi.h>
#include <lego/completion.h>
#include <lego/comp_storage.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/stat.h>
#include <memory/loader.h>
#include <memory/distvm.h>
#include <memory/replica.h>
#include <memory/thread_pool.h>
#include <memory/pgcache.h>

#include <monitor/gmm_handler.h>

void handle_bad_request(struct common_header *hdr, u64 desc)
{
	u32 retbuf;

	pr_warn("Unknown: opcode: %u, from node: %u\n",
		hdr->opcode, hdr->src_nid);

	retbuf = RET_EPERM;
	ibapi_reply_message(&retbuf, 4, desc);
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
	while (ThpoolBufferUsed(tb)) {
		WARN_ON_ONCE(1);
		cpu_relax();
	}

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

static void thpool_worker_handler(struct thpool_worker *worker,
				  struct thpool_buffer *buffer)
{
	void *msg;
	void *payload;
	struct common_header *hdr;
	void *tx;
	unsigned long desc;

	/*
	 *   | .........| ............. |
	 *   ^          ^
	 *  msg(hdr)  payload
	 */
	tx = thpool_buffer_tx(buffer);
	msg = thpool_buffer_rx(buffer);
	hdr = to_common_header(msg);
	payload = to_payload(msg);

	/*
	 * BIG FAT NOTE:
	 * 1) Handler MUST call reply message
	 * 2) Handler CAN NOT free payload and hdr
	 * 3) Handler SHOULD NOT call exit()
	 */
	switch (hdr->opcode) {
	case P2M_TEST:
		handle_p2m_test(msg, buffer);
		break;

	case P2M_TEST_NOREPLY:
		__SetThpoolBufferNoreply(buffer);
		handle_p2m_test_noreply(msg, buffer);
		break;

/* PCACHE */
	case P2M_PCACHE_MISS:
		inc_mm_stat(HANDLE_PCACHE_MISS);
		handle_p2m_pcache_miss(msg, buffer);
		break;
	case P2M_PCACHE_FLUSH:
		inc_mm_stat(HANDLE_PCACHE_FLUSH);
		handle_p2m_flush_one(msg, buffer);
		break;
	case P2M_PCACHE_ZEROFILL:
		handle_p2m_zerofill(msg, buffer);
		break;

/* SYSCALL */
	case P2M_READ:
		inc_mm_stat(HANDLE_READ);
		handle_p2m_read(payload, hdr, buffer);
		break;

	case P2M_WRITE:
		inc_mm_stat(HANDLE_WRITE);
		handle_p2m_write(payload, hdr, buffer);
		break;

	case P2M_DROP_CACHE:
		handle_p2m_drop_page_cache(hdr, buffer);
		break;

#ifdef CONFIG_MEM_PAGE_CACHE
	case P2M_LSEEK:
		handle_p2m_lseek(payload, hdr, buffer);
		break;

	case P2M_RENAME:
		handle_p2m_rename(payload, hdr, buffer);
		break;

	case P2M_STAT:
		handle_p2m_stat(payload, hdr, buffer);
		break;
	case P2M_FSYNC:
		handle_p2m_fsync(payload, hdr, buffer);
		break;
#endif

	case P2M_CLOSE:
		handle_p2m_close(payload, desc, hdr);
		break;

	case P2M_MMAP:
		inc_mm_stat(HANDLE_P2M_MMAP);
		handle_p2m_mmap(payload, hdr, buffer);
		break;

	case P2M_MPROTECT:
		handle_p2m_mprotect(payload, buffer);
		break;

	case P2M_MUNMAP:
		inc_mm_stat(HANDLE_P2M_MUNMAP);
		handle_p2m_munmap(payload, hdr, buffer);
		break;

	case P2M_MREMAP:
		handle_p2m_mremap(payload, hdr, buffer);
		break;

	case P2M_BRK:
		inc_mm_stat(HANDLE_P2M_BRK);
		handle_p2m_brk(payload, hdr, buffer);
		break;

	case P2M_MSYNC:
		handle_p2m_msync(payload, desc, hdr, tx);
		break;

	case P2M_FORK:
		handle_p2m_fork(payload, hdr, buffer);
		break;

	case P2M_EXECVE:
		handle_p2m_execve(payload, hdr, buffer);
		break;

	case P2M_CHECKPOINT:
		handle_p2m_checkpint(payload, desc, hdr);
		break;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
/* DISTRIBUTED VMA */
	case M2M_MMAP:
		inc_mm_stat(HANDLE_M2M_MMAP);
		handle_m2m_mmap(payload, hdr, buffer);
		break;

	case M2M_MUNMAP:
		inc_mm_stat(HANDLE_M2M_MUNMAP);
		handle_m2m_munmap(payload, hdr, buffer);
		break;

	case M2M_FINDVMA:
		handle_m2m_findvma(payload, hdr, buffer);
		break;

	case M2M_MREMAP_GROW:
		handle_m2m_mremap_grow(payload, hdr, buffer);
		break;

	case M2M_MREMAP_MOVE:
		handle_m2m_mremap_move(payload, hdr, buffer);
		break;

	case M2M_MREMAP_MOVE_SPLIT:
		handle_m2m_mremap_move_split(payload, hdr, buffer);
		break;

	case M2M_MSYNC:
		handle_m2m_msync(payload, hdr, buffer);
		break;

	case M2M_FORK:
		handle_m2m_fork(payload, hdr, buffer);
		break;

#ifdef CONFIG_DEBUG_VMA
	case M2M_VALIDATE:
		handle_m2m_validate(payload, hdr, buffer);
		break;
#endif

#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */

	/*
	 * Below include handlers for ibapi_send()
	 * They will all have Noreply set and the
	 * fit layer will skip reply part.
	 */

	/* clflush REPLICA */
	case P2M_PCACHE_REPLICA:
		inc_mm_stat(HANDLE_PCACHE_REPLICA);

		__SetThpoolBufferNoreply(buffer);
		handle_p2m_replica(msg, buffer);
		break;

	default:
		handle_bad_request(hdr, desc);
	}
}

DEFINE_PROFILE_POINT(thpool_worker_handler)
DEFINE_PROFILE_POINT(thpool_worker_fit_ack_reply)

static int thpool_worker_func(void *_worker)
{
	struct thpool_worker *w = _worker;
	struct thpool_buffer *b;
	unsigned long queuing_delay;
	PROFILE_POINT_TIME(thpool_worker_handler)
	PROFILE_POINT_TIME(thpool_worker_fit_ack_reply)

	pin_current_thread();
	pr_info("thpool: CPU%2d %s worker_id: %d UP\n",
		smp_processor_id(), current->comm, thpool_worker_id(w));

	complete(&thpool_init_completion);
	set_cpu_thpool_worker(w, smp_processor_id());

	/*
	 * HACK!!!
	 *
	 * We want to disable interrupt at this cpu core for better perf,
	 * because this thpool is pinned and is the only thread running.
	 *
	 * However, if our software watchdog is enabled, we want to enable
	 * the interrupt, so whenever watchdog noticed a dead thread, it
	 * will be able to send interrupt and dump the current stack.
	 */
#ifndef CONFIG_SOFT_WATCHDOG
	local_irq_disable();
#endif

	preempt_disable();
	while (1) {
		/* Check comments on enqueue */
		while (!nr_queued_thpool_worker(w))
			cpu_relax();

		spin_lock(&w->lock);
		while (!list_empty(&w->work_head)) {
			b = __dequeue_head_thpool_worker(w);
			spin_unlock(&w->lock);

			/*
			 * Update queuing stats
			 *
			 * HACK!!! The operations below except thpool_worker_handler()
			 * are for debugging/tracing purpose. The will be compiled
			 * away if disable CONFIG_COUNTER_THPOOL.
			 */
			thpool_buffer_dequeue_time(b);
			queuing_delay = thpool_buffer_queuing_delay(b);
			add_thpool_worker_total_queuing(w, queuing_delay);

			set_in_handler_thpool_worker(w);
			set_wip_buffer_thpool_worker(w, b);

			PROFILE_START(thpool_worker_handler);

			/* Invoke the real handler */
			tb_reset_tx_size(b);
			tb_reset_private_tx(b);
			thpool_worker_handler(w, b);

			/*
			 * Leave this BUG_ON checking to catch
			 * buggy handlers.
			 */
			BUG_ON(!b->tx_size);
			PROFILE_LEAVE(thpool_worker_handler);

			/*
			 * Callback to FIT layer to perform the
			 * last two steps: ACK, and REPLY.
			 */
			PROFILE_START(thpool_worker_fit_ack_reply);
			fit_ack_reply_callback(b);
			PROFILE_LEAVE(thpool_worker_fit_ack_reply);

			clear_wip_buffer_thpool_worker(w);
			clear_in_handler_thpool_worker(w);

			/* Return buffer to free pool */
			__ClearThpoolBufferNoreply(b);
			__ClearThpoolBufferUsed(b);

			inc_thpool_worker_nr_handled(w);
			spin_lock(&w->lock);
		}
		spin_unlock(&w->lock);
	}
	preempt_enable();

#ifndef CONFIG_SOFT_WATCHDOG
	local_irq_enable();
#endif

	BUG();
	return 0;
}

unsigned long nr_thpool_reqs;

void thpool_callback(void *fit_ctx, void *fit_imm,
		     void *rx, int rx_size, int node_id, int fit_offset)
{
	struct thpool_buffer *b;
	struct thpool_worker *w;

	b = alloc_thpool_buffer();
	b->fit_rx = rx;
	b->fit_ctx = fit_ctx;
	b->fit_imm = fit_imm;
	b->fit_offset = fit_offset;
	b->fit_node_id = node_id;

	/*
	 * Select a worker thread and pass the buffer
	 * to it. The worker should do ACK and REPLY.
	 */
	thpool_buffer_enqueue_time(b);
	w = select_thpool_worker(b);
	enqueue_tail_thpool_worker(w, b);
	nr_thpool_reqs++;
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
		worker->nr_handled = 0;
		worker->total_queuing_delay_ns = 0;
		worker->max_queuing_delay_ns = 0;
		worker->min_queuing_delay_ns = ULONG_MAX;
		INIT_LIST_HEAD(&worker->work_head);
		spin_lock_init(&worker->lock);
		memset(worker->queuing_stats, 0, sizeof(worker->queuing_stats));

		init_completion(&thpool_init_completion);

		p = kthread_run(thpool_worker_func, worker, "thpool-worker%d", i);
		if (IS_ERR(p))
			panic("fail to create thpool-workder%d", i);

		wait_for_completion(&thpool_init_completion);
		worker->task = p;
	}
}

void __init memory_component_init(void)
{
#ifndef CONFIG_FIT
	pr_info("Network is not compiled. Halt.");
	while (1)
		hlt();
#endif

	gmm_init();

	/* Register exec binary handlers */
	exec_init();
	thpool_init();

	init_memory_flush_thread();

#ifdef CONFIG_VMA_MEMORY_UNITTEST
	mem_vma_unittest();
#endif
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
	unsigned long nr_thpool_reqs;
};

struct hb_cached hb_cached_data[NR_THPOOL_WORKERS];

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

	pr_info("watchdog: worker[%d] CPU%2d stucked\n", idx, cpu);
	pr_info("watchdog:  common_header [op=%#x src_nid:%d]\n", hdr->opcode, hdr->src_nid);
	cpu_dumpstack(cpu);

	if (hdr->opcode == P2M_PCACHE_MISS) {
		struct p2m_pcache_miss_msg *msg = rx;

		pr_info("watchdog:  msg [pid=%u,tgid=%u,flags=%#x,vaddr=%#Lx]\n",
			msg->pid, msg->tgid, msg->flags, msg->missing_vaddr);
	}
}

static inline void ht_check_worker(int i, struct thpool_worker *tw, struct hb_cached *cached)
{
	if (!max_queued_thpool_worker(tw)) {
		cached->wip_buffer = NULL;
		cached->last_updated_jiffies = jiffies;
		cached->nr_thpool_reqs = 0;
		return;
	}

	if (wip_buffer_thpool_worker(tw) != cached->wip_buffer) {
		cached->wip_buffer = wip_buffer_thpool_worker(tw);
		cached->last_updated_jiffies = jiffies;
		cached->nr_thpool_reqs = nr_thpool_reqs;
	} else {
		if ((jiffies - cached->last_updated_jiffies) < 20 * HZ)
			return;

		if (!wip_buffer_thpool_worker(tw))
			return;
		report_stucked_worker(i, tw);
	}
}

#ifdef CONFIG_COUNTER_THPOOL
void print_thpool_stats(void)
{

	int i;
	struct thpool_worker *tw;

	for (i = 0; i < NR_THPOOL_WORKERS; i++) {
		int j;
		u64 p_i, p_re;
		char p_re_buf[32];

		tw = thpool_worker_map + i;

		pr_info("Watchdog:\n"
			"    worker[%d]\n"
			"        max_nr_queued=%d current_nr_queued=%d in_handler=%s\n"
			"        nr_handled=%lu nr_thpool_reqs=%lu\n"
			"        total_queuing_ns: %lu avg_queuing_ns:%lu max_queuing_ns: %lu min_queuing_ns: %lu\n",
			i, max_queued_thpool_worker(tw), tw->nr_queued, thpool_worker_in_handler(tw) ? "YES" : "NO",
			tw->nr_handled, nr_thpool_reqs,
			tw->total_queuing_delay_ns, tw->nr_handled ? (tw->total_queuing_delay_ns / tw->nr_handled) : 0,
			tw->max_queuing_delay_ns, tw->min_queuing_delay_ns);

		for (j = 0; j < QUEUING_STAT_ENTRIES; j++) {
			if (!tw->queuing_stats[i])
				continue;
			p_i = div64_u64_rem(tw->queuing_stats[j] * 100UL, tw->nr_handled, &p_re);
			scnprintf(p_re_buf, 8, "%0Lu", p_re);

			pr_info("        [%3d, %3d)    %Lu.%s%%\n",
				j * QUEUING_STAT_STRIDE_US, (j + 1) * QUEUING_STAT_STRIDE_US,
				p_i, p_re_buf);
		}

		ht_check_worker(i, tw, &hb_cached_data[i]);
	}
}
#else
static void print_thpool_stats(void) { }
#endif

void watchdog_print(void)
{
	struct manager_sysinfo si;

	manager_meminfo(&si);
	pr_info("Freeram: %#lx\n", si.freeram);
	print_thpool_stats();
	print_memory_manager_stats();
	print_profile_points();
}

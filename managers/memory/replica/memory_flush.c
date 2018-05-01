/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>
#include <lego/checksum.h>
#include <lego/hashtable.h>
#include <lego/fit_ibapi.h>
#include <lego/profile.h>
#include <lego/kthread.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/stat.h>
#include <memory/task.h>
#include <memory/replica.h>
#include <processor/pcache.h>

static DEFINE_SPINLOCK(log_flushd_lock);
static LIST_HEAD(log_flushd_queue);
static atomic_t nr_log_flushd_jobs;

static struct task_struct *log_flushd_task;

static inline void enqueue_tail_flush_job(struct log_flush_job *job)
{
	spin_lock(&log_flushd_lock);
	list_add_tail(&job->list, &log_flushd_queue);
	atomic_inc(&nr_log_flushd_jobs);
	spin_unlock(&log_flushd_lock);
}

void submit_replcia_flush_job(struct log_flush_job *job)
{
	enqueue_tail_flush_job(job);
	wake_up_process(log_flushd_task);
}

DEFINE_PROFILE_POINT(m2s_replica_flush)

/*
 * This code runs on Secondary Memory,
 * used to flush the batched log to Storage.
 */
void flush_replica_struct(struct replica_struct *r)
{
	size_t msg_size;
	int reply, storage_node;
	struct m2s_replica_flush_msg *msg;
	PROFILE_POINT_TIME(m2s_replica_flush)

	/*
	 * The message is pre-cooked when we create
	 * the in-memory cached log.
	 */
	msg = r->flush_msg;
	msg_size = r->flush_msg_size;
	storage_node = CONFIG_DEFAULT_STORAGE_NODE;;

	PROFILE_START(m2s_replica_flush);
	ibapi_send_reply_timeout(storage_node, msg, msg_size,
				&reply, sizeof(reply), false, DEF_NET_TIMEOUT);
	PROFILE_LEAVE(m2s_replica_flush);
}

static void __log_flushd(struct log_flush_job *job)
{
	struct replica_struct *r = job->r;

	flush_replica_struct(r);

	/* Cleanup is always essential */
	reset_replica_head(r);
	ClearReplicaFlushing(r);

	kfree(job);
	inc_mm_stat(NR_BATCHED_LOG_FLUSH);
}

static int log_flushd(void *_unused)
{
	set_cpus_allowed_ptr(current, cpu_active_mask);

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!atomic_read(&nr_log_flushd_jobs))
			schedule();
		__set_current_state(TASK_RUNNING);

		spin_lock(&log_flushd_lock);
		while (!list_empty(&log_flushd_queue)) {
			struct log_flush_job *job;

			/* Dequeue from head */
			job = list_entry(log_flushd_queue.next,
					 struct log_flush_job, list);

			list_del_init(&job->list);
			atomic_dec(&nr_log_flushd_jobs);
			spin_unlock(&log_flushd_lock);

			__log_flushd(job);

			spin_lock(&log_flushd_lock);
		}
		spin_unlock(&log_flushd_lock);
	}
	BUG();
	return 0;
}

void __init init_memory_flush_thread(void)
{
	log_flushd_task = kthread_run(log_flushd, NULL, "klog_flushd");
	if (IS_ERR(log_flushd_task))
		panic("Fail to create klog_flushed");
}

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
#include <lego/kthread.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/thread_pool.h>
#include <memory/loader.h>
#include <memory/distvm.h>

int generic_worker_func(void *passed)
{
	struct mem_worker_struct *worker = (struct mem_worker_struct *) passed;
	struct info_struct *info;
	unsigned long desc;
	void *msg;
	void *payload;
	struct common_header *hdr;

	for (;;) {
		/*
		 *each queue has only one consumer
		*/
		while (list_empty(&worker->head)) {}

		spin_lock(&worker->lock);
		while (!list_empty(&worker->head)) {
			info = list_entry(worker->head.next, 
				struct info_struct, queue);
			list_del_init(&info->queue);
			spin_unlock(&worker->lock);

			/* do something here */
			desc = info->desc;
			msg = info->msg;
			hdr = to_common_header(msg);
			payload = to_payload(msg);

			switch (hdr->opcode) {
/* PCACHE */
			case P2M_PCACHE_MISS:
				handle_p2m_pcache_miss(payload, desc, hdr);
				break;
			case P2M_PCACHE_FLUSH:
				handle_p2m_flush_one(payload, desc, hdr);
				break;

/* clflush REPLICA */
			case P2M_PCACHE_REPLICA:
				handle_p2m_replica(msg, desc);
				break;

/* SYSCALL */
			case P2M_MMAP:
				handle_p2m_mmap(payload, desc, hdr);
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
/* DISTRIBUTED MMAP */
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
#endif
/* TEST */
			case P2M_TEST:
				handle_p2m_test(payload, desc, hdr);
				break;

			default:
				handle_bad_request(hdr, desc);
			}
			
			/* mark buffer is not busy now */
			atomic_set(&info->used, 0);
			spin_lock(&worker->lock);
		}
		spin_unlock(&worker->lock);
	}
	
	/* Never reache here */
	BUG();
	return 0;
}

int io_worker_func(void *passed)
{
	struct mem_worker_struct *worker = (struct mem_worker_struct *) passed;
	struct info_struct *info;
	unsigned long desc;
	void *msg;
	void *payload;
	struct common_header *hdr;

	for (;;) {
		while (list_empty(&worker->head)) {}

		spin_lock(&worker->lock);
		while (!list_empty(&worker->head)) {
			info = list_entry(worker->head.next, 
				struct info_struct, queue);
			list_del_init(&info->queue);
			spin_unlock(&worker->lock);

			/* do something here */
			desc = info->desc;
			msg = info->msg;
			hdr = to_common_header(msg);
			payload = to_payload(msg);


			switch (hdr->opcode) {
/* IO-requests */
			case P2M_READ:
				handle_p2m_read(payload, desc, hdr);
				break;
			case P2M_WRITE:
				handle_p2m_write(payload, desc, hdr);
				break;

			default:
				WARN(1, "This opcode should not be handled by me.\n");
				handle_bad_request(hdr, desc);
			}
			
			/* mark buffer is not busy now */
			atomic_set(&info->used, 0);
			spin_lock(&worker->lock);
		}
		spin_unlock(&worker->lock);
	}
	
	/* Never reache here */
	BUG();
	return 0;
}

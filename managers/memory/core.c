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
#include <lego/fit_ibapi.h>
#include <lego/comp_storage.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/loader.h>
#include <memory/distvm.h>

#ifdef CONFIG_DEBUG_MEMORY_CORE
#define mm_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void mm_debug(const char *fmt, ...) { }
#endif

#ifndef CONFIG_FIT
static void local_qemu_test(void)
{
	struct common_header hdr;
	struct p2m_fork_struct fork;
	struct p2m_execve_struct *execve;
	struct p2m_pcache_miss_struct miss;
	struct lego_task_struct *tsk;
	const char *str;
	unsigned int nid, pid;
	unsigned long pages[3];
	struct p2m_brk_struct brk;
	struct p2m_mmap_struct mmap;
	struct p2m_munmap_struct munmap;

	nid = 88;
	pid = 6666;

	hdr.src_nid = nid;

/* Test Fork */
	fork.pid = pid;
	strcpy(fork.comm, "hotpot");
	handle_p2m_fork(&fork, 0, &hdr);
	tsk = find_lego_task_by_pid(nid, pid);
	BUG_ON(!tsk);
	pr_info("%u:%u/%s\n", tsk->node, tsk->pid, tsk->comm);

/* Test EXECVE */
	execve = kmalloc(4096, GFP_KERNEL);
	BUG_ON(!execve);
	execve->pid = pid;
	strcpy(execve->filename, "/bin/getpid");
	execve->argc = 3;
	execve->envc = 2;
	str = "/bin/getpid\0argc2\0argc3\0envp1\0envp2";
	memcpy(&execve->array, str, 40);
	handle_p2m_execve(execve, 0, &hdr);
	dump_lego_mm(tsk->mm);
	dump_all_vmas_simple(tsk->mm);

/* Test LLC miss */
	miss.pid = pid;
	miss.flags = FAULT_FLAG_WRITE;
	miss.missing_vaddr = 0x400000ULL;
	handle_p2m_pcache_miss(&miss, 0, &hdr);

/* last page of stack, see argc etc info */
	get_user_pages(tsk, 0x7fffffffe000, 1, 0, pages, NULL);
	print_hex_dump_bytes("to_user: ", DUMP_PREFIX_ADDRESS,
		(void *)pages[0] + 3072, 1024);

/* Test brk */
	pr_info("test brk..\n");
	brk.pid = pid;
	brk.brk = 0x800000ULL;
	handle_p2m_brk(&brk, 0, &hdr);
	dump_lego_mm(tsk->mm);
	dump_all_vmas_simple(tsk->mm);
	brk.brk = 0x700000ULL;
	handle_p2m_brk(&brk, 0, &hdr);
	dump_lego_mm(tsk->mm);
	dump_all_vmas_simple(tsk->mm);

/* mmap */
	pr_info("mmap..\n");
	mmap.pid = pid;
	mmap.addr = 0;
	mmap.len = PAGE_SIZE * 0x10;
	mmap.prot = PROT_READ | PROT_WRITE;
	mmap.flags = MAP_ANONYMOUS | MAP_PRIVATE;
	mmap.pgoff = 0;
	handle_p2m_mmap(&mmap, 0, &hdr);
	dump_all_vmas_simple(tsk->mm);

/* munmap */
	pr_info("munmap..\n");
	munmap.pid = pid;
	munmap.addr = 0x7ffff7ff0000;
	munmap.len = PAGE_SIZE * 0x5;
	handle_p2m_munmap(&munmap, 9, &hdr);
	dump_all_vmas_simple(tsk->mm);
}
#endif

#define MAX_RXBUF_SIZE	(PAGE_SIZE * 20)

#ifdef CONFIG_FIT
struct info_struct {
	unsigned long desc;
	char msg[MAX_RXBUF_SIZE];
};

/*
 * Memory manager is only meaningful when FIT is configured.
 */

static void handle_bad_request(struct common_header *hdr, u64 desc)
{
	u32 retbuf;

	pr_warn("Unknown: opcode: %u, from node: %u\n",
		hdr->opcode, hdr->src_nid);

	retbuf = RET_EPERM;
	ibapi_reply_message(&retbuf, 4, desc);
}

static void handle_p2m_test(void *payload, u64 desc, struct common_header *hdr)
{
	int retbuf = RET_OKAY;

	pr_info("%s(): from node: %u", __func__, hdr->src_nid);
	ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
}

static int mc_dispatcher(void *passed)
{
	struct info_struct *info = (struct info_struct *)passed;
	unsigned long desc;
	void *msg;
	void *payload;
	struct common_header *hdr;

	desc = info->desc;
	msg = info->msg;
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
		handle_p2m_pcache_miss(msg, desc);
		break;
	case P2M_PCACHE_FLUSH:
		handle_p2m_flush_one(msg, desc);
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

	case P2M_CLOSE:
		handle_p2m_close(payload, desc, hdr);
		break;

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

	/* Our responsibility to free it */
	return 0;
}

#ifdef CONFIG_DEBUG_MEMORY_CORE
static unsigned long nr_requests = 0;
static void req_counting(struct info_struct *info)
{
	mm_debug("nr_reqs: %ld desc: %#lx\n", nr_requests++, info->desc);
}
#else
static inline void req_counting(struct info_struct *info) { }
#endif

/* Memory Manager Daemon */
static int mc_manager(void *unused)
{
	struct info_struct *info;
	int port = 0;
	int retlen;

	pr_info("Memory-component manager is up and running.\n");

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (unlikely(!info)) {
		WARN_ON(1);
		do_exit(-1);
	}

	while (1) {
		/*
		 * This function is blocking,
		 * will return until FIT gets a messages:
		 */
		memset(info, 0, sizeof(*info));
		retlen = ibapi_receive_message(port,
				info->msg, MAX_RXBUF_SIZE,
				&info->desc);

		if (unlikely(retlen >= MAX_RXBUF_SIZE))
			panic("retlen: %d,maxlen: %lu", retlen, MAX_RXBUF_SIZE);

		req_counting(info);
		mc_dispatcher(info);
	}

	return 0;
}
#endif /* CONFIG_FIT */

void __init memory_component_init(void)
{
	struct task_struct *ret __maybe_unused;

	/* Register exec binary handlers */
	exec_init();

#ifdef CONFIG_VMA_MEMORY_UNITTEST
	mem_vma_unittest();
#endif

#ifdef CONFIG_FIT
	ret = kthread_run(mc_manager, NULL, "mc-manager");
	if (IS_ERR(ret))
		panic("Fail to create mc thread");
#else
	local_qemu_test();
	pr_warn("require CONFIG_FIT to be set.\n");
#endif
}

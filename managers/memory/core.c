/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "mc-manager: " fmt

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_memory.h>
#include <lego/comp_common.h>

#include <memory/include/vm.h>
#include <memory/include/pid.h>
#include <memory/include/loader.h>

static void dump_all_vmas(struct lego_mm_struct *mm)
{
	struct vm_area_struct *vma;

	vma = mm->mmap;

	while (vma) {
		dump_vma(vma);
		vma = vma->vm_next;
		pr_info("\n");
	}
}

static void local_qemu_test(void)
{
	struct common_header hdr;
	struct p2m_fork_struct fork;
	struct p2m_execve_struct *execve;
	struct lego_task_struct *tsk;
	const char *str;
	unsigned int nid, pid;

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
	execve->argc = 2;
	execve->envc = 2;
	str = "aaa\0bbb\0ccc\0ddd";
	memcpy(&execve->array, str, 20);
	handle_p2m_execve(execve, 0, &hdr);
	dump_lego_mm(tsk->mm);
	dump_all_vmas(tsk->mm);

}

#define __DEFAULT_RXBUF_SIZE	(4000)
#define __DEFAULT_DESC_SIZE	(sizeof(unsigned long))
#define DEFAULT_RXBUF_SIZE	(__DEFAULT_RXBUF_SIZE+__DEFAULT_DESC_SIZE)

#ifdef CONFIG_FIT

static unsigned long nr_rx;

static void handle_bad_request(struct common_header *hdr, u64 desc)
{
	u32 retbuf;

	pr_warn("Unknown: opcode: %u, from node: %u\n",
		hdr->opcode, hdr->src_nid);

	retbuf = RET_EPERM;
	ibapi_reply_message(&retbuf, 4, desc);
}

static int mc_dispatcher(void *rx_buf)
{
	void *desc_p, *payload;
	unsigned long desc;
	struct common_header *hdr;

	desc_p = rx_buf + __DEFAULT_RXBUF_SIZE;
	desc = *(unsigned long *)desc_p;

	hdr = to_common_header(rx_buf);
	payload = to_payload(rx_buf);

	/* handler should call reply message */
	switch (hdr->opcode) {
	case P2M_LLC_MISS:
		handle_p2m_llc_miss(payload, desc, hdr);
		break;
	case P2M_FORK:
		handle_p2m_fork(payload, desc, hdr);
		break;
	case P2M_EXECVE:
		handle_p2m_execve(payload, desc, hdr);
		break;
	default:
		handle_bad_request(hdr, desc);
	}

	return 0;
}

/* Memory Manager Daemon */
static int mc_manager(void *unused)
{
	void *rx_buf, *rx_desc;
	struct task_struct *ret;
	int port = 0;

	pr_info("Memory-component manager is up and running.\n");

	while (1) {
		rx_buf = kmalloc(DEFAULT_RXBUF_SIZE, GFP_KERNEL);
		if (unlikely(!rx_buf))
			panic("OOM");
		rx_desc = rx_buf + __DEFAULT_RXBUF_SIZE;

		ibapi_receive_message(port, rx_buf, __DEFAULT_RXBUF_SIZE, rx_desc);

		/*
		 * XXX:
		 * The overhead to create a new thread might be too costly
		 * Later on we should find a more efficient implementation.
		 * Something like thread pool, or workqueue.
		 */
		ret = kthread_run(mc_dispatcher, rx_buf, "mcdisp-%lu", nr_rx++);
		if (unlikely(IS_ERR(ret))) {
			kfree(rx_buf);
			WARN_ON_ONCE(1);
		}
	}

	return 0;
}
#endif /* CONFIG_FIT */

void __init memory_component_init(void)
{
	/* Register exec binary handlers */
	exec_init();

#ifdef CONFIG_FIT
	struct task_struct *ret;

	ret = kthread_run(mc_manager, NULL, "mc-manager");
	if (IS_ERR(ret))
		panic("Fail to create mc thread");
#else
	local_qemu_test();
	pr_warn("require CONFIG_FIT to be set.\n");
#endif
}


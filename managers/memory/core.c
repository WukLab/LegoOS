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

#include <memory/include/vm.h>
#include <memory/include/pid.h>
#include <memory/include/loader.h>

#ifndef CONFIG_FIT
static void local_qemu_test(void)
{
	struct common_header hdr;
	struct p2m_fork_struct fork;
	struct p2m_execve_struct *execve;
	struct p2m_llc_miss_struct miss;
	struct lego_task_struct *tsk;
	const char *str;
	unsigned int nid, pid;
	unsigned long pages[3];
	int i;
	void *buffer;
	size_t buffer_len;

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
	dump_all_vmas_simple(tsk->mm);

/* Test LLC miss */
	miss.pid = pid;
	miss.flags = FAULT_FLAG_WRITE;
	miss.missing_vaddr = 0x400000ULL;
	handle_p2m_llc_miss(&miss, 0, &hdr);

/* Test GUP */
	buffer_len = PAGE_SIZE + 0x10 + 0xf;
	buffer = kmalloc(buffer_len, GFP_KERNEL);
	BUG_ON(!buffer);
	memset(buffer, 65, buffer_len);
	lego_copy_to_user(tsk, (void *)0x7fffffffcff0, buffer, buffer_len);

	get_user_pages(tsk, 0x7fffffffc000, ARRAY_SIZE(pages), 0, pages, NULL);
	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		pr_info("Page %d\n", i);
		print_hex_dump_bytes("hex: ", DUMP_PREFIX_ADDRESS,
			(void *)pages[i], 4096);
	}
}
#endif

#define __DEFAULT_RXBUF_SIZE	(PAGE_SIZE - __DEFAULT_DESC_SIZE)
#define __DEFAULT_DESC_SIZE	(sizeof(unsigned long))
#define DEFAULT_RXBUF_SIZE	(PAGE_SIZE)

#ifdef CONFIG_FIT
/*
 * Memory manager is only meaningful when FIT is configured.
 */

static unsigned long nr_rx;

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
	void *page;

	pr_info("%s(): from node: %u", __func__, hdr->src_nid);

	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	*(int *)page = 0xffffffff;
	BUG_ON(!page);
	ibapi_reply_message(page, PAGE_SIZE, desc);
	pr_info("%s(): after sending\n", __func__);
	kfree(page);
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
	case P2M_TEST:
		handle_p2m_test(payload, desc, hdr);
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
	int retlen;

	pr_info("Memory-component manager is up and running.\n");

	while (1) {
		rx_buf = kmalloc(DEFAULT_RXBUF_SIZE, GFP_KERNEL);
		if (unlikely(!rx_buf))
			panic("OOM");
		rx_desc = rx_buf + __DEFAULT_RXBUF_SIZE;

		retlen = ibapi_receive_message(port, rx_buf,
					    __DEFAULT_RXBUF_SIZE, rx_desc);
		if (unlikely(retlen > __DEFAULT_RXBUF_SIZE)) {
			/* Catch processor bugs.. */
			panic("Got message len: %d, configured max len: %d",
				retlen, __DEFAULT_RXBUF_SIZE);
		}

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
	struct task_struct *ret __maybe_unused;

	/* Register exec binary handlers */
	exec_init();

#ifdef CONFIG_FIT
	ret = kthread_run(mc_manager, NULL, "mc-manager");
	if (IS_ERR(ret))
		panic("Fail to create mc thread");
#else
	local_qemu_test();
	pr_warn("require CONFIG_FIT to be set.\n");
#endif
}


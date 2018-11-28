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
#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_memory.h>
#include <processor/processor.h>

/*
 * If you see this warning, here is what you should do
 * 1) If you are planning to have a storage node, disable RAMFS.
 * 2) If you don't have a storage node, and planning to have
 *    multiple P and multiple M, ignore this message. You are fine.
 */
#ifdef CONFIG_USE_RAMFS
#if (CONFIG_FIT_NR_NODES > 2)
#  warning You configured more than two nodes and RAMFS option.	\
	   This setting disallow a storage manager node.	\
	   Please make sure of that
#endif
#endif

/*
 * The default home memory node and storage node must be
 * smaller than number of connected nodes.
 *
 * If user is using 1P-1M setting, there is no need to config
 * default storage node.
 */
#if (CONFIG_DEFAULT_MEM_NODE >= CONFIG_FIT_NR_NODES)
# error "Please adjust default home memory node."
#endif

#if (CONFIG_DEFAULT_STORAGE_NODE >= CONFIG_FIT_NR_NODES)
#ifndef CONFIG_USE_RAMFS
# error "Please adjust default storage node."
#endif
#endif

/* Indicate if processor or memory manager is up or not. */
int manager_state = MANAGER_DOWN;

unsigned int LEGO_LOCAL_NID __read_mostly = MY_NODE_ID;

/**
 * @node: target node id
 * @opcode: see <lego/comp_common.h>
 * @payload: payload of your message
 * @len_payload: length of your payload (beaware not to exceed valid *payload)
 * @retbuf: your buffer for the replied message
 * @max_len_retbuf: the maximum length of your return buffer
 *
 * @RETURN: 
 *
 * This function will block until network layer received reply.
 */
int net_send_reply_timeout(u32 node, u32 opcode,
			   void *payload, u32 len_payload,
			   void *retbuf, u32 max_len_retbuf, bool retbuf_is_phys,
			   u32 timeout)
{
	int ret;
	u32 len_msg;
	void *msg, *payload_msg;
	struct common_header *hdr;

	BUG_ON(!payload || !retbuf);

	/* compose message */
	len_msg = len_payload + sizeof(*hdr);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		WARN(1, "OOM");
		return -ENOMEM;
	}

	hdr = to_common_header(msg);
	hdr->opcode = opcode;
	hdr->src_nid = LEGO_LOCAL_NID;

	payload_msg = to_payload(msg);
	memcpy(payload_msg, payload, len_payload);

	/* Synchronously send it out */
	ret = ibapi_send_reply_timeout(node, msg, len_msg, retbuf,
				   max_len_retbuf, retbuf_is_phys, timeout);
	if (ret == -ETIMEDOUT)
		pr_info("  %s() CPU:%d PID:%d caller: %pS\n",
			FUNC, smp_processor_id(), current->pid,
			__builtin_return_address(0));

	kfree(msg);
	return ret;
}

static void dump_cpumasks(void)
{
	char buf[64];

	sprintf(buf, "Online CPU: %*pbl\n", nr_cpu_ids, cpu_online_mask);
	pr_debug("%s", buf);
	sprintf(buf, "Active CPU: %*pbl\n", nr_cpu_ids, cpu_active_mask);
	pr_debug("%s", buf);
}

void __init manager_init(void)
{
#ifdef CONFIG_COMP_PROCESSOR
	processor_manager_init();
#elif defined(CONFIG_COMP_MEMORY)
	memory_component_init();
#endif
	manager_state = MANAGER_UP;

	soft_watchdog_init();

	/* Print schedulable CPUs */
	pin_registered_threads();
	dump_cpumasks();

	rpc_profile();

	/*
	 * Start running user threads.
	 * Now we only run user context at Processor Manager.
	 * Maybe.. we want memory to do the same in the future ;-)
	 */
	kick_off_user();
	pr_info("Manager is up and running.\n");
}

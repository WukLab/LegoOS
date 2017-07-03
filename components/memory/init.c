/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "mcd: " fmt

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_memory.h>

#ifdef CONFIG_FIT

#define __DEFAULT_RXBUF_SIZE	(128)
#define __DEFAULT_DESC_SIZE	(sizeof(unsigned long))
#define DEFAULT_RXBUF_SIZE	(__DEFAULT_RXBUF_SIZE+__DEFAULT_DESC_SIZE)

static unsigned long nr_rx;

static int mc_dispatcher(void *rx_buf)
{
	void *tx_buf, *rx_desc_p;
	unsigned long rx_desc;

	rx_desc_p = rx_buf + __DEFAULT_RXBUF_SIZE;
	rx_desc = *(unsigned long *)rx_desc_p;

	pr_info("%d/%s/cpu%d\n", current->pid, current->comm, smp_processor_id());

	return 0;
}

/* Memory Manager Daemon */
static int mc(void *unused)
{
	void *rx_buf, *rx_desc;
	struct task_struct *ret;
	int port = 0;

	while (1) {
		rx_buf = kmalloc(DEFAULT_RXBUF_SIZE, GFP_KERNEL);
		if (unlikely(!rx_buf))
			panic("OOM");
		rx_desc = rx_buf + __DEFAULT_RXBUF_SIZE;

		ibapi_receive_message(port, rx_buf, DEFAULT_RXBUF_SIZE, rx_desc);

		ret = kthread_run(mc_dispatcher, rx_buf, "mcd-%lu", nr_rx++);
		if (unlikely(IS_ERR(ret))) {
			kfree(rx_buf);
			WARN_ON_ONCE(1);
		}
	}

	return 0;
}
#else
static int mc(void *unused)
{
	WARN(1, "CONFIG_FIT is not set!");
	return 0;
}
#endif /* CONFIG_FIT */

void __init memory_component_init(void)
{
	struct task_struct *ret;

	ret = kthread_run(mc, NULL, "mc");
	if (IS_ERR(ret))
		panic("Fail to create mc thread");
}

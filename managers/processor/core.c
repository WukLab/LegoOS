/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "pc-manager: " fmt

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/comp_processor.h>
#include "processor.h"

static void test(void)
{
	void *page;
	int payload;
	int ret;

	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	pr_info("%s: page: %p\n", __func__, page);
	ret = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_TEST,
		&payload, sizeof(payload), page, PAGE_SIZE, false,
		DEF_NET_TIMEOUT);

	pr_info("%s: ret=%d\n", __func__, ret);
	print_hex_dump_bytes("EFL: ", DUMP_PREFIX_OFFSET, page, PAGE_SIZE);
	panic("asd\n");
}

/**
 * processor_component_init
 *
 * Initiliaze all processor component contained subsystems.
 * System will just panic if any of them failed.
 */
void __init processor_component_init(void)
{
	pcache_init();
	pr_info("processor-component manager is up and running.\n");
	test();
}

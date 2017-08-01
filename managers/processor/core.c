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
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>
#include "processor.h"

#ifndef CONFIG_FIT
static void p_test(void)
{
	char *buf;
	int fd;

	buf = kmalloc(8192, GFP_KERNEL);

	fd = sys_open("/proc/stat", 0, 0);
	sys_read(fd, buf, 8192);
	pr_info("fd: %d buf: \n%s\n", fd, buf);
	sys_close(fd);

	memset(buf, 0, 8192);
	fd = sys_open("/sys/devices/system/cpu/online", 0, 0);
	sys_read(fd, buf, 8192);
	pr_info("fd: %d buf: \n%s\n", fd, buf);
	sys_close(fd);

	kfree(buf);
}
#endif

/**
 * processor_component_init
 *
 * Initiliaze all processor component contained subsystems.
 * System will just panic if any of them failed.
 */
void __init processor_component_init(void)
{
	pcache_init();
	pr_info("pc-manager running...\n");

#ifndef CONFIG_FIT
	pr_info("Test start...\n");
	p_test();
	pr_info("Test end...\n");
	hlt();
#endif
}

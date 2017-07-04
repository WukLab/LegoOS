/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "pc-manager: " fmt

#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/comp_common.h>
#include <lego/comp_processor.h>
#include "processor.h"

static int test_run(void *u)
{
	pr_info("%d:%s\n", current->pid, current->comm);
	return 0;
}

/**
 * processor_component_init
 *
 * Initiliaze all processor component contained subsystems.
 * System will just panic if any of them failed.
 */
void __init processor_component_init(void)
{
	pr_info("processor-component manager is up and running.\n");
	global_kthread_run(test_run, NULL, "test_runmamm");
	pcache_init();
}

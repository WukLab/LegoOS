/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Self heartbeat printing
 *
 * We will create a daemon thread, which is _pinned_ a to core.
 * This thread will do nothing but print some critical information
 * that is useful for debugging.
 */

#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/jiffies.h>
#include <processor/processor.h>

extern void hb_print(void);

static long hb_interval_sec = CONFIG_MANAGER_SELF_HEARTBEAT_INTERVAL_SEC;

static int hb(void *_unused)
{
	if (pin_current_thread_core())
		pr_err("Fail to pin self_hb.\n");

	while (1) {
		hb_print();
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(hb_interval_sec * HZ);

		if (kthread_should_stop())
			break;
	}
	return 0;
}

void __init self_hb_init(void)
{
	struct task_struct *ret;

	ret = kthread_run(hb, NULL, "self_hb");
	if (IS_ERR(ret)) {
		pr_info("Fail to create self_hb.\n");
	}
}

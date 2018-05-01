/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/time.h>
#include <lego/jiffies.h>
#include <lego/sysinfo.h>
#include <lego/comp_common.h>
#include <lego/fit_ibapi.h>
#include <lego/kthread.h>
#include <memory/stat.h>
#include <memory/thread_pool.h>
#include <monitor/common.h>
#include <monitor/gmm_handler.h>

unsigned long sysctl_m2mm_status_report_interval_ms = 500;

static int m2mm_status_report(void *_unused)
{
	struct m2mm_status_report r;
	struct manager_sysinfo info;
	int reply;

	r.hdr.src_nid = LEGO_LOCAL_NID;
	r.hdr.opcode = M2MM_STATUS_REPORT;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(sysctl_m2mm_status_report_interval_ms));
		__set_current_state(TASK_RUNNING);

		manager_meminfo(&info);
		r.totalram = info.totalram;
		r.freeram = info.freeram;
		r.nr_request = mm_stat(HANDLE_PCACHE_MISS) + mm_stat(HANDLE_PCACHE_FLUSH);

		//pr_info("%s(): r.nr_req:%lu mm_stat:%lu\n", __func__, r.nr_request, mm_stat(HANDLE_PCACHE_MISS));
		ibapi_send_reply_timeout(CONFIG_GMM_NODEID, &r, sizeof(r),
					 &reply, sizeof(reply), false, 10);
	}
	BUG();
	return 0;
}

void __init gmm_init(void)
{
	struct task_struct *ret;

	ret = kthread_run(m2mm_status_report, NULL, "m2mm_hb");
	if (IS_ERR(ret))
		pr_info("ERROR: fail to create m2mm_hb thread");
}

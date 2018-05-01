/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/sysinfo.h>
#include <lego/comp_common.h>
#include <lego/fit_ibapi.h>
#include <memory/stat.h>
#include <memory/thread_pool.h>
#include <monitor/gmm_handler.h>

void handle_m2mm_status_report(struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	struct m2mm_mnode_status_reply *reply;
	struct manager_sysinfo info;

#ifdef CONFIG_SOFT_WATCHDOG
	pr_info("[REPORT MEMORY STATUS]\n");
#endif
	WARN_ON(nid != CONFIG_GMM_NODEID);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	manager_meminfo(&info);
	reply->totalram = info.totalram;
	reply->freeram = info.freeram;
	reply->nr_request = atomic_long_read(&memory_manager_stats.stat[HANDLE_PCACHE_MISS]);
}

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
#include <monitor/gmm_handler.h>

int handle_m2mm_status_report(u64 desc, struct common_header *hdr)
{
	u32 nid = hdr->src_nid;
	struct m2mm_mnode_status_reply reply;
	struct manager_sysinfo info;

	pr_info("[STATUS REPORT]\n");
	WARN_ON(nid != CONFIG_GMM_NODEID);

	manager_meminfo(&info);
	reply.totalram = info.totalram;
	reply.freeram = info.freeram;

	ibapi_reply_message(&reply, sizeof(reply), desc);
	return 0;
}


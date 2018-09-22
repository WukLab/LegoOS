/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/syscalls.h>
#include <lego/comp_common.h>
#include <lego/fit_ibapi.h>
#include <processor/processor.h>

/*
 * Send a request to memory node to let it drop the page cache
 * Similar effect to "echo 3 > /proc/sys/vm/drop_caches"
 */
static int do_drop_page_cache(void)
{
	int retval, retlen;
	struct common_header hdr;
	int mem_node = current_pgcache_home_node();

	hdr.opcode = P2M_DROP_CACHE;
	hdr.src_nid = LEGO_LOCAL_NID;

	retlen = ibapi_send_reply_imm(mem_node, &hdr, sizeof(hdr),
				      &retval, sizeof(retval), false);

	if (unlikely(retlen != sizeof(retval))) {
		WARN_ON_ONCE(1);
		return -EIO;
	}
	return 0;
}

SYSCALL_DEFINE0(drop_page_cache)
{
	return do_drop_page_cache();
}

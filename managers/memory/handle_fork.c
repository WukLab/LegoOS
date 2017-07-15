/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/fit_ibapi.h>
#include <lego/comp_common.h>
#include <lego/comp_memory.h>

#include "include/pid.h"

int handle_p2m_fork(struct p2m_fork_struct *payload, u64 desc,
		    struct common_header *hdr)
{
	u32 retbuf;

	pr_info("%s: remote pid: %d, comm: %s\n",
		__func__, payload->pid, payload->comm);

	retbuf = RET_OKAY;
	ibapi_reply_message(&retbuf, 4, desc);

	return 0;
}

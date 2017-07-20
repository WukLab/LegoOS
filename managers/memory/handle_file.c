/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes all file-related syscall handlers
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>
#include <lego/comp_memory.h>

#include <memory/include/file_ops.h>

int handle_p2m_read(struct p2m_read_struct *payload, u64 desc,
		struct common_header *hdr)
{
	WARN_ON(1);
	return 0;
}

int handle_p2m_write(struct p2m_write_struct *payload, u64 desc,
		struct common_header *hdr)
{
	WARN_ON(1);
	return 0;
}

int handle_p2m_open(struct p2m_open_struct *payload, u64 desc,
		struct common_header *hdr)
{
	WARN_ON(1);
	return 0;
}

int handle_p2m_close(struct p2m_close_struct *payload, u64 desc,
		struct common_header *hdr)
{
	WARN_ON(1);
	return 0;
}

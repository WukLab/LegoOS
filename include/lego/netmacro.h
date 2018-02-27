/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

enum NET_REUEST_OPS {

	/* commands sent to memory */
	OP_ALLOC,
	OP_FREE,
	OP_MMAP,
	OP_MUNMAP,
	OP_MSYNC,
	OP_LOAD,
	OP_STORE,

	/* commands sent to storage */
	OP_OPEN,
	OP_CLOSE,
	OP_READ,
	OP_WRITE,

	__NR_NET_REQUEST_OPS
};

enum NET_REPLY_STATUS {
	REPLY_SUCCESS,
	REPLY_INVALID_OP,
	REPLY_ENOMEM,
	REPLY_EINVAL,
	REPLY_EBUSY,

	__NR_NET_REPLY_STATUS
};

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_RPC_STRUCT_COMMON_H_
#define _LEGO_RPC_STRUCT_COMMON_H_

/*
 * This file can be included by both Lego and Linux modules.
 * If you add anything here please make sure it does not require
 * extra Lego header files to compile.
 */

#include <lego/rpc/opcode.h>

#define MAX_FILENAME_LENGTH	128

struct common_header {
	unsigned int opcode;
	unsigned int src_nid;		/* source nid */
	unsigned int length;		/* of the whole message */
};

static inline struct common_header *to_common_header(void *msg)
{
	return (struct common_header *)(msg);
}

static inline void *to_payload(void *msg)
{
	return (void *)(msg + sizeof(struct common_header));
}

#endif /* _LEGO_RPC_STRUCT_COMMON_H_ */

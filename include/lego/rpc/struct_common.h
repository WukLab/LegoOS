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

#define MAX_FILENAME_LENGTH	256

#define COMMON_HEADER_ALIGNMENT (8)

struct common_header {
	unsigned int opcode;
	unsigned int src_nid;		/* source nid */

	/*
	 * XXX: Useless. Rmove me.
	 */
	unsigned int length;
} __aligned(COMMON_HEADER_ALIGNMENT);

static inline struct common_header *to_common_header(void *msg)
{
	return (struct common_header *)(msg);
}

static inline void *to_payload(void *msg)
{
	return (void *)(msg + sizeof(struct common_header));
}

#ifndef _LEGO_STORAGE_SOURCE_
/*
 * Fill the common_header part of the given @msg
 * @msg must have the common_header at the top of its struct.
 */
static __always_inline void fill_common_header(void *msg, unsigned int opcode)
{
	struct common_header *hdr;

	hdr = to_common_header(msg);
	hdr->opcode = opcode;
	hdr->src_nid = LEGO_LOCAL_NID;
}
#endif

#endif /* _LEGO_RPC_STRUCT_COMMON_H_ */

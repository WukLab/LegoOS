/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>

#define M2S_BASE	((__u32)0x00100000)
#define M2S_READ	((__u32)(M2S_BASE)+1)
#define M2S_WRITE	((__u32)(M2S_BASE)+2)
#define M2S_OPEN	((__u32)(M2S_BASE)+3)
#define LINUX_NODE	0
#define LEGO_NODE	1

#define DEBUG_STORAGE

/* fit module */
extern int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int if_use_ret_phys_addr);
extern int ibapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor);
extern int ibapi_reply_message(void *addr, int size, uintptr_t descriptor);

/*static inline struct common_header *to_common_header(void *msg)
{
	return (struct common_header *)(msg);
}*/

static inline void *to_payload(void *msg)
{
	return (void *)(msg + sizeof(__u32));
}


#define MAX_FILENAME_LENGTH	128

struct m2s_open_payload{
	int uid;
	char filename[MAX_FILENAME_LENGTH];
	fmode_t permission;
	int flags;
};

struct m2s_read_write_payload{
	int uid;
	char filename[MAX_FILENAME_LENGTH];
	int flags;
	size_t len;
	loff_t offset;
};

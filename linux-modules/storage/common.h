/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_STORAGE_COMMON_H_
#define _LEGO_STORAGE_COMMON_H_

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/statfs.h>

#include <lego/rpc/opcode.h>
#include <lego/rpc/struct_common.h>
#include <lego/rpc/struct_p2s.h>
#include <lego/rpc/struct_m2s.h>

#define BLK_SIZE	(5 * 4096)

/* fit module */
int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr,
			 int max_ret_size, int if_use_ret_phys_addr);
int ibapi_receive_message(unsigned int designed_port, void *ret_addr,
			  int receive_size, uintptr_t *descriptor);
int ibapi_reply_message(void *addr, int size, uintptr_t descriptor);

/* getdents */
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

#endif /* _LEGO_STORAGE_COMMON_H_ */

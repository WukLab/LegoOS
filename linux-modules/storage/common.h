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

#include "../../include/lego/comp_common.h"

#define LINUX_NODE	0
#define LEGO_NODE	1

//#define DEBUG_STORAGE
#define BLK_SIZE 5*4096

/* fit module */
int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int if_use_ret_phys_addr);
int ibapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor);
int ibapi_reply_message(void *addr, int size, uintptr_t descriptor);

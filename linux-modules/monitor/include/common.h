/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_COMMON_H 
#define _LEGO_COMMON_H 

#include "../../fit/fit_config.h"
#include <monitor_config.h>
#include <monitor/common.h>
#include <lego/rpc/struct_common.h>

/*
 * IB layer network API
 */
extern int ibapi_send_reply_imm(int target_node, void *addr, int size, 
			void *ret_addr, int max_ret_size, 
			int if_use_ret_phys_addr);
extern int ibapi_receive_message(unsigned int designed_port, void *ret_addr, 
			int receive_size, uintptr_t *descriptor);
extern int ibapi_reply_message(void *addr, int size, uintptr_t descriptor);

#endif /* _LEGO_COMMON_H */

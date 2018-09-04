/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Things shared by both processor-component and memory-component
 */

#ifndef _LEGO_COMP_COMMON_H_
#define _LEGO_COMP_COMMON_H_

#include <lego/distvm.h>

#define DEF_MEM_HOMENODE	CONFIG_DEFAULT_MEM_NODE
#define STORAGE_NODE		CONFIG_DEFAULT_STORAGE_NODE

#define DEF_NET_TIMEOUT	 30	/* second */

enum {
	MANAGER_DOWN,
	MANAGER_UP,
};
extern int manager_state;
extern unsigned int LEGO_LOCAL_NID;

void __init manager_init(void);
int pin_current_thread(void);
void pin_registered_threads(void);

#ifdef CONFIG_SOFT_WATCHDOG
void __init soft_watchdog_init(void);
#else
static inline void __init soft_watchdog_init(void) { }
#endif

int net_send_reply_timeout(u32 node, u32 opcode,
			   void *payload, u32 len_payload,
			   void *retbuf, u32 max_len_retbuf, bool retbuf_is_phys,
			   u32 timeout);

/*
 * Put those header files at last because they may need
 * to use some generic macros, variables defined above.
 */
#include <lego/rpc/opcode.h>
#include <lego/rpc/struct_common.h>
#include <lego/rpc/struct_p2m.h>
#include <lego/rpc/struct_p2s.h>
#include <lego/rpc/struct_m2m.h>
#include <lego/rpc/struct_m2s.h>

#endif /* _LEGO_COMP_COMMON_H_ */

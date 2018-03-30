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

#include <lego/rpc/opcode.h>
#include <lego/rpc/struct_common.h>
#include <lego/rpc/struct_p2m.h>
#include <lego/rpc/struct_p2s.h>
#include <lego/rpc/struct_m2m.h>
#include <lego/rpc/struct_m2s.h>

#define DEF_MEM_HOMENODE	CONFIG_DEFAULT_MEM_NODE
#define STORAGE_NODE		CONFIG_DEFAULT_STORAGE_NODE

#define DEF_NET_TIMEOUT	 30	/* second */

enum {
	MANAGER_DOWN,
	MANAGER_UP,
};
extern int manager_state;
extern unsigned int LEGO_LOCAL_NID;

void print_pinned_threads(void);
int pin_current_thread_core(void);
#ifdef CONFIG_CHECK_PINNED_THREADS
void check_pinned_status(void);
#else
static inline void check_pinned_status(void) { }
#endif

int net_send_reply_timeout(u32 node, u32 opcode,
			   void *payload, u32 len_payload,
			   void *retbuf, u32 max_len_retbuf, bool retbuf_is_phys,
			   u32 timeout);

struct gsm2p_ret_struct {
	int mid;
	int sid;
};

#endif /* _LEGO_COMP_COMMON_H_ */

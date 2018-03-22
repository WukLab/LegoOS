/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MONITOR_COMMON_H
#define _LEGO_MONITOR_COMMON_H

#include <lego/rpc/opcode.h>

/*
 * PM2P_START_PROC
 * start a new process
 */ 
struct pm2p_start_proc_struct {
	int vpid;			/* virtual pid */
	int homenode;			/* memory home node id */
};

#define max_cmd_len \
({ \
	(int)(MAX_RXBUF_SIZE - sizeof(struct common_header) \
		- sizeof(struct pm2p_start_proc_struct)); \
})

/*
 * P2PM_EXIT_PROC
 * report process exit status to processor monitor
 */
struct p2pm_exit_proc_struct {
	int vpid;
	int ret;
};

/*
 * M2MM_CONSULT
 * consult memory monitor for memory allocation
 */
struct consult_info {
	unsigned long len;
};

/*
 * consult memory monitor for memory allocation
 */
struct alloc_scheme {
	int nid;
	unsigned long len;
};

/* 
 * this looks not clean but becuase linux module don't have
 * CONFIG_MEM_NR_NODES, so we have to define it in 
 * linux module header
 */
struct consult_reply {
	int count;
	struct alloc_scheme scheme[CONFIG_MEM_NR_NODES];
};

/* 
 * M2MM_MNODE_STATUS 
 * we don't need any struct when sending request,
 * only necessary when receive request
 */
struct m2mm_mnode_status_reply {
	unsigned long totalram;
	unsigned long freeram;
};

#endif /* _LEGO_MONITOR_COMMON_H */

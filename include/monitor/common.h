/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
/*
 * for any sending message struct, if no reply struct defined,
 * just reply the status using int
 */

#ifndef _LEGO_MONITOR_COMMON_H
#define _LEGO_MONITOR_COMMON_H

#include <lego/rpc/struct_common.h>

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
 * together reporting current memory status
 */
struct consult_info {
	unsigned long len;
	unsigned long freeram;
	unsigned long totalram;
	unsigned long nr_request;
};

/*
 * consult memory monitor for memory allocation
 */
struct alloc_scheme {
	int nid;
	unsigned long len;
};

struct consult_reply {
	int count;
	struct alloc_scheme scheme[CONFIG_FIT_NR_NODES];
};

/*
 * M2MM_MNODE_STATUS
 */
struct m2mm_status_report {
	struct common_header hdr;
	int counter;
	unsigned long totalram;
	unsigned long freeram;
	unsigned long nr_request;
};

/*
 * P2PM_REQUEST_VNODE
 */
struct p2pm_request_vnode_struct {
	struct common_header hdr;
};

struct p2pm_request_vnode_reply_struct {
	int status;
	int p_nid;
	int vid;
	int ip;
};

/*
 * PM2P_BROADCAST_VNODE
 */
struct pm2p_broadcast_vnode_struct {
	struct common_header hdr;
	int p_nid;
	int vid;
	int ip;
};

#endif /* _LEGO_MONITOR_COMMON_H */

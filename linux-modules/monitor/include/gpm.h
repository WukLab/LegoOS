/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_GPM_H
#define _LEGO_GPM_H

#include <common.h>

#define VNODE_MAP_SIZE			(1 << VNODE_MAP_ORDER)

/*
 * vnode struct 
 */
struct vnode_struct {
	int p_nid;
	int vid;
	int ip;
};

/*
 * process information structs, holding information of all processes
 */
struct proc_struct {
	__u32 vpid;
	char *command;
	struct pnode_struct *pnode;
	struct list_head proclist;
};

/*
 * information of each processor component
 */
struct pnode_struct {
	__u32 nid;
	__u32 core_count;
	__u32 proc_count;
	struct list_head proclist;
	struct list_head list;
};

#define info_offset(buffer) \
({ \
 	(void *)(buffer + sizeof(struct common_header)); \
})

#define cmd_offset(buffer) \
({ \
 	(char *)(buffer + sizeof(struct common_header) \
			+ sizeof(struct pm2p_start_proc_struct)); \
})

#define start_proc_msg_len(size) \
({ \
 	sizeof(struct common_header) + sizeof(struct pm2p_start_proc_struct) + size; \
})

int lego_proc_create(char*, int);
extern int handle_p2pm_exit_proc(struct p2pm_exit_proc_struct *payload, 
				 uintptr_t desc, struct common_header *hdr);
extern int handle_p2pm_request_vnode(struct p2pm_request_vnode_struct *req, uintptr_t desc);

#endif /* _LEGO_GPM_H */

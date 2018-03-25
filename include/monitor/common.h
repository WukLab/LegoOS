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

/*
 * communication type enum
 *
 * Prefix Rules:
 * 	PM2P:	processor monitor -> processor
 * 	P2PM:	processor -> processor monitor
 * 	PM2UM:	processor monitor -> user monitor
 * 	UM2PM:	user monitor -> processor monitor
 * 	M2MM:   memory -> memory monitor
 *
 */

#define MONITOR_BASE			((__u32)0x10000000)
#define PM2P_START_PROC			(MONITOR_BASE + 1)
#define P2PM_EXIT_PROC			(MONITOR_BASE + 2)
#define M2MM_CONSULT	 		(MONITOR_BASE + 3) 
#define MM2M_CONSULT_REPLY		(MONITOR_BASE + 4)	/* only used during reply */

/*
 * PM2P_START_PROC
 * start a new process
 */ 
struct pm2p_start_proc_struct {
	int vpid;			/* virtual pid */
	int homenode;			/* memory home node id */
};

#define start_proc_msg_size(hdr) \
({ \
	(int)(hdr->length - sizeof(struct common_header) \
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
	__u32 len;
};

/*
 * MM2M_CONSULT_REPLY
 * consult memory monitor for memory allocation
 */
struct consult_reply {
	__u32 count;
};

/*
 * the msg buffer above has to be a chain
 * of the struct alloc_scheme
 */
struct alloc_scheme {
	__u32 nid;
	__u64 len;
};

#define alloc_scheme_msg_size(reply) \
({ \
 	(((struct common_header *)reply)->length - \
			sizeof(struct common_header) - \
			sizeof(struct consult_reply)); \
})

#define is_reply_valid(length, count) \
({ \
 	(count && length == count * sizeof(struct alloc_scheme)); \
})

#define consult_reply_entry(reply)	\
({ \
	(struct consult_reply *)(reply + \
			sizeof(struct common_header)); \
})

#define alloc_scheme_entry(reply)	\
({ \
	(struct alloc_scheme *)(reply + \
			sizeof(struct common_header) + \
			sizeof(struct consult_reply));  \
})

#endif /* _LEGO_MONITOR_COMMON_H */

/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

#include <lego/sched.h>
#include <lego/signal.h>
#include <generated/unistd_64.h>

extern unsigned int LEGO_LOCAL_NID;

/*
 * Rules about our message opcodes:
 *
 * 1) Prefix:
 *	P2M: processor -> memory
 *	M2P: memory -> processor
 *	M2S: memory -> storage
 *	S2M: storage -> memory
 *
 * 2) System calls related:
 *	Follow the original SYSCALL number
 */

#define P2M_HEARTBEAT	((__u32)0x00000001)
#define P2M_LLC_MISS	((__u32)0x00000002)
#define P2M_FORK	((__u32)__NR_fork)
#define P2M_EXECVE	((__u32)__NR_execve)

/* To fold signal values into ret, without conflicting with EXXXX values */
#define RET_SIGNAL_BASE	((__u32)1000)

/* Return status */
#define RET_OKAY	((__u32)0)	/* Operation succeed */
#define RET_EPERM	((__u32)EPERM)	/* Operation not permitted */
#define RET_ESRCH	((__u32)ESRCH)	/* No such process */
#define RET_EAGAIN	((__u32)EAGAIN)	/* Try again */
#define RET_ENOMEM	((__u32)ENOMEM)	/* Out of memory */
#define RET_EFAULT	((__u32)EFAULT)	/* Bad address */

#define RET_ESIGSEGV	((__u32)(RET_SIGNAL_BASE+SIGSEGV)) /* Segmentation fault*/

static inline __u32 ERR_TO_LEGO_RET(long err)
{
	switch (err) {
	case -EPERM:	return RET_EPERM;
	case -ESRCH:	return RET_ESRCH;
	case -EAGAIN:	return RET_EAGAIN;
	case -ENOMEM:	return RET_ENOMEM;
	case -EFAULT:	return RET_EFAULT;
	default:	return RET_EFAULT;
	};
}

static inline char *ret_to_string(u32 ret_status)
{
	switch (ret_status) {
	case RET_OKAY:		return "Okay";
	case RET_EPERM:		return "Operation not permitted";
	case RET_ESRCH:		return "No such process";
	case RET_EAGAIN:	return "Try again";
	case RET_ENOMEM:	return "Out of memory";
	}
	return "undefined";
}

struct common_header {
	__u32	opcode;		/* see above */
	__u32	src_nid;	/* source nid */
	__u32	length;		/* of the whole message */
};

static inline struct common_header *to_common_header(void *msg)
{
	return (struct common_header *)(msg);
}

static inline void *to_payload(void *msg)
{
	return (void *)(msg + sizeof(struct common_header));
}

int net_send_reply(u32 node, u32 opcode,
		   void *payload, u32 len_payload,
		   void *retbuf, u32 max_len_retbuf, bool retbuf_is_phys);

int net_send_reply_timeout(u32 node, u32 opcode,
			   void *payload, u32 len_payload,
			   void *retbuf, u32 max_len_retbuf, bool retbuf_is_phys,
			   u32 timeout);

/* P2M_LLC_MISS */

struct p2m_llc_miss_struct {
	__u32	pid;
	__u32	flags;
	__u64	missing_vaddr;
};
int pcache_fill(unsigned long, unsigned long, unsigned long *);
int handle_p2m_llc_miss(struct p2m_llc_miss_struct *, u64,
			struct common_header *);

/* P2M_FORK */

struct p2m_fork_struct {
	__u32	pid;	
	char	comm[TASK_COMM_LEN];
};
int p2m_fork(struct task_struct *p);
int handle_p2m_fork(struct p2m_fork_struct *, u64, struct common_header *);

/* P2M_EXECVE */

/*
 * These are the maximum length and maximum number of strings passed to the
 * execve() system call.  MAX_ARG_STRLEN is essentially random but serves to
 * prevent the kernel from being unduly impacted by misaddressed pointers.
 * MAX_ARG_STRINGS is chosen to fit in a signed 32-bit integer.
 */
#define MAX_ARG_STRLEN		(PAGE_SIZE * 32)
#define MAX_ARG_STRINGS		0x7FFFFFFF

#define MAX_FILENAME_LENGTH	256
struct p2m_execve_struct {
	__u32	pid;
	__u32	payload_size;
	char	filename[MAX_FILENAME_LENGTH];
	__u32	argc;
	__u32	envc;
	char	*array;
	/*
	 * NOTE:
	 * variable size struct
	 * the @payload_size means the total size
	 */
};
struct m2p_execve_struct {
	__u32	status;
	__u64	new_ip;
	__u64	new_sp;
};
int handle_p2m_execve(struct p2m_execve_struct *, u64, struct common_header *);

#endif /* _LEGO_COMP_COMMON_H_ */

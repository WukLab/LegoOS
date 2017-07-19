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
#define P2M_MMAP	((__u32)__NR_mmap)
#define P2M_MUNMAP	((__u32)__NR_munmap)
#define P2M_BRK		((__u32)__NR_brk)
#define P2M_FORK	((__u32)__NR_fork)
#define P2M_EXECVE	((__u32)__NR_execve)
#define P2M_TEST	((__u32)0x0fffffff)

#define M2S_BASE	((__u32)0x00100000)
#define M2S_READ	((__u32)(M2S_BASE)+1)
#define M2S_WRITE	((__u32)(M2S_BASE)+2)

/* Return status */
#define RET_OKAY	((__u32)0)	/* Operation succeed */
#define RET_ENOENT	((__u32)ENOENT)	/* No such file or directory */
#define RET_ESRCH	((__u32)ESRCH)	/* No such process */
#define RET_EINTR	((__u32)EINTR)	/* Interrupted system call */
#define RET_EPERM	((__u32)EPERM)	/* Operation not permitted */
#define RET_EAGAIN	((__u32)EAGAIN)	/* Try again */
#define RET_ENOMEM	((__u32)ENOMEM)	/* Out of memory */
#define RET_EFAULT	((__u32)EFAULT)	/* Bad address */
#define RET_EBUSY	((__u32)EBUSY)	/* Device or resource busy */
#define RET_EEXIST	((__u32)EEXIST) /* Already exist */
#define RET_EINVAL	((__u32)EINVAL) /* invalid argument */
#define RET_NOSYS	((__u32)ENOSYS)	/* Invalid system call number */

/* To fold signal values into ret, without conflicting with EXXXX values */
#define RET_SIGNAL_BASE	((__u32)0x01000000)

#define RET_ESIGSEGV	((__u32)(RET_SIGNAL_BASE+SIGSEGV)) /* Segmentation fault*/

static inline __u32 ERR_TO_LEGO_RET(long err)
{
	switch (err) {
	case -EINTR:	return RET_EINTR;
	case -EPERM:	return RET_EPERM;
	case -ESRCH:	return RET_ESRCH;
	case -EAGAIN:	return RET_EAGAIN;
	case -ENOMEM:	return RET_ENOMEM;
	case -EFAULT:	return RET_EFAULT;
	case -EINVAL:	return RET_EINVAL;
	default:	return RET_EFAULT;
	};
}

static inline char *ret_to_string(u32 ret_status)
{
	switch (ret_status) {
	case RET_OKAY:		return "OKAY";
	case RET_ENOENT:	return "ENOENT:No such file or directory";
	case RET_ESRCH:		return "ESRCH:No such process";
	case RET_EINTR:		return "EINTR:Interrupted system call";
	case RET_EPERM:		return "EPERM:Operation not permitted";
	case RET_EAGAIN:	return "EAGAIN:Try again";
	case RET_ENOMEM:	return "ENOMEM:Out of memory";
	case RET_EFAULT:	return "EFAULT:bad address";
	case RET_EBUSY:		return "EBUSY:resource busy";
	case RET_EEXIST:	return "EEXIST:already exist";
	case RET_EINVAL:	return "EINVAL:Invalid argument";
	case RET_NOSYS:		return "ENOSYS:invalid system call number";
	}
	return "Undefined ret_status";
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

/* Task command name length */
#define LEGO_TASK_COMM_LEN 16

struct p2m_fork_struct {
	__u32	pid;	
	char	comm[LEGO_TASK_COMM_LEN];
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

/* P2M_MMAP */
struct p2m_mmap_struct {
	__u32	pid;
	__u64	addr;
	__u64	len;
	__u32	prot;
	__u32	flags;
	__u32	fd;
	__u64	off;
};
int handle_p2m_mmap(struct p2m_mmap_struct *, u64, struct common_header *);

/* P2M_MUNMAP */
struct p2m_munmap_struct {
	__u32	pid;
	__u64	addr;
	__u64	len;
};
int handle_p2m_munmap(struct p2m_munmap_struct *, u64, struct common_header *);

/* P2M_BRK */
struct p2m_brk_struct {
	__u32	pid;
	__u64	brk;
};
int handle_p2m_brk(struct p2m_brk_struct *, u64, struct common_header *);

/* M2S_READ */
struct m2s_read {
	__u32	pid;
	char    filename[MAX_FILENAME_LENGTH];
};

/* M2S_WRITE */
struct m2s_write {
	__u32	pid;
	char    filename[MAX_FILENAME_LENGTH];
};

#endif /* _LEGO_COMP_COMMON_H_ */

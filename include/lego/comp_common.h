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

#include <processor/pcache.h>

#define DEF_MEM_HOMENODE	CONFIG_DEFAULT_MEM_NODE
#define STORAGE_NODE		CONFIG_DEFAULT_STORAGE_NODE

#define DEF_NET_TIMEOUT	 30	/* second */

enum {
	MANAGER_DOWN,
	MANAGER_UP,
};
extern int manager_state;
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

#define P2M_HEARTBEAT	((__u32)0x10000000)
#define P2M_PCACHE_MISS	((__u32)0x20000000)
#define P2M_PCACHE_FLUSH ((__u32)0x30000000)

#define P2M_READ	((__u32)__NR_read)
#define P2M_WRITE	((__u32)__NR_write)
#define P2M_CLOSE	((__u32)__NR_close)
#define P2M_MMAP	((__u32)__NR_mmap)
#define P2M_MPROTECT	((__u32)__NR_mprotect)
#define P2M_MUNMAP	((__u32)__NR_munmap)
#define P2M_MREMAP	((__u32)__NR_mremap)
#define P2M_BRK		((__u32)__NR_brk)
#define P2M_MSYNC	((__u32)__NR_msync)
#define P2M_FORK	((__u32)__NR_fork)
#define P2M_EXECVE	((__u32)__NR_execve)
#define P2M_CHECKPOINT	((__u32)__NR_checkpoint_process)
#define P2M_TEST	((__u32)0x0fffffff)

/* Processor to Storage directly */
#define P2S_OPEN	((__u32)__NR_open)	/* open() goes to storage directly */
#define P2S_STAT	((__u32)__NR_stat)
#define P2S_ACCESS	((__u32)__NR_access)

/* Memory to Storage */
#define M2S_READ	P2M_READ		/* Reuse the same nr */
#define M2S_WRITE	P2M_WRITE		/* Reuse the same nr */
/* Processor to GSM */
#define P2GSM_COMMON	P2S_OPEN		/* Resue the open nr */

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

int net_send_reply_timeout(u32 node, u32 opcode,
			   void *payload, u32 len_payload,
			   void *retbuf, u32 max_len_retbuf, bool retbuf_is_phys,
			   u32 timeout);

/* P2M_PCACHE_MISS */

struct p2m_pcache_miss_struct {
	__u32	pid;
	__u32	tgid;
	__u32	flags;
	__u64	missing_vaddr;
};

#define PCACHE_MAPPING_ANON	0x1
#define PCACHE_MAPPING_FILE	0x2

struct p2m_pcache_miss_reply_struct {
	__u32	mapping_flags;
	__wsum	csum;
	char	data[PCACHE_LINE_SIZE];
};

int handle_p2m_pcache_miss(struct p2m_pcache_miss_struct *, u64,
			struct common_header *);

#define MAX_FILENAME_LENGTH	128

/* P2M_READ */
/* P2M_WRITE */
/*
 * We need pass the filename, uid, flags, len, offset
 * and virtual address of user buffer to memory component
 * Also we need nid and pid to convert user virtual address
 * to coresponding kernel virtual address.
 */
struct p2m_read_write_payload {
	u32	pid;
	u32	tgid;
	char __user *buf;
	int	uid;
	char	filename[MAX_FILENAME_LENGTH];
	int	flags;
	ssize_t	len;
	loff_t	offset;
};
int handle_p2m_read(struct p2m_read_write_payload*, u64, struct common_header *);
int handle_p2m_write(struct p2m_read_write_payload*, u64, struct common_header *);

/* P2M_CLOSE */
struct p2m_close_struct {
	__u32 pid;
};
int handle_p2m_close(struct p2m_close_struct *, u64, struct common_header *);

/* P2M_FORK */

/* Task command name length */
#define LEGO_TASK_COMM_LEN 16

struct p_vm_area_struct {
	__u64	vm_start;
	__u64	vm_end;
	__u64	vm_flags;
};

struct p2m_fork_struct {
	__u32	pid;
	__u32	tgid;
	__u32	parent_tgid;
	__u32	clone_flags;
	char	comm[LEGO_TASK_COMM_LEN];
};
int p2m_fork(struct task_struct *p, unsigned long clone_flags);
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
	__u64	prot;
	__u64	flags;
	__u64	pgoff;
	char	f_name[MAX_FILENAME_LENGTH];
};
struct p2m_mmap_reply_struct {
	__u32	ret;
	__u64	ret_addr;
};
int handle_p2m_mmap(struct p2m_mmap_struct *, u64, struct common_header *);

/* P2M_MUNMAP */
struct p2m_munmap_struct {
	__u32	pid;
	__u64	addr;
	__u64	len;
};
int handle_p2m_munmap(struct p2m_munmap_struct *, u64, struct common_header *);

/* P2M_MREMAP */
struct p2m_mremap_struct {
	__u32	pid;
	__u64	old_addr;
	__u64	old_len;
	__u64	new_len;
	__u64	flags;
	__u64	new_addr;
};

struct p2m_mremap_reply_struct {
	__u32	status;
	__u32	line;			/* which line fails... */
	__u64	new_addr;
};
int handle_p2m_mremap(struct p2m_mremap_struct *, u64, struct common_header *);

/* P2M_MPROTECT */
struct p2m_mprotect_struct {
	__u32	pid;
	__u64	addr;
	__u64	len;
	__u32	prot;
};
int handle_p2m_mprotect(struct p2m_mprotect_struct *, u64, struct common_header *);

/* P2M_BRK */
struct p2m_brk_struct {
	__u32	pid;
	__u64	brk;
};
int handle_p2m_brk(struct p2m_brk_struct *, u64, struct common_header *);

/* P2M_MSYNC */
#define MS_ASYNC	1		/* sync memory asynchronously */
#define MS_INVALIDATE	2		/* invalidate the caches */
#define MS_SYNC		4		/* synchronous memory sync */
struct p2m_msync_struct {
	__u32	pid;
	__u64	start;
	__u64	len;
	__u32	flags;
};
int handle_p2m_msync(struct p2m_msync_struct *, u64, struct common_header *);

/* P2M_CHECKPOINT */
int handle_p2m_checkpint(void *, u64, struct common_header *);

/* P2S_OPEN */
struct p2s_open_struct{
	int	uid;
	char	filename[MAX_FILENAME_LENGTH];
	fmode_t	permission;
	int	flags;
};

/* M2S_READ */
/* M2S_WRITE */
struct m2s_read_write_payload{
	int	uid;
	char	filename[MAX_FILENAME_LENGTH];
	int	flags;
	size_t	len;
	loff_t	offset;
};

/* P2M_PCACHE_FLUSH */
struct p2m_flush_payload {
	u32		pid;
	unsigned long	user_va;
	char		pcacheline[PCACHE_LINE_SIZE];
};
int handle_p2m_flush_one(struct p2m_flush_payload *, u64, struct common_header *);

struct p2s_access_struct {
	char filename[MAX_FILENAME_LENGTH];
	int mode;
};

struct p2s_stat_struct {
	char filename[MAX_FILENAME_LENGTH];
	int flag;
};

struct gsm2p_ret_struct {
	int mid;
	int sid;
};
#endif /* _LEGO_COMP_COMMON_H_ */

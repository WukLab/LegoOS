/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_RPC_OPCODE_H_
#define _LEGO_RPC_OPCODE_H_

#include <generated/unistd_64.h>

/*
 * Rules about our message opcodes:
 *
 * 1) Prefix:
 *	P2M:	processor <--> memory
 *	P2S:	processor <--> storage
 *	M2S:	memory    <--> storage
 *	P2GSM:	processor <--> global storage monitor
 *	PM2P:	processor monitor -> processor
 *	P2PM:	processor -> processor monitor
 *	M2MM:   memory -> memory monitor
 *
 * 2) System calls related:
 *	Follow the original SYSCALL number
 */

#define P2M_HEARTBEAT		((__u32)0x10000000)
#define P2M_PCACHE_MISS		((__u32)0x20000000)
#define P2M_PCACHE_FLUSH	((__u32)0x30000000)
#define P2M_PCACHE_REPLICA	((__u32)0x30000001)
#define P2M_PCACHE_ZEROFILL	((__u32)0x30000002)


/* 
 * add our own opcode
 */
#define P2M_MQOPEN		((__u32)__NR_mq_open)		
#define P2M_MQCLOSE		((__u32)__NR_mq_close)		
#define P2M_MQSEND		((__u32)__NR_mq_send)
#define P2M_MQRECV		((__u32)__NR_mq_receive)

#define P2M_READ		((__u32)__NR_read)
#define P2M_WRITE		((__u32)__NR_write)
#define P2M_CLOSE		((__u32)__NR_close)
#define P2M_MMAP		((__u32)__NR_mmap)
#define P2M_MPROTECT		((__u32)__NR_mprotect)
#define P2M_MUNMAP		((__u32)__NR_munmap)
#define P2M_MREMAP		((__u32)__NR_mremap)
#define P2M_BRK			((__u32)__NR_brk)
#define P2M_MSYNC		((__u32)__NR_msync)
#define P2M_FORK		((__u32)__NR_fork)
#define P2M_EXECVE		((__u32)__NR_execve)
#define P2M_CHECKPOINT		((__u32)__NR_checkpoint_process)
#define P2M_TEST		((__u32)0x0ffffff0)
#define P2M_TEST_NOREPLY	((__u32)0x0ffffff1)
#define P2M_RENAME		((__u32)__NR_rename)
#define P2M_STAT		((__u32)__NR_stat)
#define P2M_DROP_CACHE		((__u32)__NR_drop_page_cache)

/* Processor to Storage directly */
#define P2S_OPEN		((__u32)__NR_open)	/* open() goes to storage directly */
#define P2S_STAT		((__u32)__NR_stat)
#define P2S_ACCESS		((__u32)__NR_access)
#define P2S_TRUNCATE		((__u32)__NR_truncate)
#define P2S_UNLINK		((__u32)__NR_unlink)
#define P2S_MKDIR		((__u32)__NR_mkdir)
#define P2S_RMDIR		((__u32)__NR_rmdir)
#define P2S_STATFS		((__u32)__NR_statfs)
#define P2S_GETDENTS		((__u32)__NR_getdents)
#define P2S_READLINK		((__u32)__NR_readlink)
#define P2S_RENAME		((__u32)__NR_rename)
#define P2M_LSEEK		((__u32)__NR_lseek)
#define P2M_FSYNC		((__u32)__NR_fsync)

/* Homenode Memory to other Memory */
#define M2M_BASE		((__u32)0x40000000)
#define M2M_MMAP		(M2M_BASE + 1)
#define M2M_MUNMAP		(M2M_BASE + 2)
#define M2M_MREMAP_GROW		(M2M_BASE + 3)
#define M2M_MREMAP_MOVE		(M2M_BASE + 4)
#define M2M_MREMAP_MOVE_SPLIT	(M2M_BASE + 5)
#define M2M_FINDVMA		(M2M_BASE + 6)
#define M2M_MSYNC		(M2M_BASE + 7)
#define M2M_FORK		(M2M_BASE + 8)
#define M2M_VALIDATE		(M2M_BASE + 9)

/* Monitor relevant opcode */
#define MONITOR_BASE			((__u32)0x50000000)
#define PM2P_START_PROC			(MONITOR_BASE + 1)
#define P2PM_EXIT_PROC			(MONITOR_BASE + 2)
#define M2MM_CONSULT			(MONITOR_BASE + 3)
#define M2MM_STATUS_REPORT		(MONITOR_BASE + 4)
#define P2PM_REQUEST_VNODE		(MONITOR_BASE + 5)
#define PM2P_BROADCAST_VNODE		(MONITOR_BASE + 6)

/* Memory to Storage */
#define M2S_READ		P2M_READ		/* Reuse the same nr */
#define M2S_WRITE		P2M_WRITE		/* Reuse the same nr */
#define M2S_LSEEK		P2M_LSEEK		/* Reuse the same nr */

#define M2S_BASE		((__u32)0x60000000)
#define M2S_REPLICA_FLUSH	(M2S_BASE + 1)
#define M2S_REPLICA_VMA		(M2S_BASE + 2)

/* Processor to GSM */
#define P2GSM_COMMON		P2S_OPEN		/* Resue the open nr */

/* Return status */
#define RET_OKAY		((__u32)0)	/* Operation succeed */
#define RET_ENOENT		((__u32)ENOENT)	/* No such file or directory */
#define RET_ESRCH		((__u32)ESRCH)	/* No such process */
#define RET_EINTR		((__u32)EINTR)	/* Interrupted system call */
#define RET_EPERM		((__u32)EPERM)	/* Operation not permitted */
#define RET_EAGAIN		((__u32)EAGAIN)	/* Try again */
#define RET_ENOMEM		((__u32)ENOMEM)	/* Out of memory */
#define RET_EFAULT		((__u32)EFAULT)	/* Bad address */
#define RET_EBUSY		((__u32)EBUSY)	/* Device or resource busy */
#define RET_EEXIST		((__u32)EEXIST) /* Already exist */
#define RET_EINVAL		((__u32)EINVAL) /* invalid argument */
#define RET_NOSYS		((__u32)ENOSYS)	/* Invalid system call number */

/* To fold signal values into ret, without conflicting with EXXXX values */
#define RET_SIGNAL_BASE		((__u32)0x01000000)

#define RET_ESIGSEGV		((__u32)(RET_SIGNAL_BASE+SIGSEGV)) /* Segmentation fault*/

// State Management
//#define P2M_STATE_BASE          ((__u32)0x70000000)
#define P2M_STATE_DUMMY_GET		((__u32)__NR_dummy_get)
#define P2M_STATE_SAVE		    ((__u32)__NR_state_save)
#define P2M_STATE_LOAD		    ((__u32)__NR_state_load)
//#define P2M_STATE_DUMMY_GET		(P2M_STATE_BASE + 1)
//#define P2M_STATE_SAVE		    (P2M_STATE_BASE + 2)
//#define P2M_STATE_LOAD		    (P2M_STATE_BASE + 3)



static inline unsigned int ERR_TO_LEGO_RET(long err)
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

#endif /* _LEGO_RPC_OPCODE_H_ */

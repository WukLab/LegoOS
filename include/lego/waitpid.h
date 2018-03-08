/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Macros and helpers for syscalls:
 *  - waitid
 *  - wait4
 */

#ifndef _LEGO_WAITPID_H_
#define _LEGO_WAITPID_H_

#include <lego/pid.h>
#include <lego/types.h>
#include <lego/time.h>
#include <lego/kernel.h>
#include <lego/siginfo.h>

#define WNOHANG		0x00000001
#define WUNTRACED	0x00000002
#define WSTOPPED	WUNTRACED
#define WEXITED		0x00000004
#define WCONTINUED	0x00000008
#define WNOWAIT		0x01000000	/* Don't reap, just poll status.  */

#define __WNOTHREAD	0x20000000	/* Don't wait on children of other threads in this group */
#define __WALL		0x40000000	/* Wait on all children, regardless of type */
#define __WCLONE	0x80000000	/* Wait only on non-SIGCHLD children */

/* First argument to waitid: */
#define P_ALL		0
#define P_PID		1
#define P_PGID		2

/*
 * Definition of struct rusage taken from BSD 4.3 Reno
 * 
 * We don't support all of these yet, but we might as well have them....
 * Otherwise, each time we add new items, programs which depend on this
 * structure will lose.  This reduces the chances of that happening.
 */
#define	RUSAGE_SELF	0
#define	RUSAGE_CHILDREN	(-1)
#define RUSAGE_BOTH	(-2)		/* sys_wait4() uses this */
#define	RUSAGE_THREAD	1		/* only the calling thread */

struct rusage {
	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
	long	ru_maxrss;		/* maximum resident set size */
	long	ru_ixrss;		/* integral shared memory size */
	long	ru_idrss;		/* integral unshared data size */
	long	ru_isrss;		/* integral unshared stack size */
	long	ru_minflt;		/* page reclaims */
	long	ru_majflt;		/* page faults */
	long	ru_nswap;		/* swaps */
	long	ru_inblock;		/* block input operations */
	long	ru_oublock;		/* block output operations */
	long	ru_msgsnd;		/* messages sent */
	long	ru_msgrcv;		/* messages received */
	long	ru_nsignals;		/* signals received */
	long	ru_nvcsw;		/* voluntary context switches */
	long	ru_nivcsw;		/* involuntary " */
};

int getrusage(struct task_struct *p, int who, struct rusage __user *ru);

#endif /* _LEGO_WAITPID_H_ */

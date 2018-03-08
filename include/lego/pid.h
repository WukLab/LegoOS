/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PID_H_
#define _LEGO_PID_H_

#include <lego/sched.h>

/*
 * XXX:
 *
 * Currently in Lego, we don't support pgid
 * thus pid == pgid
 */
enum pid_type
{
	PIDTYPE_PID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX,

	/* only valid to __task_pid_nr_ns() */
	__PIDTYPE_TGID
};

pid_t alloc_pid(struct task_struct *p);
void free_pid(pid_t pid);

struct task_struct *find_task_by_pid(pid_t pid);

void __init pid_init(void);

#endif /* _LEGO_PID_H_ */

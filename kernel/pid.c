/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "pid: " fmt

#include <lego/pid.h>
#include <lego/sched.h>
#include <lego/bitops.h>
#include <lego/kernel.h>
#include <lego/memblock.h>
#include <lego/spinlock.h>

#define DEFAULT_MAX_PID	65535

static DECLARE_BITMAP(pid_map, DEFAULT_MAX_PID);
static DEFINE_SPINLOCK(pid_lock);

static struct task_struct **pid_task_map;

pid_t alloc_pid(struct task_struct *p)
{
	int bit;

	BUG_ON(!p);

	spin_lock(&pid_lock);
	/* pid 0 is swapper */
	bit = find_next_zero_bit(pid_map, DEFAULT_MAX_PID, 1);
	if (WARN_ON(bit >= DEFAULT_MAX_PID)) {
		bit = -1;
		goto unlock;
	}
	__set_bit(bit, pid_map);
	pid_task_map[bit] = p;
unlock:
	spin_unlock(&pid_lock);
	return (pid_t)bit;
}

void free_pid(pid_t pid)
{
	if (WARN_ON(pid <= 0 || pid >= DEFAULT_MAX_PID))
		return;

	spin_lock(&pid_lock);
	BUG_ON(!test_and_clear_bit(pid, pid_map));
	BUG_ON(!pid_task_map[pid]);
	pid_task_map[pid] = NULL;
	spin_unlock(&pid_lock);
}

struct task_struct *find_task_by_pid(pid_t pid)
{
	if (pid <= 0 || pid >= DEFAULT_MAX_PID)
		return NULL;

	return pid_task_map[pid];
}

void __init pid_init(void)
{
	size_t size;

	size = DEFAULT_MAX_PID * sizeof(struct task_struct *);
	pid_task_map = memblock_virt_alloc(size, 0);
	if (!pid_task_map)
		panic("fail to allocate pid task map\n");
	else
		pr_info("pid_task_map: %p, size: %#lx\n",
			pid_task_map, size);
}

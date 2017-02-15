/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/bitops.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>

#define DEFAULT_MAX_PID 65535

static DECLARE_BITMAP(pid_map, DEFAULT_MAX_PID);
static DEFINE_SPINLOCK(pid_lock);

pid_t alloc_pid(void)
{
	int bit;

	spin_lock(&pid_lock);
	/* pid 0 is swapper */
	bit = find_next_zero_bit(pid_map, DEFAULT_MAX_PID, 1);
	if (bit >= DEFAULT_MAX_PID) {
		bit = -1;
		goto unlock;
	}
	__set_bit(bit, pid_map);
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
	spin_unlock(&pid_lock);
}

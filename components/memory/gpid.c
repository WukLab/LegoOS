/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/comp_memory.h>
#include <lego/comp_common.h>

pid_t alloc_gpid(struct lego_task_struct *tsk)
{
	return 0;
}

void free_gpid(pid_t pid)
{
	return;
}

struct lego_task_struct *
find_lego_task_by_pid(unsigned int node, pid_t pid)
{
	return NULL;
}

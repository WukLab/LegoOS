/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <disos/sched.h>

#define INIT_TASK(task)							\
{									\
	.state		= 0,						\
	.comm		= "swapper",					\
	.stack		= &init_thread_info,				\
}

struct task_struct init_task = INIT_TASK(init_task);

/*
 * Initial task kernel stack.
 * The alignment is handled specially by linker script.
 */
union thread_union init_thread_union __init_task_data = {
	INIT_THREAD_INFO(init_task)
};

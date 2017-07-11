/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file records SYSCALLs that are ONLY available
 * at processor-component. We just define a simple prototypes
 * here and panic in case someone calls.
 */

#include <lego/syscalls.h>

#define MSG	"%s(): is not allowed at memory-component\n", __func__

SYSCALL_DEFINE3(execve,
		const char __user*, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	return 0;
}

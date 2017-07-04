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

#include <generated/unistd_64.h>

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

#define P2M_HEARTBEAT	(0x00000001)
#define P2M_LLC_MISS	(0x00000002)
#define P2M_FORK	((__u32)__NR_fork)
#define P2M_EXECVE	((__u32)__NR_execve)

#endif /* _LEGO_COMP_COMMON_H_ */

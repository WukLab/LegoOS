/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PREEMPT_H_
#define _LEGO_PREEMPT_H_

#include <lego/percpu.h>

DECLARE_PER_CPU(int, __preempt_count);

static __always_inline int preempt_count(void)
{
	return this_cpu_read(__preempt_count);
}

#endif /* _LEGO_PREEMPT_H_ */

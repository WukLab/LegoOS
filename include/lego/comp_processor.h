/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_COMP_PROCESSOR_H_
#define _LEGO_COMP_PROCESSOR_H_

#include <lego/compiler.h>

#ifdef CONFIG_COMP_PROCESSOR
void __init processor_component_init(void);
int __init processor_cache_range_register(u64 start, u64 size);
#else
static inline void processor_component_init(void) { }
static inline int processor_cache_range_register(u64 start, u64 size)
{
	return 0;
}
#endif

#endif /* _LEGO_COMP_PROCESSOR_H_ */

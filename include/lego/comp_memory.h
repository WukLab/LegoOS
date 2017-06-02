/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_COMP_MEMORY_H_
#define _LEGO_COMP_MEMORY_H_

#include <lego/compiler.h>

#ifdef CONFIG_COMP_MEMORY
void __init memory_component_init(void);
#else
static inline void memory_component_init(void) { }
#endif

#endif /* _LEGO_COMP_MEMORY_H_ */

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/sched.h>
#include <lego/kernel.h>

#ifdef CONFIG_MEMCOMPONENT
void memcomponent_init(void);
void memory_cleanup(void);
void mem_handle_fault(struct task_struct *task, unsigned long address);
#else
static inline void  memcomponent_init(void) { }
static inline void  memcomponent_cleanup(void) { }
static inline void mem_handle_fault(struct task_struct *task, unsigned long address) { }
#endif


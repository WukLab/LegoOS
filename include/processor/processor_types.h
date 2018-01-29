/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PROCESSOR_TYPES_H_
#define _LEGO_PROCESSOR_PROCESSOR_TYPES_H_

#include <lego/atomic.h>

#ifdef CONFIG_COMP_PROCESSOR

struct processor_manager {
	int		home_node;
#ifdef CONFIG_CHECKPOINT
	atomic_t	process_barrier;
#endif
};

#define get_memory_home_node(tsk) ({		\
	tsk->pm_data.home_node;			\
})

#define set_memory_home_node(tsk, new)		\
	do {					\
		tsk->pm_data.home_node = new;	\
	} while (0)

#define current_memory_home_node() ({		\
	get_memory_home_node(current);		\
})

#endif /* COMP_PROSESSOR */

#endif /* _LEGO_PROCESSOR_PROCESSOR_TYPES_H_ */

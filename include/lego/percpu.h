/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PERCPU_H_
#define _LEGO_PERCPU_H_

/*
 * BIG TODO here Bro!
 *
 * And Caution!
 * Everything here actually is not safe, because interrupt
 * is not disabled. The chance that interrupt happen between
 * smp_proceesor_id and index into array is pretty normal??
 */

#include <lego/cpumask.h>	/* For NR_CPU */
#include <lego/compiler.h>	/* For __percpu */

#define DEFINE_PER_CPU(type, name) \
	__typeof__(type) name[NR_CPUS] __percpu

#define DECLARE_PER_CPU(type, name) \
	extern DEFINE_PER_CPU(type, name)

#define per_cpu_ptr(var, cpu) \
	((void *)(&(var) + cpu))

#endif /* _LEGO_PERCPU_H_ */

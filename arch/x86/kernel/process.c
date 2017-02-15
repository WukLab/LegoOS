/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/msr.h>
#include <asm/ptrace.h>
#include <asm/processor.h>

#include <lego/sched.h>
#include <lego/kernel.h>

/*
 * per-CPU TSS segments. Threads are completely 'soft' on LegoOS,
 * no more per-task TSS's. The TSS size is kept cacheline-aligned
 * so they are allowed to end up in the .data..cacheline_aligned
 * section. Since TSS's are completely CPU-local, we want them
 * on exact cacheline boundaries, to eliminate cacheline ping-pong.
 */

struct tss_struct cpu_tss = {
	.x86_tss = {
		.sp0 = TOP_OF_INIT_STACK,
	 },
};

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/ctype.h>
#include <lego/sched.h>
#include <lego/string.h>
#include <lego/kernel.h>

#include <asm/asm.h>
#include <asm/msr.h>
#include <asm/desc.h>
#include <asm/processor.h>

struct cpuid_bit {
	u16 feature;
	u8 reg;
	u8 bit;
	u32 level;
	u32 sub_leaf;
};

enum cpuid_regs {
	CR_EAX = 0,
	CR_ECX,
	CR_EDX,
	CR_EBX
};

void init_scattered_cpuid_features(struct cpu_info *c)
{
	u32 max_level;
	u32 regs[4];
	const struct cpuid_bit *cb;

	static const struct cpuid_bit cpuid_bits[] = {
		{ X86_FEATURE_AVX512_4VNNIW,	CR_EDX, 2, 0x00000007, 0 },
		{ X86_FEATURE_AVX512_4FMAPS,	CR_EDX, 3, 0x00000007, 0 },
		{ X86_FEATURE_APERFMPERF,	CR_ECX, 0, 0x00000006, 0 },
		{ X86_FEATURE_EPB,		CR_ECX, 3, 0x00000006, 0 },
		{ X86_FEATURE_HW_PSTATE,	CR_EDX, 7, 0x80000007, 0 },
		{ X86_FEATURE_CPB,		CR_EDX, 9, 0x80000007, 0 },
		{ X86_FEATURE_PROC_FEEDBACK,	CR_EDX,11, 0x80000007, 0 },
		{ 0, 0, 0, 0, 0 }
	};

	for (cb = cpuid_bits; cb->feature; cb++) {

		/* Verify that the level is valid */
		max_level = cpuid_eax(cb->level & 0xffff0000);
		if (max_level < cb->level ||
		    max_level > (cb->level | 0xffff))
			continue;

		cpuid_count(cb->level, cb->sub_leaf, &regs[CR_EAX],
			    &regs[CR_EBX], &regs[CR_ECX], &regs[CR_EDX]);

		if (regs[cb->reg] & (1 << cb->bit))
			set_cpu_cap(c, cb->feature);
	}
}


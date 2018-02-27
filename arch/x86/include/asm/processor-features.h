/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_PROCESSOR_FEATURES_H_
#define _ASM_X86_PROCESSOR_FEATURES_H_

#include <asm/processor-features-flags.h>

#ifndef __ASSEMBLY__

#include <lego/bitops.h>
#include <lego/compiler.h>

enum cpuid_leafs
{
	CPUID_1_EDX		= 0,
	CPUID_8000_0001_EDX,
	CPUID_8086_0001_EDX,
	CPUID_LNX_1,
	CPUID_1_ECX,
	CPUID_C000_0001_EDX,
	CPUID_8000_0001_ECX,
	CPUID_LNX_2,
	CPUID_LNX_3,
	CPUID_7_0_EBX,
	CPUID_D_1_EAX,
	CPUID_F_0_EDX,
	CPUID_F_1_EDX,
	CPUID_8000_0008_EBX,
	CPUID_6_EAX,
	CPUID_8000_000A_EDX,
	CPUID_7_ECX,
	CPUID_8000_0007_EBX,
};

extern __u32 cpu_caps_cleared[NCAPINTS + NBUGINTS];
extern __u32 cpu_caps_set[NCAPINTS + NBUGINTS];

#ifdef CONFIG_X86_FEATURE_NAMES
extern const char * const x86_cap_flags[NCAPINTS*32];
extern const char * const x86_power_flags[32];
#define X86_CAP_FMT "%s"
#define x86_cap_flag(flag) x86_cap_flags[flag]
#else
#define X86_CAP_FMT "%d:%d"
#define x86_cap_flag(flag) ((flag) >> 5), ((flag) & 31)
#endif

/*
 * In order to save room, we index into this array by doing
 * X86_BUG_<name> - NCAPINTS*32.
 */
extern const char * const x86_bug_flags[NBUGINTS*32];

extern struct cpu_info default_cpu_info __read_mostly;

#define test_cpu_cap(c, bit)						\
	 test_bit(bit, (unsigned long *)((c)->x86_capability))

#define cpu_has(bit)		test_cpu_cap(&default_cpu_info, bit)
#define this_cpu_has(bit)	cpu_has(bit)
#define boot_cpu_has(bit)	cpu_has(bit)
#define set_cpu_cap(c, bit)	set_bit(bit, (unsigned long *)((c)->x86_capability))
#define clear_cpu_cap(c, bit)	clear_bit(bit, (unsigned long *)((c)->x86_capability))
#define setup_clear_cpu_cap(bit)			\
do {							\
	clear_cpu_cap(&default_cpu_info, bit);		\
	set_bit(bit, (unsigned long *)cpu_caps_cleared);\
} while (0)
#define setup_force_cpu_cap(bit)			\
do {							\
	set_cpu_cap(&default_cpu_info, bit);		\
	set_bit(bit, (unsigned long *)cpu_caps_set);	\
} while (0)

#define setup_force_cpu_bug(bit) setup_force_cpu_cap(bit)

#define static_cpu_has(c, bit)		boot_cpu_has(bit)

#define cpu_has_bug(c, bit)		cpu_has(bit)
#define set_cpu_bug(c, bit)		set_cpu_cap(c, (bit))
#define clear_cpu_bug(c, bit)		clear_cpu_cap(c, (bit))

#define static_cpu_has_bug(bit)		static_cpu_has((bit))
#define boot_cpu_has_bug(bit)		cpu_has_bug(&default_cpu_info, (bit))

#define MAX_CPU_FEATURES		(NCAPINTS * 32)
#define cpu_have_feature		boot_cpu_has

#define CPU_FEATURE_TYPEFMT		"x86,ven%04Xfam%04Xmod%04X"
#define CPU_FEATURE_TYPEVAL		default_cpu_info.x86_vendor, default_cpu_info.x86, \

#ifdef CONFIG_SMP
#define cpu_data(cpu)		default_cpu_info
#else
#define cpu_info		default_cpu_info
#define cpu_data(cpu)		default_cpu_info
#endif

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_PROCESSOR_FEATURES_H_ */

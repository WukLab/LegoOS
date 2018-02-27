/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <lego/bitops.h>

#include <asm/asm.h>
#include <asm/msr.h>
#include <asm/apic.h>
#include <asm/intel-family.h>
#include <asm/processor.h>

/*
 * Check for extended topology enumeration cpuid leaf 0xb and if it
 * exists, use it for populating initial_apicid and cpu topology
 * detection.
 */

/* leaf 0xb SMT level */
#define SMT_LEVEL	0

/* leaf 0xb sub-leaf types */
#define INVALID_TYPE	0
#define SMT_TYPE	1
#define CORE_TYPE	2

#define LEAFB_SUBTYPE(ecx)		(((ecx) >> 8) & 0xff)
#define BITS_SHIFT_NEXT_LEVEL(eax)	((eax) & 0x1f)
#define LEVEL_MAX_SIBLINGS(ebx)		((ebx) & 0xffff)

/*
 * Check for extended topology enumeration cpuid leaf 0xb and if it
 * exists, use it for populating initial_apicid and cpu topology
 * detection.
 */
void detect_extended_topology(struct cpu_info *c)
{
#ifdef CONFIG_SMP
	unsigned int eax, ebx, ecx, edx, sub_index;
	unsigned int ht_mask_width, core_plus_mask_width;
	unsigned int core_select_mask, core_level_siblings;
	static bool printed;

	if (c->cpuid_level < 0xb)
		return;

	cpuid_count(0xb, SMT_LEVEL, &eax, &ebx, &ecx, &edx);

	/*
	 * check if the cpuid leaf 0xb is actually implemented.
	 */
	if (ebx == 0 || (LEAFB_SUBTYPE(ecx) != SMT_TYPE))
		return;

	set_cpu_cap(c, X86_FEATURE_XTOPOLOGY);

	/*
	 * initial apic id, which also represents 32-bit extended x2apic id.
	 */
	c->initial_apicid = edx;

	/*
	 * Populate HT related information from sub-leaf level 0.
	 */
	core_level_siblings = LEVEL_MAX_SIBLINGS(ebx);
	core_plus_mask_width = ht_mask_width = BITS_SHIFT_NEXT_LEVEL(eax);

	sub_index = 1;
	do {
		cpuid_count(0xb, sub_index, &eax, &ebx, &ecx, &edx);

		/*
		 * Check for the Core type in the implemented sub leaves.
		 */
		if (LEAFB_SUBTYPE(ecx) == CORE_TYPE) {
			core_level_siblings = LEVEL_MAX_SIBLINGS(ebx);
			core_plus_mask_width = BITS_SHIFT_NEXT_LEVEL(eax);
			break;
		}

		sub_index++;
	} while (LEAFB_SUBTYPE(ecx) != INVALID_TYPE);

	core_select_mask = (~(-1 << core_plus_mask_width)) >> ht_mask_width;

	c->cpu_core_id = apic->phys_pkg_id(c->initial_apicid, ht_mask_width)
						 & core_select_mask;
	c->phys_proc_id = apic->phys_pkg_id(c->initial_apicid, core_plus_mask_width);
	/*
	 * Reinit the apicid, now that we have extended initial_apicid.
	 */
	c->apicid = apic->phys_pkg_id(c->initial_apicid, 0);

	// TODO:
	//c->x86_max_cores = (core_level_siblings / smp_num_siblings);

	if (!printed) {
		pr_info("CPU: Physical Processor ID: %d\n",
		       c->phys_proc_id);
		if (c->x86_max_cores > 1)
			pr_info("CPU: Processor Core ID: %d\n",
			       c->cpu_core_id);
		printed = 1;
	}
	return;
#endif
}

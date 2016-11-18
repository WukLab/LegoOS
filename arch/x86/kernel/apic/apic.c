/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/apic.h>
#include <asm/processor.h>

#include <lego/kernel.h>
#include <lego/bitops.h>

#ifdef CONFIG_X86_X2APIC
int x2apic_mode;
int x2apic_phys;

enum {
	X2APIC_OFF,
	X2APIC_ON,
	X2APIC_DISABLED,
};
static int x2apic_state;

void __init check_x2apic(void)
{
	u64 msr;
	rdmsrl(MSR_IA32_APICBASE, msr);
	printk("%#llx\n", msr);

	if (x2apic_enabled()) {
		pr_info("x2apic: enabled by BIOS, switching to x2apic ops\n");
		x2apic_mode = 1;
		x2apic_state = X2APIC_ON;
	} else if (!x2apic_supported()) {
		pr_info("x2apic: not supported by CPU\n");
		x2apic_state = X2APIC_DISABLED;
	}
}
#endif

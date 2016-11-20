/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/ipi.h>
#include <asm/apic.h>
#include <asm/setup.h>
#include <asm/bootparam.h>
#include <asm/trampoline.h>

#include <lego/kernel.h>
#include <lego/early_ioremap.h>

unsigned int trampoline_base;
unsigned int trampoline_size;

void __init copy_trampoline(void)
{
	trampoline_base = boot_params.trampoline_base;
	trampoline_size = (unsigned int)((void *)&trampoline_end - (void *)&trampoline_start);

	printk("Trampoline: [%p - %p] -> [%#x - %#x]\n",
		&trampoline_start, &trampoline_end,
		trampoline_base, trampoline_base + trampoline_size);
}

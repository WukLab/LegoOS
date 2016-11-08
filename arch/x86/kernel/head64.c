/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/pgtable.h>

#include <disos/linkage.h>
#include <disos/compiler.h>
#include <disos/start_kernel.h>

pmdval_t early_pmd_flags = __PAGE_KERNEL_LARGE & ~(_PAGE_GLOBAL | _PAGE_NX);

asmlinkage __visible void __init x86_64_start_kernel(char *real_mode_data)
{
	start_kernel();
}

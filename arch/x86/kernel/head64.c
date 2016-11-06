/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */

#include <asm/pgtable.h>

#include <disos/linkage.h>
#include <disos/compiler.h>

pmdval_t early_pmd_flags = __PAGE_KERNEL_LARGE & ~(_PAGE_GLOBAL | _PAGE_NX);

asmlinkage __visible void __init x86_64_start_kernel(char *real_mode_data)
{

}

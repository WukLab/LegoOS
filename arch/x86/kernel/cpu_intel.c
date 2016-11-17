/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/processor.h>

static const struct cpu_vendor intel_cpu_vendor = {
	.c_vendor	= "Intel",
	.c_ident	= { "GenuineIntel" },
	.c_x86_vendor	= X86_VENDOR_INTEL,
};

cpu_vendor_register(intel_cpu_vendor);

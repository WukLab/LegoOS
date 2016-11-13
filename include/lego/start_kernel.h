/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_START_KERNEL_H_
#define _LEGO_START_KERNEL_H_

#include <lego/linkage.h>
#include <lego/compiler.h>

/*
 * Define the prototype for start_kernel here,
 * rather than cluttering up something else.
 */
asmlinkage void __init start_kernel(void);

/* And the architecture-specific initialization hook */
void __init setup_arch(void);

#endif /* _LEGO_START_KERNEL_H_ */

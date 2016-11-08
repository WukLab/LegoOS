/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _DISOS_START_KERNEL_H_
#define _DISOS_START_KERNEL_H_

#include <disos/linkage.h>
#include <disos/compiler.h>

/* Define the prototype for start_kernel here, rather than cluttering
   up something else. */

asmlinkage void __init start_kernel(void);

#endif /* _DISOS_START_KERNEL_H_ */

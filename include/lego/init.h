/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_INIT_H_
#define _LEGO_INIT_H_

#include <lego/linkage.h>
#include <lego/compiler.h>

extern char __initdata boot_command_line[];

asmlinkage void __init start_kernel(void);

#endif /* _LEGO_INIT_H_ */

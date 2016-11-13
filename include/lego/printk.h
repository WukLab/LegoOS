/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PRINTK_H_
#define _LEGO_PRINTK_H_

#include <stdarg.h>
#include <lego/linkage.h>
#include <lego/compiler.h>

asmlinkage __printf(1, 2)
int printk(const char *fmt, ...);

#endif /* _LEGO_PRINTK_H_ */

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PANIC_H_
#define _LEGO_PANIC_H_

#include <lego/compiler.h>

__printf(1, 2) void panic(const char *fmt, ...) __cold;

#endif /* _LEGO_PANIC_H_ */

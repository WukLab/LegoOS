/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <lego/printk.h>
#include <lego/linkage.h>

#define KMBUF_LEN 1024
static unsigned char KMBUF[KMBUF_LEN];

asmlinkage __printf(1, 2)
int printk(const char *fmt, ...)
{
	va_list args;
	int len;

	va_start(args, fmt);
	len = vsnprintf(KMBUF, KMBUF_LEN, fmt, args);
	va_end(args);

	return len;
}

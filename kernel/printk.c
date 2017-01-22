/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/tty.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/printk.h>
#include <lego/linkage.h>

#define KMBUF_LEN 1024
static unsigned char KMBUF[KMBUF_LEN];

static size_t print_time(unsigned char *buf, u64 ts)
{
	unsigned long rem_nsec;

	rem_nsec = do_div(ts, 1000000000);

	return sprintf(buf, "[%5lu.%06lu] ",
		(unsigned long)ts, rem_nsec / 1000);
}

/**
 * printk - print a kernel message
 * @fmt: format string
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
asmlinkage __printf(1, 2)
int printk(const char *fmt, ...)
{
	va_list args;
	size_t len;
	unsigned char *buf = KMBUF;

	len = print_time(buf, sched_clock());
	buf += len;

	va_start(args, fmt);
	len += vsnprintf(buf, KMBUF_LEN - len, fmt, args);
	va_end(args);

	return tty_write(KMBUF, len);
}

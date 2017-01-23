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

static inline int printk_get_level(const char *buffer)
{
	if (buffer[0] == KERN_SOH_ASCII && buffer[1]) {
		switch (buffer[1]) {
		case '0' ... '7':
		case 'd':	/* KERN_DEFAULT */
		case 'c':	/* KERN_CONT */
			return buffer[1];
		}
	}
	return 0;
}

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
	size_t time_len, fmt_len, len;
	unsigned char *buf = KMBUF;
	unsigned char *output_buf;

	time_len = print_time(buf, sched_clock());
	buf += time_len;

	va_start(args, fmt);
	fmt_len = vsnprintf(buf, KMBUF_LEN - time_len, fmt, args);
	va_end(args);

	switch (printk_get_level(buf)) {
	case '0' ... '7':
	case 'd':
		output_buf = KMBUF;
		len = time_len + fmt_len - 2;
		memmove(buf, buf + 2, fmt_len - 2);
		break;
	case 'c':
		output_buf = buf;
		len = fmt_len - 2;
		memmove(buf, buf + 2, fmt_len - 2);
		break;
	default:
		output_buf = KMBUF;
		len = time_len + fmt_len;
	};

	return tty_write(output_buf, len);
}

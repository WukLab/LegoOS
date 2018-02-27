/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <lego/spinlock.h>
#include <lego/ratelimit.h>

#define LOG_LINE_MAX	2048

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

static DEFINE_SPINLOCK(printk_lock);

static char TEXTBUF[LOG_LINE_MAX];

/**
 * printk - print a kernel message
 * @fmt: format string
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
asmlinkage __printf(1, 2)
int printk(const char *fmt, ...)
{
	unsigned char *text = TEXTBUF;
	unsigned char *output_buf;
	size_t time_len, fmt_len, len, ret_len;
	va_list args;
	unsigned long flags;

	spin_lock_irqsave(&printk_lock, flags);
	memset(text, 0, LOG_LINE_MAX);

	time_len = print_time(text, sched_clock());
	text += time_len;

	va_start(args, fmt);
	fmt_len = vsnprintf(text, LOG_LINE_MAX - time_len, fmt, args);
	va_end(args);

	switch (printk_get_level(text)) {
	case '0' ... '7':
	case 'd':
		output_buf = TEXTBUF;
		len = time_len + fmt_len - 2;
		memmove(text, text + 2, fmt_len - 2);
		break;
	case 'c':
		/* Contiguous printk(). Do not print prefix */
		output_buf = text;
		len = fmt_len - 2;
		memmove(text, text+ 2, fmt_len - 2);
		break;
	default:
		output_buf = TEXTBUF;
		len = time_len + fmt_len;
	};

	ret_len = tty_write(output_buf, len);
	spin_unlock_irqrestore(&printk_lock, flags);

	return ret_len;
}

int vprintk(const char *fmt, va_list args)
{
	unsigned char *text = TEXTBUF;
	unsigned char *output_buf;
	size_t time_len, fmt_len, len, ret_len;
	unsigned long flags;

	spin_lock_irqsave(&printk_lock, flags);

	time_len = print_time(text, sched_clock());
	text += time_len;

	fmt_len = vsnprintf(text, LOG_LINE_MAX - time_len, fmt, args);

	switch (printk_get_level(text)) {
	case '0' ... '7':
	case 'd':
		output_buf = TEXTBUF;
		len = time_len + fmt_len - 2;
		memmove(text, text + 2, fmt_len - 2);
		break;
	case 'c':
		/* Contiguous printk(). Do not print prefix */
		output_buf = text;
		len = fmt_len - 2;
		memmove(text, text+ 2, fmt_len - 2);
		break;
	default:
		output_buf = TEXTBUF;
		len = time_len + fmt_len;
	};

	ret_len = tty_write(output_buf, len);
	spin_unlock_irqrestore(&printk_lock, flags);

	return ret_len;
}

/*
 * printk rate limiting, lifted from the networking subsystem.
 *
 * This enforces a rate limit: not more than 10 kernel messages
 * every 5s to make a denial-of-service attack impossible.
 */
DEFINE_RATELIMIT_STATE(printk_ratelimit_state, 5 * HZ, 10);

int __printk_ratelimit(const char *func)
{
	return ___ratelimit(&printk_ratelimit_state, func);
}

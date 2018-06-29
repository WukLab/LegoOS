/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

#define KERN_SOH	"\001"		/* ASCII Start Of Header */
#define KERN_SOH_ASCII	'\001'

#define KERN_EMERG	KERN_SOH "0"	/* System is unusable */
#define KERN_ALERT	KERN_SOH "1"	/* Action must be taken immediately */
#define KERN_CRIT	KERN_SOH "2"	/* Critical conditions */
#define KERN_ERR	KERN_SOH "3"	/* Error conditions */
#define KERN_WARNING	KERN_SOH "4"	/* Warning conditions */
#define KERN_NOTICE	KERN_SOH "5"	/* Normal but significant condition */
#define KERN_INFO	KERN_SOH "6"	/* Informational */
#define KERN_DEBUG	KERN_SOH "7"	/* Debug-level messages */
#define KERN_DEFAULT	KERN_SOH "d"	/* The default kernel loglevel */

/*
 * Annotation for a "continued" line of log printout (only done after a
 * line that had no enclosing \n). Only to be used by core/arch code
 * during early bootup (a continued line is not SMP-safe otherwise).
 */
#define KERN_CONT	KERN_SOH "c"

/* Integer equivalents of KERN_<LEVEL> */
#define LOGLEVEL_SCHED		-2	/* Deferred messages from sched code
					 * are set to this special level */
#define LOGLEVEL_DEFAULT	-1	/* Default (or last) loglevel */
#define LOGLEVEL_EMERG		0	/* System is unusable */
#define LOGLEVEL_ALERT		1	/* Action must be taken immediately */
#define LOGLEVEL_CRIT		2	/* Critical conditions */
#define LOGLEVEL_ERR		3	/* Error conditions */
#define LOGLEVEL_WARNING	4	/* Warning conditions */
#define LOGLEVEL_NOTICE		5	/* Normal but significant condition */
#define LOGLEVEL_INFO		6	/* Informational */
#define LOGLEVEL_DEBUG		7	/* Debug-level messages */

asmlinkage __printf(1, 2)
int printk(const char *fmt, ...);

int vprintk(const char *fmt, va_list args);

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#define pr_emerg(fmt, ...)					\
	printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert(fmt, ...)					\
	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit(fmt, ...)					\
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...)					\
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...)					\
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...)					\
	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...)					\
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...)					\
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont(fmt,...)					\
	printk(KERN_CONT pr_fmt(fmt), ##__VA_ARGS__)

/*
 * printk_once pr_xxx_once: print message only once
 */

#define printk_once(fmt, ...)					\
({								\
	static bool __print_once __read_mostly;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		printk(fmt, ##__VA_ARGS__);			\
	}							\
})

#define pr_emerg_once(fmt, ...)					\
	printk_once(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_once(fmt, ...)					\
	printk_once(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_once(fmt, ...)					\
	printk_once(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_once(fmt, ...)					\
	printk_once(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_once(fmt, ...)					\
	printk_once(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_once(fmt, ...)				\
	printk_once(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_once(fmt, ...)					\
	printk_once(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug_once(fmt, ...)					\
	printk_once(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)

enum {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};

void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
		    int rowsize, int groupsize,
		    const void *buf, size_t len, bool ascii);
void print_hex_dump_bytes(const char *prefix_str, int prefix_type,
			  const void *buf, size_t len);

/*
 * ratelimited messages with local ratelimit_state,
 * no local ratelimit_state used in the !PRINTK case
 */
#define printk_ratelimited(fmt, ...)					\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		printk(fmt, ##__VA_ARGS__);				\
})

#define pr_emerg_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

struct va_format {
	const char *fmt;
	va_list *va;
};

struct device;

extern __printf(3, 4)
int dev_printk(const char *level, const struct device *dev,
	       const char *fmt, ...);
extern __printf(2, 3)
int dev_emerg(const struct device *dev, const char *fmt, ...);
extern __printf(2, 3)
int dev_alert(const struct device *dev, const char *fmt, ...);
extern __printf(2, 3)
int dev_crit(const struct device *dev, const char *fmt, ...);
extern __printf(2, 3)
int dev_err(const struct device *dev, const char *fmt, ...);
extern __printf(2, 3)
int dev_warn(const struct device *dev, const char *fmt, ...);
extern __printf(2, 3)
int dev_notice(const struct device *dev, const char *fmt, ...);
extern __printf(2, 3)
int _dev_info(const struct device *dev, const char *fmt, ...);

/*
 * Stupid hackaround for existing uses of non-printk uses dev_info
 *
 * Note that the definition of dev_info below is actually _dev_info
 * and a macro is used to avoid redefining dev_info
 */

#define dev_info(dev, fmt, arg...) _dev_info(dev, fmt, ##arg)

#endif /* _LEGO_PRINTK_H_ */

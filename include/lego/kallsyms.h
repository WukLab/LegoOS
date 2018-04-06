/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_KALLSYMS_H_
#define _LEGO_KALLSYMS_H_

#include <lego/types.h>

#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s]") + (KSYM_NAME_LEN - 1) + \
			 2*(BITS_PER_LONG*3/10) + 1)

unsigned long get_symbol_start_addr(unsigned long addr);
int sprint_symbol(char *buffer, unsigned long address);
int sprint_symbol_no_offset(char *buffer, unsigned long address);
int sprint_backtrace(char *buffer, unsigned long address);

/* This macro allows us to keep printk typechecking */
static __printf(1, 2)
void __check_printsym_format(const char *fmt, ...)
{
}

/* Look up a kernel symbol and print it to the kernel messages. */
void __print_symbol(const char *fmt, unsigned long address);

static inline void print_symbol(const char *fmt, unsigned long addr)
{
	__check_printsym_format(fmt, "");
	__print_symbol(fmt, (unsigned long)
		       __builtin_extract_return_addr((void *)addr));
}

static inline void print_ip_sym(unsigned long ip)
{
	printk("[<%p>] %pS\n", (void *) ip, (void *) ip);
}

#endif /* _LEGO_KALLSYMS_H_ */

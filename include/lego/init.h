/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
extern char command_line[];

asmlinkage void __init start_kernel(void);

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
};

#define __initconst	__section(.init.rodata)

/*
 * Force the alignment so the compiler doesn't space elements of the
 * obs_kernel_param "array" too far apart in .init.setup.
 */
#define __setup_param(str, unique_id, fn)				\
	static const char __setup_str_##unique_id[] __initconst		\
		__aligned(1) = str; 					\
	static struct obs_kernel_param __setup_##unique_id		\
		__used __section(.init.setup)				\
		__attribute__((aligned((sizeof(long)))))		\
		= { __setup_str_##unique_id, fn }

#define __setup(str, fn)						\
	__setup_param(str, fn, fn)

bool parameq(const char *a, const char *b);
char *parse_args(char *args, int (*handle)(char *param, char *val));

#endif /* _LEGO_INIT_H_ */

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/random.h>
#include <lego/kernel.h>
#include <lego/sched.h>

static inline char __get_random_byte(void)
{
	return (char)sched_clock();
}

void get_random_bytes(void *buf, int nbytes)
{
	int i;
	char *s = buf;

	if (WARN_ON(!nbytes))
		return;

	for (i = 0; i < nbytes; i++)
		s[i] = __get_random_byte();
}

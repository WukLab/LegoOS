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

void get_random_bytes(void *buf, int nbytes)
{
	int i;
	char *s = buf;

	WARN(1, "Fake Random Number. Implement Me");

	for (i = 0; i < nbytes; i++) {
		s[i] = 0x66;
	}
}

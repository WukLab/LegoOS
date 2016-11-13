/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/tty.h>

static struct tty_ldisc_operations n_tty_ops = {
};

struct tty_ldisc n_tty = {
	.name	= "n_tty",
	.ops	= &n_tty_ops,
	.tty	= &default_tty_struct,
};

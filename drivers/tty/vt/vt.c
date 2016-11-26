/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * VT102 Emulation
 */

#include <lego/bug.h>
#include <lego/tty.h>
#include <lego/ctype.h>
#include <lego/kernel.h>
#include <lego/termios.h>
#include <lego/console.h>
#include <lego/screen_info.h>

/* The console currently used by kernel */
struct console_struct *console;

static int con_putchar(struct tty_struct *tty, unsigned char ch)
{
	return 0;
}

static int con_write(struct tty_struct *tty, const unsigned char *buf, int count)
{
	struct console_struct *cs = tty->driver_data;

	return 0;
}

const struct tty_operations vt_tty_ops = {
	.write		= con_write,
	.put_char	= con_putchar,
};

struct tty_driver vt_tty_driver = {
	.ops		= &vt_tty_ops,
};

struct n_tty_data vt_ldisc_data;

void __init vt_init(void)
{
	vt_tty_struct.termios = tty_std_termios;
	console = &vga_console;
}

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/tty.h>
#include <lego/errno.h>
#include <lego/kernel.h>
#include <lego/termios.h>
#include <lego/console.h>
#include <lego/files.h>

struct termios tty_std_termios = {
	.c_iflag = ICRNL | IXON,
	.c_oflag = OPOST | ONLCR,
	.c_cflag = B38400 | CS8 | CREAD | HUPCL,
	.c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK |
		   ECHOCTL | ECHOKE | IEXTEN,
	.c_cc = INIT_C_CC,
	.c_ispeed = 38400,
	.c_ospeed = 38400,
	/* .c_line = N_TTY, */
};

/**
 * tty_write_room		-	write queue space
 * @tty: terminal
 *
 * Return the number of bytes that can be queued to this device
 * at the present time. The result should be treated as a guarantee
 * and the driver cannot offer a value it later shrinks by more than
 * the number of bytes written. If no method is provided 2K is always
 * returned and data may be lost as there will be no flow control.
 */
int tty_write_room(struct tty_struct *tty)
{
	if (tty->ops->write_room)
		return tty->ops->write_room(tty);
	return 2048;
}

/**
 * tty_put_char	-	write one character to a tty
 * @tty: tty
 * @ch: character
 *
 * Write one byte to the tty using the provided put_char method
 * if present. Return the number of characters successfully output
 *
 * Note: the specific put_char operation in the driver layer may go
 * away soon. Don't call it directly, use this method
 */
int tty_put_char(struct tty_struct *tty, unsigned char ch)
{
	if (tty->ops->put_char)
		return tty->ops->put_char(tty, ch);
	return tty->ops->write(tty, &ch, 1);
}

static inline ssize_t __tty_write(struct tty_struct *tty,
				  const char *buf, size_t count)
{
	struct tty_ldisc *ldisc;
	ssize_t ret;

	ldisc = tty->ldisc;
	if (!ldisc || !ldisc->ops->write)
		return -EIO;

	ret = ldisc->ops->write(tty, buf, count);
	return ret;
}

#define TTY_MAP_SERIAL	0
#define TTY_MAP_VT	1
#define NR_TTY_MAP	2

struct tty_struct *tty_map[NR_TTY_MAP] = {
	[TTY_MAP_SERIAL]	= &serial_tty_struct,
	[TTY_MAP_VT]		= &vt_tty_struct,
};

/**
 * tty_write	-	Write method for tty device
 * @buf: user data to write
 * @count: bytes to write
 *
 * Write data to a tty device via the line discipline
 */
ssize_t tty_write(const char *buf, size_t count)
{
	struct tty_struct *tty;
	ssize_t ret;

#if !defined(CONFIG_TTY_SERIAL) && !defined(CONFIG_TTY_VT)
	compiletime_assert(0, "Enable at least one of them");
#endif

#ifdef CONFIG_TTY_SERIAL
	tty = tty_map[TTY_MAP_SERIAL];
	if (!tty || !tty->ops->write)
		return -EIO;
	ret = __tty_write(tty, buf, count);
#endif

#ifdef CONFIG_TTY_VT
	tty = tty_map[TTY_MAP_VT];
	if (!tty || !tty->ops->write)
		return -EIO;
	ret = __tty_write(tty, buf, count);
#endif

	return ret;
}

struct tty_struct serial_tty_struct = {
	.driver		= &serial_tty_driver,
	.ops		= &serial_tty_ops,
	.ldisc		= &n_tty,
	.ldisc_data	= &serial_ldisc_data,
};

struct tty_struct vt_tty_struct = {
	.driver		= &vt_tty_driver,
	/* VGA is the default console */
	.driver_data	= &vga_console,
	.ops		= &vt_tty_ops,
	.ldisc		= &n_tty,
	.ldisc_data	= &vt_ldisc_data,
};

/*
 * Prepare TTY layer
 * Afterwards, terminal and serial are ready to use
 */
void __init tty_init(void)
{
	vt_init();
	serial_init();
}

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/io.h>
#include <asm/asm.h>

#include <lego/tty.h>
#include <lego/mutex.h>

#ifdef CONFIG_TTY_SERIAL_BAUD9600
# define DEFAULT_BAUD	9600
#elif defined(CONFIG_TTY_SERIAL_BAUD115200)
# define DEFAULT_BAUD	115200
#endif

#ifdef CONFIG_TTY_SERIAL_TTYS0
# define DEFAULT_SERIAL_PORT	0x3f8
#elif defined(CONFIG_TTY_SERIAL_TTYS1)
# define DEFAULT_SERIAL_PORT	0x2f8
#endif

static unsigned long serial_base = DEFAULT_SERIAL_PORT;

#define DLAB		0x80
#define XMTRDY          0x20

#define TXR             0       /*  Transmit register (WRITE) */
#define RXR             0       /*  Receive register  (READ)  */
#define IER             1       /*  Interrupt Enable          */
#define IIR             2       /*  Interrupt ID              */
#define FCR             2       /*  FIFO control              */
#define LCR             3       /*  Line control              */
#define MCR             4       /*  Modem control             */
#define LSR             5       /*  Line Status               */
#define MSR             6       /*  Modem Status              */
#define DLL             0       /*  Divisor Latch Low         */
#define DLH             1       /*  Divisor latch High        */

static int serial_putchar(struct tty_struct *tty, unsigned char ch)
{
	unsigned int timeout = 0xffff;

	while ((inb(serial_base + LSR) & XMTRDY) == 0 && --timeout)
		cpu_relax();
	outb(ch, serial_base + TXR);
	return timeout ? 1 : 0;
}

static int serial_write(struct tty_struct *tty,
			const unsigned char *buf, int count)
{
	int c = 0;
        while (*buf && count-- > 0) {
		c += serial_putchar(tty, *buf);
		buf++;
	}
	return c;
}

const struct tty_operations serial_tty_ops = {
	.write	= serial_write,
	.put_char = serial_putchar,
};

struct tty_driver serial_tty_driver = {
	.ops	= &serial_tty_ops,
};

struct n_tty_data serial_ldisc_data;

static void __init serial_init_hw(int port, int baud)
{
	unsigned char c;
	unsigned divisor;

	outb(0x3, port + LCR);	/* 8n1 */
	outb(0, port + IER);	/* no interrupt */
	outb(0, port + FCR);	/* no fifo */
	outb(0x3, port + MCR);	/* DTR + RTS */

	divisor	= 115200 / baud;
	c = inb(port + LCR);
	outb(c | DLAB, port + LCR);
	outb(divisor & 0xff, port + DLL);
	outb((divisor >> 8) & 0xff, port + DLH);
	outb(c & ~DLAB, port + LCR);

	serial_base = port;
}

void __init serial_init(void)
{
	mutex_init(&serial_ldisc_data.output_lock);
	serial_init_hw(DEFAULT_SERIAL_PORT, DEFAULT_BAUD);

	serial_tty_struct.termios = tty_std_termios;

#ifdef CONFIG_TTY_SERIAL_BAUD9600
	serial_tty_struct.termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
#elif defined(CONFIG_TTY_SERIAL_BAUD115200)
	serial_tty_struct.termios.c_cflag = B115200 | CS8 | CREAD | HUPCL | CLOCAL;
#endif

	serial_tty_struct.termios.c_ispeed = DEFAULT_BAUD;
	serial_tty_struct.termios.c_ospeed = DEFAULT_BAUD;
}


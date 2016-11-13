/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TTY_H_
#define _LEGO_TTY_H_

#include <lego/types.h>
#include <lego/termios.h>

struct tty_struct;

/*
 * This structure defines the interface between
 * the low-level tty driver and the tty routines.
 *
 * int (*write)(struct tty_struct * tty,
 * 		 const unsigned char *buf, int count);
 *
 * 	This routine is called by the kernel to write a series of
 * 	characters to the tty device.  The characters may come from
 * 	user space or kernel space.  This routine will return the
 *	number of characters actually accepted for writing.
 *
 * int (*put_char)(struct tty_struct *tty, unsigned char ch);
 *
 * 	This routine is called by the kernel to write a single
 * 	character to the tty device.  If the kernel uses this routine,
 * 	it must call the flush_chars() routine (if defined) when it is
 * 	done stuffing characters into the driver.  If there is no room
 * 	in the queue, the character is ignored.
 *
 *	Optional: Kernel will use the write method if not provided.
 *
 *	Note: Do not call this function directly, call tty_put_char
 *
 */
struct tty_operations {
	int (*write)(struct tty_struct *tty, const unsigned char *buf, int count);
	int (*put_char)(struct tty_struct *tty, unsigned char ch);
};

/**
 * struct tty_driver
 * @name:		Nick name
 * @flags:		flags of tty driver
 * @type:		Type of this tty driver(See below)
 * @major:		Major number of this tty driver
 * @minor_start:	Starting minor number of this tty driver
 * @num:		Number of devices allocated
 * @init_termios:	Termios of this driver
 * @ops:		Hardware-operations of this tty driver
 *
 * The driver's job is to format data that is sent to it in a manner that the
 * hardware can understand, and receive data from the hardware.
 */
struct tty_driver {
	const char			*name;
	unsigned long			flags;
	unsigned int			type;
	unsigned int			major;
	unsigned int			minor_start;
	unsigned int			num;
	struct termios			init_termios;
	const struct tty_operations	*ops;
};

/*
 * This structure defines the interface between the tty line discipline
 * implementation and the tty routines.  The following routines can be
 * defined; unless noted otherwise, they are optional, and can be
 * filled in with a null pointer.
 *
 * ssize_t (*read)(struct tty_struct * tty,
 *		   unsigned char * buf, size_t nr);
 *
 *	This function is called when the user requests to read from
 *	the tty.  The line discipline will return whatever characters
 *	it has buffered up for the user.  If this function is not
 *	defined, the user will receive an EIO error.
 *
 * ssize_t (*write)(struct tty_struct * tty,
 *		    const unsigned char * buf, size_t nr);
 *
 *	This function is called when the user requests to write to the
 *	tty.  The line discipline will deliver the characters to the
 *	low-level tty device for transmission, optionally performing
 *	some processing on the characters first.  If this function is
 *	not defined, the user will receive an EIO error.
 *
 * void	(*receive_buf)(struct tty_struct *, const unsigned char *cp,
 *		       char *fp, int count);
 *
 *	This function is called by the low-level tty driver to send
 *	characters received by the hardware to the line discpline for
 *	processing.  <cp> is a pointer to the buffer of input
 *	character received by the device.  <fp> is a pointer to a
 *	pointer of flag bytes which indicate whether a character was
 *	received with a parity error, etc. <fp> may be NULL to indicate
 *	all data received is TTY_NORMAL.
 *
 * void	(*write_wakeup)(struct tty_struct *);
 *
 *	This function is called by the low-level tty driver to signal
 *	that line discpline should try to send more characters to the
 *	low-level driver for transmission.  If the line discpline does
 *	not have any more data to send, it can just return. If the line
 *	discipline does have some data to send, please arise a tasklet
 *	or workqueue to do the real data transfer. Do not send data in
 *	this hook, it may leads to a deadlock.
 *
 */
struct tty_ldisc_operations {
	/*
	 * The following routines are called from above.
	 */
	ssize_t (*read)(struct tty_struct *tty, unsigned char *buf, size_t count);
	ssize_t (*write)(struct tty_struct *tty, const unsigned char *buf, size_t count);

	/*
	 * The following routines are called from below.
	 */
	void (*receive_buf)(struct tty_struct *, const unsigned char *cp, char *fp, int count);
	void (*write_wakeup)(struct tty_struct *);
};

struct tty_ldisc {
	const char *name;
	struct tty_ldisc_operations	*ops;
	struct tty_struct		*tty;
};

struct tty_struct {
	struct tty_driver		*driver;
	const struct tty_operations	*ops;
	void				*driver_data;
	struct tty_ldisc		*ldisc;
	void				*ldisc_data;
};

/*
 * The default tty struct
 * The default line discipline
 */
extern struct tty_struct default_tty_struct;
extern struct tty_ldisc n_tty;

/* drivers/tty/serial and drivers/tty/vt */
extern struct tty_driver vt_driver;
extern struct tty_driver serial_driver;

void tty_init(void);
void serial_init(void);

#endif /* _LEGO_TTY_H_ */

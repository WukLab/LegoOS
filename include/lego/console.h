/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CONSOLE_H_
#define _LEGO_CONSOLE_H_

/* VT Parameters */
#define NPAR 16

/* scroll */
#define SM_UP       (1)
#define SM_DOWN     (2)

/* cursor */
#define CM_DRAW     (1)
#define CM_ERASE    (2)
#define CM_MOVE     (3)

#define CUR_DEF		0
#define CUR_NONE	1
#define CUR_UNDERLINE	2
#define CUR_LOWER_THIRD	3
#define CUR_LOWER_HALF	4
#define CUR_TWO_THIRDS	5
#define CUR_BLOCK	6

#define CUR_DEFAULT CUR_UNDERLINE

/*
 * Hardware console driver: the one beneath virtual terminal (VT).
 *
 * The hardware console is just adding another indirect layer to
 * enable VGA, MDA and others to be able to work with virtual terminal
 * at the same time.
 *
 * TTY can have multiple drivers, e.g. serial or VT.
 * Both serial and VT have their own another indirect layer.
 * This is the real-world where hardware are made from different vendors.
 */

struct console_struct;

struct console_driver {
	void (*con_startup)(void);
	void (*con_init)(struct console_struct *);
	void (*con_putc)(struct console_struct *, unsigned char, int, int);
	void (*con_puts)(struct console_struct *, unsigned char *, int, int, int);
	void (*con_set_origin)(struct console_struct *);
	int  (*con_scroll)(struct console_struct *, int, int, int, int);
	void (*con_cursor)(struct console_struct *, int);
};

/*
 * struct console_struct
 * Describes a console's attributes and operations
 */
struct console_struct {
	const char *name;
	unsigned int cols;
	unsigned int rows;
	unsigned int row_size;			/* Bytes per row */
	unsigned int scan_lines;		/* # of scan lines */
	unsigned long origin;			/* Start of real screen */
	unsigned long scr_end;			/* End of real screen */
	unsigned long visible_origin;		/* Top of visible window */
	unsigned int top, bottom;		/* Scrolling region */
	unsigned int screenbuf_size;
	unsigned int can_do_color;

	/* Attributes */
	unsigned char attr;			/* Current attributes */
	unsigned char def_color;		/* Default color */
	unsigned long color;			/* Foreground & background color */
	unsigned long saved_color;		/* Saved foreground & background color */
	unsigned char ulcolor;			/* Color for underline mode */
	unsigned char itcolor;			/* Color for italic */
	unsigned int blink;			/* Blink character */
	unsigned int f_color;			/* Foreground color */
	unsigned int b_color;			/* Background color */
	unsigned int italic;			/* Italic characters */
	unsigned int bold;			/* Bold characters */
	unsigned int underline;			/* Underline characters */

	/* Cursor */
	unsigned int cursor_type;
	unsigned int x, y;			/* Cursor position */
	unsigned int saved_x, saved_y;		/* Saved cursor position */
	unsigned long pos;			/* Cursor address */
	unsigned short erase_char;		/* Background erase character */

	/* VT terminal data */
	unsigned int state;			/* Escape seq parser state */
	unsigned int npar, par[NPAR];	/* Parameters of current escape sequence */
	const struct console_driver *driver;

	/* Font */
	unsigned int font_width;
	unsigned int font_height;
};

extern struct console_struct *console;
extern struct console_struct vga_console;
extern struct console_struct dummy_console;

#endif /* _LEGO_CONSOLE_H_ */

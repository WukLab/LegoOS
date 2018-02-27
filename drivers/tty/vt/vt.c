/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * VT102 Emulation
 *
 * http://man7.org/linux/man-pages/man4/console_codes.4.html
 */

#include <lego/bug.h>
#include <lego/tty.h>
#include <lego/ctype.h>
#include <lego/mutex.h>
#include <lego/kernel.h>
#include <lego/termios.h>
#include <lego/console.h>
#include <lego/screen_info.h>

/* Answers to a ESC-Z or CSI0c query. */
#define VT100ID "\033[?1;2c"
#define VT102ID "\033[?6c"

const unsigned char color_table[] = { 0, 4, 2, 6, 1, 5, 3, 7,
				       8,12,10,14, 9,13,11,15 };

static int default_color           = 7; /* white */
static int default_italic_color    = 2; /* green (ASCII) */
static int default_underline_color = 3; /* cyan (ASCII) */

/* The console currently used by kernel */
struct console_struct *console;

static inline void hide_cursor(struct console_struct *c)
{
	c->driver->con_cursor(c, CM_ERASE);
}

static inline void set_cursor(struct console_struct *c)
{
	c->driver->con_cursor(c, CM_DRAW);
}

static inline void save_cursor(struct console_struct *cs)
{
	cs->saved_x = cs->x;
	cs->saved_y = cs->y;
}

static inline void restore_cursor(struct console_struct *cs)
{
	cs->x = cs->saved_x;
	cs->y = cs->saved_y;
}

static inline void cr(struct console_struct *cs)
{
	cs->pos -= (cs->x << 1);
	cs->x = 0;
}

static void scrup(struct console_struct *cs,
		  unsigned int top, unsigned int bottom, int nr)
{
	if (top + nr >= bottom)
		nr = bottom - top - 1;

	if (bottom > cs->rows || top >= bottom || nr < 1)
		return;

	cs->driver->con_scroll(cs, top, bottom, SM_UP, nr);
}

static void lf(struct console_struct *cs)
{
	if (cs->y + 1 == cs->bottom)
		scrup(cs, cs->top, cs->bottom, 1);
	else if (cs->y < cs->rows - 1) {
		cs->y++;
		cs->pos += cs->row_size;
	}
}

static void reverse_line_feed(struct console_struct *cs)
{

}

static void gotoxy(struct console_struct *cs, int new_x, int new_y)
{
	if (new_x >= cs->cols || new_y >= cs->rows)
		return;
	cs->x = new_x;
	cs->y = new_y;
	cs->pos = cs->visible_origin +
		(((cs->cols * cs->y) + cs->x) << 1);
}

__unused static void respond(struct tty_struct *tty)
{

}

static void respond_ID(struct tty_struct *tty)
{

}

static void delete_char(struct console_struct *cs, unsigned int nr)
{
	unsigned short *p = (unsigned short *)cs->pos;

	scr_memcpyw(p, p + nr, cs->cols - cs->x - nr);
	scr_memsetw(p + cs->cols - cs->x - nr, cs->erase_char, nr);
}

static void insert_char(struct console_struct *cs, unsigned int nr)
{
	unsigned short *p = (unsigned short *)cs->pos;

	scr_memmovew(p + nr, p, cs->cols - cs->x - nr);
	scr_memsetw(p, cs->erase_char, nr);
}

/* Erase Display */
static void csi_J(struct console_struct *cs)
{
	unsigned int count;
	unsigned short *start;

	switch (cs->par[0]) {
	case 0:	/* Erase from cursor to end of display */
		count = (cs->scr_end - cs->pos) >> 1;
		start = (unsigned short *)cs->pos;
		break;
	case 1:	/* Erase from start to cursor */
		count = ((cs->pos - cs->visible_origin) >> 1) + 1;
		start = (unsigned short *)cs->visible_origin;
		break;
	case 2:	/* Erase whole display */
		count = cs->cols * cs->rows;
		start = (unsigned short *)cs->visible_origin;
		break;
	case 3:	/* Erase scroll-back buffer */
		count = ((cs->pos - cs->origin) >> 1) + 1;
		start = (unsigned short *)cs->origin;
		break;
	default:
		return;
	};

	scr_memsetw(start, cs->erase_char, count);
}

/* Erase Line */
static void csi_K(struct console_struct *cs)
{
	unsigned int count;
	unsigned short *start;

	switch (cs->par[0]) {
	case 0:	/* Erase from cursor to end of line */
		count = cs->cols - cs->x;
		start = (unsigned short *)cs->pos;
		break;
	case 1:	/* Erase from start of line to cursor */
		count = cs->x + 1;
		start = (unsigned short *)(cs->pos - (cs->x << 1));
	case 2:	/* Erase whole line */
		count = cs->cols;
		start = (unsigned short *)(cs->pos - (cs->x << 1));
	default:
		return;
	};

	scr_memsetw(start, cs->erase_char, count);
}

/* Insert Lines */
static void csi_L(struct console_struct *cs)
{
	unsigned int lines = cs->par[0];

	if (lines > (cs->rows - cs->y))
		lines = cs->rows - cs->y;
	else if (!lines)
		lines = 1;
}

/* Delete Lines */
static void csi_M(struct console_struct *cs)
{
	unsigned int lines = cs->par[0];

	if (lines > (cs->rows - cs->y))
		lines = cs->rows - cs->y;
	else if (!lines)
		lines = 1;
}

/* Delete chars in current line */
static void csi_P(struct console_struct *cs)
{
	unsigned int nr = cs->par[0];

	if (nr > (cs->cols - cs->x))
		nr = cs->cols - cs->x;
	else if (!nr)
		nr = 1;
	delete_char(cs, nr);
}

/* Erase chars in current line */
static void csi_X(struct console_struct *cs)
{
	unsigned int nr = cs->par[0];

	if (!nr)
		nr++;
	nr = (nr > cs->cols - cs->x) ? (cs->cols - cs->x) : nr;
	scr_memsetw((unsigned short *)cs->pos, cs->erase_char, nr);
}

static u8 build_attr(struct console_struct *c,
		    u8 _color, u8 _bold, u8 _blink, u8 _underline, u8 _italic)
{
/*
 * ++roman: I completely changed the attribute format for monochrome
 * mode (!can_do_color). The formerly used MDA (monochrome display
 * adapter) format didn't allow the combination of certain effects.
 * Now the attribute is just a bit vector:
 *  Bit 0..1: intensity (0..2)
 *  Bit 2   : underline
 *  Bit 3   : reverse
 *  Bit 7   : blink
 */
	u8 a = _color;
	if (!c->can_do_color)
		return _bold |
		       (_italic ? 2 : 0) |
		       (_underline ? 4 : 0) |
		       (_blink ? 0x80 : 0);
	if (_italic)
		a = (a & 0xF0) | c->itcolor;
	else if (_underline)
		a = (a & 0xf0) | c->ulcolor;
	else if (_bold == 0)
		a = (a & 0xf0) | c->ulcolor;
	if (_blink)
		a ^= 0x80;
	if (_bold == 2)
		a ^= 0x08;
	return a;
}

static void update_attribute(struct console_struct *c)
{
	c->attr = build_attr(c, c->color, c->bold, c->blink, c->underline, c->italic);
	c->erase_char = (build_attr(c, c->color, 1, c->blink, 0, 0) << 8) | ' ';
}

/* Set attribute */
static void csi_m(struct console_struct *cs)
{
	int i;

	for (i = 0; i <= cs->npar; i++) {
		switch (cs->par[i]) {
		case 0:	/* Default */
			cs->bold = 1;
			cs->underline = 0;
			cs->blink = 0;
			cs->italic = 0;
			cs->color = cs->def_color;
			break;
		case 1:
			cs->bold = 2;
			break;
		case 2:
			cs->bold = 0;
			break;
		case 3:
			cs->italic = 1;
			break;
		case 4:
			cs->underline = 1;
			break;
		case 5:
			cs->blink = 1;
			break;
		case 21:
		case 22:
			cs->bold = 1;
			break;
		case 23:
			cs->italic = 0;
			break;
		case 24:
			cs->underline = 0;
			break;
		case 25:
			cs->blink = 0;
			break;
		case 38:
		case 39:
			cs->color = (cs->def_color & 0x0f) |
				(cs->color & 0xf0);
			break;
		case 48:
		case 49:
			cs->color = (cs->def_color & 0xf0) |
				(cs->color & 0x0f);
			break;
		default:
			if (cs->par[i] >= 30 && cs->par[i] <= 37)
				cs->color = color_table[cs->par[i] - 30]
					| (cs->color & 0xf0);
			else if (cs->par[i] >= 40 && cs->par[i] <= 47)
				cs->color = (color_table[cs->par[i] - 40] << 4)
					| (cs->color & 0x0f);
			break;
		}
	}
	update_attribute(cs);
}

/* Insert blank chars in current line */
static void csi_at(struct console_struct *cs)
{
	unsigned int nr = cs->par[0];

	if (nr > cs->cols - cs->x)
		nr = cs->cols - cs->x;
	else if (!nr)
		nr = 1;
	insert_char(cs, nr);
}

enum {
	VT_NORMAL,
	VT_ESC,
	VT_CSI_QUESTION,
	VT_CSI_PARAMETER,
	VT_CSI_HANDLE
};

static int con_write(struct tty_struct *tty, const unsigned char *buf, int count)
{
#define BS	8		/* Back Space */
#define HT	9		/* Horizontal Table */
#define NL	10		/* New Line */
#define VT	11		/* Vertical Tab */
#define NP	12		/* New Page */
#define CR	13		/* Carriage Return */
#define ESC	27		/* Escape */
#define DEL	127		/* Delete */
	struct console_struct *cs = tty->driver_data;
	int npar, c, ret, state;

	hide_cursor(cs);

	ret = 0;
	npar = 0;
	state = VT_NORMAL;
	while (count) {
		c = *buf;
		count--;
		buf++;
		ret++;

		switch (state) {
		case (VT_NORMAL):
			if (c > 31 && c < 127) {
				if (cs->x == cs->cols) {
					cs->x = 0;
					cs->pos -= cs->row_size;
					lf(cs);
				}
				cs->driver->con_putc(cs, c, cs->x, cs->y);
				cs->x++;
				cs->pos += 2;
			} else if (c == BS) {
				if (cs->x) {
					cs->x--;
					cs->pos -= 2;
				}
			} else if (c == HT) {
				/* Table Width = 8 */
				c = 8 - (cs->x & 7);
				cs->x += c;
				cs->pos += c << 1;
				if (cs->x >= cs->cols) {
					cs->x -= cs->cols;
					cs->pos -= cs->row_size;
					lf(cs);
				}
			} else if (c == NL || c == VT || c == NP) {
				lf(cs);
			} else if (c == CR) {
				cr(cs);
			} else if (c == ESC) {
				state = VT_ESC;
			}
			break;
		/* ESC- but not CSI- */
		case (VT_ESC):
			state = VT_NORMAL;
			if (c == '[') {
				state = VT_CSI_QUESTION;
			} else if (c == 'D') {
				lf(cs);
			} else if (c == 'E') {
				gotoxy(cs, 0, cs->y++);
			} else if (c == 'M') {
				reverse_line_feed(cs);
			} else if (c == 'Z') {
				respond_ID(tty);
			} else if (c == '7') {
				save_cursor(cs);
			} else if (c == '8') {
				restore_cursor(cs);
			}
			break;
		case (VT_CSI_QUESTION):
			for (npar = 0; npar < NPAR; npar++)
				cs->par[npar] = 0;
			npar = 0;
			state = VT_CSI_PARAMETER;
			if (c == '?') {
				/* \033[? */
				break;
			}
		case (VT_CSI_PARAMETER):
			if (c == ';' && npar < (NPAR - 1)) {
				npar++;
				break;
			} else if (c >= '0' && c <= '9') {
				cs->par[npar] = 10 * cs->par[npar]
				    + (c - '0');
				break;
			} else {
				state = VT_CSI_HANDLE;
				cs->npar = npar;
			}
		case (VT_CSI_HANDLE):
			state = VT_NORMAL;
			switch (c) {
			case 'G':
			case '`':
				if (cs->par[0])
					cs->par[0]--;
				gotoxy(cs, cs->par[0], cs->y);
				break;
			case 'A':
				if (!cs->par[0])
					cs->par[0]++;
				gotoxy(cs, cs->x, cs->y - cs->par[0]);
				break;
			case 'B':
			case 'e':
				if (!cs->par[0])
					cs->par[0]++;
				gotoxy(cs, cs->x, cs->y + cs->par[0]);
				break;
			case 'C':
			case 'a':
				if (!cs->par[0])
					cs->par[0]++;
				gotoxy(cs, cs->x + cs->par[0], cs->y);
				break;
			case 'D':
				if (!cs->par[0])
					cs->par[0]++;
				gotoxy(cs, cs->x + cs->par[0], cs->y);
				break;
			case 'E':
				if (!cs->par[0])
					cs->par[0]++;
				gotoxy(cs, 0, cs->y + cs->par[0]);
				break;
			case 'F':
				if (!cs->par[0])
					cs->par[0]++;
				gotoxy(cs, 0, cs->y - cs->par[0]);
				break;
			case 'd':
				if (cs->par[0])
					cs->par[0]--;
				gotoxy(cs, cs->x, cs->par[0]);
				break;
			case 'H':
			case 'f':
				if (cs->par[0])
					cs->par[0]--;
				if (cs->par[1])
					cs->par[1]--;
				gotoxy(cs, cs->par[1], cs->par[0]);
				break;
			case 'J':
				csi_J(cs);
				break;
			case 'K':
				csi_K(cs);
				break;
			case 'L':
				csi_L(cs);
				break;
			case 'M':
				csi_M(cs);
				break;
			case 'P':
				csi_P(cs);
				break;
			case 'X':
				csi_X(cs);
				break;
			case 'c':
				if (!cs->par[0])
					respond_ID(tty);
				break;
			case 'm':
				csi_m(cs);
				break;
			case 'r':
				if (!cs->par[0])
					cs->par[0]++;
				if (!cs->par[1])
					cs->par[1] = cs->rows;
				/* Minimum allowed region is 2 lines */
				if (cs->par[0] < cs->par[1] &&
				    cs->par[1] <= cs->rows) {
					cs->top = cs->par[0] - 1;
					cs->bottom = cs->par[1];
					/* Move to home position */
					gotoxy(cs, 0, 0);
				}
				break;
			case 's':
				save_cursor(cs);
				break;
			case 'u':
				restore_cursor(cs);
				break;
			case '@':
				csi_at(cs);
				break;
			};
			break;
		};
	}

	set_cursor(cs);
	return ret;
#undef BS
#undef HT
#undef NL
#undef VT
#undef NP
#undef CR
#undef ESC
#undef DEL
}

static int con_putchar(struct tty_struct *tty, unsigned char ch)
{
	return con_write(tty, &ch, 1);
}

void con_reset(struct console_struct *c)
{
	c->top = 0;
	c->bottom = c->rows;
	c->state = VT_NORMAL;

	gotoxy(c, 0, 0);
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
	mutex_init(&vt_ldisc_data.output_lock);
	vt_tty_struct.termios = tty_std_termios;

	/*
	 * Initialize VGA console
	 * which is the only console we support now
	 */
	console = &vga_console;
	console->driver->con_startup();
	console->driver->con_init(console);

	console->def_color = default_color;
	console->ulcolor = default_underline_color;
	console->itcolor = default_italic_color;
}

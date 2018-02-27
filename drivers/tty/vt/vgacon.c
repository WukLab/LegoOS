/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/io.h>
#include <asm/page.h>

#include <lego/bug.h>
#include <lego/tty.h>
#include <lego/irq.h>
#include <lego/kernel.h>
#include <lego/console.h>
#include <lego/spinlock.h>
#include <lego/resource.h>
#include <lego/screen_info.h>

#include "vga.h"

#define BLANK		0x0020

/*
 * On the PC, we can just recalculate addresses and then
 * access the videoram directly without any black magic.
 */
#define VGA_MAP_MEM(x, s) (unsigned long)phys_to_virt(x)

static DEFINE_SPINLOCK(vga_lock);
static int cursor_size_lastfrom;
static int cursor_size_lastto;

/* Description of the hardware situation */
static int		vga_startup_done	__read_mostly;
static unsigned long	vga_visible_origin	__read_mostly;	/* Upper left character */
static unsigned int	vga_x			__read_mostly;	/* Cursor x */
static unsigned int	vga_y			__read_mostly;	/* Cursor y */
static unsigned long	vga_pos			__read_mostly;	/* Cursor position address */
static unsigned short	vga_vram_attr		__read_mostly;	/* Character attribute */
static unsigned short	vga_erase_char		__read_mostly;	/* Erase background */
static unsigned long	vga_vram_base		__read_mostly;	/* Base of video memory */
static unsigned long	vga_vram_end		__read_mostly;	/* End of video memory */
static unsigned int	vga_vram_size		__read_mostly;	/* Size of video memory */
static u16		vga_video_port_reg	__read_mostly;	/* Video register select port */
static u16		vga_video_port_val	__read_mostly;	/* Video register value port */
static unsigned int	vga_video_num_columns;			/* Number of text columns */
static unsigned int	vga_video_num_lines;			/* Number of text lines */
static int		vga_can_do_color	__read_mostly;	/* Do we support colors? */
static unsigned char	vga_video_type		__read_mostly;	/* Card type */
static int 		vga_scan_lines		__read_mostly;
static unsigned int 	vga_rolled_over;
static int 		vga_video_font_height;

/*
 * By replacing the four outb with two back to back outw, we can reduce
 * the window of opportunity to see text mislocated to the RHS of the
 * console during heavy scrolling activity. However there is the remote
 * possibility that some pre-dinosaur hardware won't like the back to back
 * I/O. Since the Xservers get away with it, we should be able to as well.
 */
static inline void write_vga(unsigned char reg, unsigned int val)
{
	unsigned int v1, v2;
	unsigned long flags;

	/*
	 * ddprintk might set the console position from interrupt
	 * handlers, thus the write has to be IRQ-atomic.
	 */
	spin_lock_irqsave(&vga_lock, flags);

#ifndef SLOW_VGA
	v1 = reg + (val & 0xff00);
	v2 = reg + 1 + ((val << 8) & 0xff00);
	outw(v1, vga_video_port_reg);
	outw(v2, vga_video_port_reg);
#else
	outb(reg, vga_video_port_reg);
	outb(val >> 8, vga_video_port_val);
	outb(reg + 1, vga_video_port_reg);
	outb(val & 0xff, vga_video_port_val);
#endif
	spin_unlock_irqrestore(&vga_lock, flags);
}

static inline void vga_set_mem_top(struct console_struct *c)
{
	write_vga(12, (c->visible_origin - vga_vram_base) / 2);
}

static void vgacon_set_cursor_size(int xpos, int from, int to)
{
	unsigned long flags;
	int curs, cure;

	if ((from == cursor_size_lastfrom) && (to == cursor_size_lastto))
		return;
	cursor_size_lastfrom = from;
	cursor_size_lastto = to;

	spin_lock_irqsave(&vga_lock, flags);
	if (vga_video_type >= VIDEO_TYPE_VGAC) {
		outb(VGA_CRTC_CURSOR_START, vga_video_port_reg);
		curs = inb(vga_video_port_val);
		outb(VGA_CRTC_CURSOR_END, vga_video_port_reg);
		cure = inb_p(vga_video_port_val);
	} else {
		curs = 0;
		cure = 0;
	}

	curs = (curs & 0xc0) | from;
	cure = (cure & 0xe0) | to;

	outb(VGA_CRTC_CURSOR_START, vga_video_port_reg);
	outb(curs, vga_video_port_val);
	outb(VGA_CRTC_CURSOR_END, vga_video_port_reg);
	outb(cure, vga_video_port_val);
	spin_unlock_irqrestore(&vga_lock, flags);
}

static void vga_console_cursor(struct console_struct *c, int mode)
{
	/* Fall-through, draw method only. */
	switch (mode) {
	case CM_ERASE:
		write_vga(14, (c->pos - vga_vram_base) / 2);
	        if (vga_video_type >= VIDEO_TYPE_VGAC)
			vgacon_set_cursor_size(c->x, 31, 30);
		else
			vgacon_set_cursor_size(c->x, 31, 31);
		break;
	case CM_MOVE:
	case CM_DRAW:
		write_vga(14, (c->pos - vga_vram_base) / 2);
		switch (c->cursor_type & 0x0f) {
		case CUR_UNDERLINE:
			vgacon_set_cursor_size(c->x,
					       c->font_height -
					       (c->font_height <
						10 ? 2 : 3),
					       c->font_height -
					       (c->font_height <
						10 ? 1 : 2));
			break;
		case CUR_TWO_THIRDS:
			vgacon_set_cursor_size(c->x,
					       c->font_height / 3,
					       c->font_height -
					       (c->font_height <
						10 ? 1 : 2));
			break;
		case CUR_LOWER_THIRD:
			vgacon_set_cursor_size(c->x,
					       (c->font_height * 2) / 3,
					       c->font_height -
					       (c->font_height <
						10 ? 1 : 2));
			break;
		case CUR_LOWER_HALF:
			vgacon_set_cursor_size(c->x,
					       c->font_height / 2,
					       c->font_height -
					       (c->font_height <
						10 ? 1 : 2));
			break;
		case CUR_NONE:
			if (vga_video_type >= VIDEO_TYPE_VGAC)
				vgacon_set_cursor_size(c->x, 31, 30);
			else
				vgacon_set_cursor_size(c->x, 31, 31);
			break;
		default:
			vgacon_set_cursor_size(c->x, 1,
					       c->font_height);
			break;
		}
	};
}

static int vga_console_scroll(struct console_struct *c,
			      int t, int b, int dir, int lines)
{
	unsigned long oldo;
	unsigned int delta;

	if (t || b != c->rows || lines >= c->rows / 2)
		return -EINVAL;

	oldo = c->origin;
	delta = lines * c->row_size;
	if (dir == SM_UP) {
		if (c->scr_end + delta >= vga_vram_end) {
			/*
			 * Running out of video ram
			 * Have to copy some lines and go back to base
			 */
			scr_memcpyw((u16 *) vga_vram_base,
				    (u16 *) (oldo + delta),
				    c->screenbuf_size - delta);
			c->origin = vga_vram_base;
			vga_rolled_over = oldo - vga_vram_base;
		} else
			c->origin += delta;
		scr_memsetw((u16 *)(c->origin + c->screenbuf_size - delta),
			    c->erase_char, delta);
	} else {
		if (oldo - delta < vga_vram_base) {
			scr_memmovew((u16 *)(vga_vram_end - c->screenbuf_size + delta),
				      (u16 *) oldo, c->screenbuf_size - delta);
			c->origin = vga_vram_end - c->screenbuf_size;
			vga_rolled_over = 0;
		} else
			c->origin -= delta;
		c->scr_end = c->origin + c->screenbuf_size;
		scr_memsetw((u16 *)(c->origin), c->erase_char, delta);
	}

	c->scr_end = c->origin + c->screenbuf_size;
	c->visible_origin = c->origin;
	vga_set_mem_top(c);
	c->pos = (c->pos - oldo) + c->origin;

	return 0;
}

/* Called only once during system boot */
static void vga_console_startup(void)
{
	if (vga_startup_done)
		return;

	vga_video_num_lines = screen_info.orig_video_lines;
	vga_video_num_columns = screen_info.orig_video_cols;

	if (screen_info.orig_video_mode == 7) {
		/* Monochrome display */
		vga_vram_base = 0xb0000;
		vga_video_port_reg = VGA_CRT_IM;
		vga_video_port_val = VGA_CRT_DM;
		if ((screen_info.orig_video_ega_bx & 0xff) != 0x10) {
			static struct resource ega_console_resource =
			    { .name = "EGA", .start = 0x3B0, .end = 0x3BF };
			vga_video_type = VIDEO_TYPE_EGAM;
			vga_vram_size = 0x8000;
			request_resource(&ioport_resource,
					 &ega_console_resource);
		} else {
			static struct resource mda1_console_resource =
			    { .name = "MDA", .start = 0x3B0, .end = 0x3BB };
			static struct resource mda2_console_resource =
			    { .name = "MDA", .start = 0x3BF, .end = 0x3BF };
			vga_video_type = VIDEO_TYPE_MDA;
			vga_vram_size = 0x2000;
			request_resource(&ioport_resource,
					 &mda1_console_resource);
			request_resource(&ioport_resource,
					 &mda2_console_resource);
			vga_video_font_height = 14;
		}
	} else {
		/* If not, it is color. */
		vga_can_do_color = 1;
		vga_vram_base = 0xb8000;
		vga_video_port_reg = VGA_CRT_IC;
		vga_video_port_val = VGA_CRT_DC;
		if ((screen_info.orig_video_ega_bx & 0xff) != 0x10) {
			vga_vram_size = 0x8000;

			if (!screen_info.orig_video_isVGA) {
				static struct resource ega_console_resource
				    = { .name = "EGA", .start = 0x3C0, .end = 0x3DF };
				vga_video_type = VIDEO_TYPE_EGAC;
				request_resource(&ioport_resource,
						 &ega_console_resource);
			} else {
				static struct resource vga_console_resource
				    = { .name = "VGA+", .start = 0x3C0, .end = 0x3DF };
				vga_video_type = VIDEO_TYPE_VGAC;
				request_resource(&ioport_resource,
						 &vga_console_resource);
			}
		} else {
			static struct resource cga_console_resource =
			    { .name = "CGA", .start = 0x3D4, .end = 0x3D5 };
			vga_video_type = VIDEO_TYPE_CGA;
			vga_vram_size = 0x2000;
			request_resource(&ioport_resource,
					 &cga_console_resource);
			vga_video_font_height = 14;
		}
	}

	if (vga_video_type == VIDEO_TYPE_EGAC
	    || vga_video_type == VIDEO_TYPE_VGAC
	    || vga_video_type == VIDEO_TYPE_EGAM) {
		vga_video_font_height = screen_info.orig_video_points;
		/* This may be suboptimal but is a safe bet - go with it */
		vga_scan_lines = vga_video_font_height * vga_video_num_lines;
	}

	vga_vram_base = VGA_MAP_MEM(vga_vram_base, vga_vram_size);
	vga_vram_end = vga_vram_base + vga_vram_size;
	vga_visible_origin = vga_vram_base;

	vga_x = screen_info.orig_x;
	vga_y = screen_info.orig_y;
	vga_pos = (unsigned long)(((vga_video_num_columns * vga_y) + vga_x) << 1)
		+ vga_vram_base;

	vga_vram_attr = 0x7;
	vga_erase_char = (vga_vram_attr << 8) | BLANK;

	cursor_size_lastfrom = 0;
	cursor_size_lastto = 0;

	if (!vga_startup_done)
		vga_startup_done = 1;
}

#define VGA_OFFSET(cs, x, y)	(unsigned long)(((cs)->cols*(y)+(x))<<1)
#define VGA_ADDR(cs, x, y)	(unsigned long)((cs)->visible_origin + VGA_OFFSET((cs), (x), (y)))
#define VGA_ATTR(cs, ch)	(unsigned short)((((cs)->attr) << 8) | (unsigned char)(ch))

static void vga_console_putc(struct console_struct *cs, unsigned char ch,
			     int x, int y)
{
	unsigned long ADDR;

	ADDR = VGA_ADDR(cs, x, y);
	scr_writew(VGA_ATTR(cs, ch), ADDR);
}

/* Called everytime there is a new virtual console */
static void vga_console_init(struct console_struct *c)
{
	if (!vga_startup_done)
		return;

	c->x = vga_x;
	c->y = vga_y;
	c->pos = vga_pos;
	c->cols = vga_video_num_columns;
	c->rows = vga_video_num_lines;
	c->row_size = c->cols * 2;
	c->scan_lines = vga_scan_lines;
	c->screenbuf_size = c->rows * c->row_size;
	c->attr = vga_vram_attr;
	c->top = 0;
	c->bottom = c->rows;
	c->visible_origin = vga_visible_origin;
	c->origin = c->visible_origin;
	c->scr_end = c->visible_origin + c->screenbuf_size;
	c->erase_char = vga_erase_char;
	c->font_height = vga_video_font_height;
	c->cursor_type = CUR_DEFAULT;
	c->can_do_color = vga_can_do_color;

	c->bold = 1;
	c->underline = 0;
	c->blink = 0;
	c->italic = 0;
}

static void vga_console_set_origin(struct console_struct *c)
{
	c->origin = c->visible_origin = vga_vram_base;
	vga_set_mem_top(c);
}

static const struct console_driver vga_driver = {
	.con_startup	= vga_console_startup,
	.con_init	= vga_console_init,
	.con_set_origin = vga_console_set_origin,
	.con_scroll	= vga_console_scroll,
	.con_putc	= vga_console_putc,
	.con_cursor	= vga_console_cursor,
};

struct console_struct vga_console = {
	.name = "vgacon",
	.driver = &vga_driver,
};

/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
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
#include <lego/kernel.h>
#include <lego/console.h>
#include <lego/resource.h>
#include <lego/screen_info.h>

#include "vga.h"

static u32 vgacon_xres;
static u32 vgacon_yres;

#define BLANK		0x0020

/* VGA does not support fontwidths != 8 */
#define VGA_FONTWIDTH	8

/*
 * On the PC, we can just recalculate addresses and then
 * access the videoram directly without any black magic.
 */
#define VGA_MAP_MEM(x, s) (unsigned long)phys_to_virt(x)

/* Description of the hardware situation */
static int		vga_startup_done	__read_mostly;
static unsigned long	vga_vram_base		__read_mostly;	/* Base of video memory */
static unsigned long	vga_vram_end		__read_mostly;	/* End of video memory */
static unsigned int	vga_vram_size		__read_mostly;	/* Size of video memory */
static u16		vga_video_port_reg	__read_mostly;	/* Video register select port */
static u16		vga_video_port_val	__read_mostly;	/* Video register value port */
static unsigned int	vga_video_num_columns;			/* Number of text columns */
static unsigned int	vga_video_num_lines;			/* Number of text lines */
static int		vga_can_do_color	__read_mostly;	/* Do we support colors? */
static unsigned int	vga_default_font_height __read_mostly;	/* Height of default screen font */
static unsigned char	vga_video_type		__read_mostly;	/* Card type */
static unsigned char	vga_hardscroll_enabled	__read_mostly;
static unsigned char	vga_hardscroll_user_enable __read_mostly = 1;
static int 		vga_video_font_height;
static int 		vga_scan_lines		__read_mostly;


/* Called only once during system boot */
static void vga_console_startup(void)
{
	u16 saved1, saved2;
	volatile u16 *p;

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
			vga_video_font_height = 8;
		}
	}

	vga_vram_base = VGA_MAP_MEM(vga_vram_base, vga_vram_size);
	vga_vram_end = vga_vram_base + vga_vram_size;

	/*
	 *      Find out if there is a graphics card present.
	 *      Are there smarter methods around?
	 */
	p = (volatile u16 *) vga_vram_base;
	saved1 = scr_readw(p);
	saved2 = scr_readw(p + 1);
	scr_writew(0xAA55, p);
	scr_writew(0x55AA, p + 1);
	if (scr_readw(p) != 0xAA55 || scr_readw(p + 1) != 0x55AA) {
		scr_writew(saved1, p);
		scr_writew(saved2, p + 1);
		goto no_vga;
	}
	scr_writew(0x55AA, p);
	scr_writew(0xAA55, p + 1);
	if (scr_readw(p) != 0x55AA || scr_readw(p + 1) != 0xAA55) {
		scr_writew(saved1, p);
		scr_writew(saved2, p + 1);
		goto no_vga;
	}
	scr_writew(saved1, p);
	scr_writew(saved2, p + 1);

	if (vga_video_type == VIDEO_TYPE_EGAC
	    || vga_video_type == VIDEO_TYPE_VGAC
	    || vga_video_type == VIDEO_TYPE_EGAM) {
		vga_hardscroll_enabled = vga_hardscroll_user_enable;
		vga_default_font_height = screen_info.orig_video_points;
		vga_video_font_height = screen_info.orig_video_points;
		/* This may be suboptimal but is a safe bet - go with it */
		vga_scan_lines =
		    vga_video_font_height * vga_video_num_lines;
	}

	vgacon_xres = screen_info.orig_video_cols * VGA_FONTWIDTH;
	vgacon_yres = vga_scan_lines;

	if (!vga_startup_done) {
		//vgacon_scrollback_startup();
		vga_startup_done = 1;
	}

no_vga:
	panic("no vga");
}

/* Called everytime there is a new virtual console */
static void vga_console_init(struct console_struct *con, int x)
{

}

static const struct console_driver vga_driver = {
	.con_startup	= vga_console_startup,
	.con_init	= vga_console_init,
};

struct console_struct vga_console = {
	.name = "vgacon",
	.driver = &vga_driver,
};

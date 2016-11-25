/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CONSOLE_H_
#define _LEGO_CONSOLE_H_

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

struct console_driver {

};

struct console_struct {

};

#endif /* _LEGO_CONSOLE_H_ */

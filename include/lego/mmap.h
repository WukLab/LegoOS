/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * mmap() syscall flags
 * Used by both processor and memory managers
 */

#ifndef _LEGO_MMAP_H_
#define _LEGO_MMAP_H_

#define PROT_READ	0x01		/* page can be read */
#define PROT_WRITE	0x02		/* page can be written */
#define PROT_EXEC	0x04		/* page can be executed */
#define PROT_SEM	0x08		/* page may be used for atomic ops */
#define PROT_NONE	0x00		/* page can not be accessed */

#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked */

#endif /* _LEGO_MMAP_H_ */

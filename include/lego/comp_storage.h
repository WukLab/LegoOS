/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Things shared by both processor-component and storage-component
 */

#ifndef _LEGO_COMP_STORAGE_H_
#define _LEGO_COMP_STORAGE_H_

#include <lego/comp_common.h>

#define DEBUG_STORAGE

#define O_CREAT		00000100
#define O_WRONLY	00000001
#define O_RDONLY 	00000000
#define O_RDWR		00000002

#define PREFETCH_ORDER 7 /* prefetching 128 pages a time */

#endif

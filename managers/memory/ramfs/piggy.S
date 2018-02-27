/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/linkage.h>

	.section ".ramfs","ax"
GLOBAL(ramfs_start)
#ifdef CONFIG_USE_RAMFS
.incbin CONFIG_RAMFS_OBJECT_FILE
#endif
GLOBAL(ramfs_end)

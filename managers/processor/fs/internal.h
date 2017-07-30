/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _PROCESSOR_FS_INTERNAL_H_
#define _PROCESSOR_FS_INTERNAL_H_

#include <lego/bug.h>
#include <lego/files.h>
#include <lego/atomic.h>

struct file *fdget(int fd);

#endif /* _PROCESSOR_FS_INTERNAL_H_ */

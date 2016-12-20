/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SLAB_H_
#define _LEGO_SLAB_H_

#include <lego/mm.h>

void kfree(const void *p);
void *kmalloc(size_t size, gfp_t flags);

#endif /* _LEGO_SLAB_H_ */

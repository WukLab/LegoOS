/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/bug.h>
#include <lego/kernel.h>

void kfree(const void *p)
{
	BUG_ON(!p);
	free_page((unsigned long)p);
}

void *kmalloc(size_t size, gfp_t flags)
{
	if (size > PAGE_SIZE) {
		WARN(1, "Limit kmalloc() size to PAGE_SIZE");
		return NULL;
	}
	return (void *)get_zeroed_page(GFP_KERNEL);
}

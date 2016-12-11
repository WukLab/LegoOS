/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/list.h>
#include <lego/spinlock.h>

#include <asm/pgtable.h>

struct mm_struct init_mm = {
	.pgd			= swapper_pg_dir,
	.page_table_lock	=  __SPIN_LOCK_UNLOCKED(init_mm.page_table_lock),
	.mmlist			= LIST_HEAD_INIT(init_mm.mmlist),
};

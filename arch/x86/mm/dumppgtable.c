/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/sched.h>

void ptdump_walk_pgd_level(pgd_t *pgd)
{
	pgd_t *start = current->mm->pgd;
	int i;

	if (pgd)
		start = pgd;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		pr_info("%3d [%#18lx - %#18lx] %#lx\n",
			i, i * PGDIR_SIZE,  (i+1)*PGDIR_SIZE - 1, pgd_val(*start));
		start++;
	}
}

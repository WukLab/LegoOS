/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/kernel.h>

/*
 * Helpers for scheduler related information
 */

void print_nr_cpus_allowd(int line)
{
	char buf[64];

	scnprintf(buf, 64, "%*pbl", NR_CPUS, &current->cpus_allowed);
	pr_info("Current: %d %s, nr_allowd: %d, %s (info: %d)\n",
		current->pid, current->comm, current->nr_cpus_allowed, buf, line);
}

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/bug.h>
#include <lego/kernel.h>
#include <lego/atomic.h>
#include <lego/profile.h>

/* Profile Point */
extern struct profile_point __sprofilepoint[], __eprofilepoint[];

void print_profile_point(struct profile_point *pp)
{
	struct timespec ts = {0, 0};
	long nr = 0, avg_ns = 0, time_ns = 0;

	nr = atomic_long_read(&pp->nr);
	time_ns = atomic_long_read(&pp->time_ns);
	ts = ns_to_timespec(time_ns);

	if (!nr)
		goto print;

	avg_ns = DIV_ROUND_UP(time_ns, nr);

print:
	pr_info("%s  %35s  %6Ld.%09Ld  %16ld  %16ld\n",
		pp->enabled? "     on" : "    off",
		pp->pp_name,
		(s64)ts.tv_sec, (s64)ts.tv_nsec,
		nr,
		avg_ns);
}

void print_profile_points(void)
{
	struct profile_point *pp;
	int count = 0;

	pr_info("\n");
	pr_info("Kernel Profile Points\n");
	pr_info(" Status                                 Name          Total(s)                NR           Avg(ns)\n");
	pr_info("-------  -----------------------------------  ----------------  ----------------  ----------------\n");
	for (pp = __sprofilepoint; pp < __eprofilepoint; pp++) {
		print_profile_point(pp);
		count++;
	}
	pr_info("-------  -----------------------------------  ----------------  ----------------  ----------------\n");
	pr_info("\n");
}

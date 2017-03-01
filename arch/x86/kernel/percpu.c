/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/percpu.h>
#include <lego/cpumask.h>
#include <lego/nodemask.h>

void __init setup_per_cpu_areas(void)
{
	pr_info("NR_CPUS:%d nr_cpumask_bits:%d nr_cpu_ids:%d nr_node_ids:%d\n",
		NR_CPUS, nr_cpumask_bits, nr_cpu_ids, nr_node_ids);
}

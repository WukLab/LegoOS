/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/apic.h>
#include <asm/numa.h>

#include <lego/numa.h>
#include <lego/kernel.h>
#include <lego/nodemask.h>

/*
 * __apicid_to_node[] stores the raw mapping between physical apicid
 * and node, and is used to initialize cpu_to_node mapping.
 */
int __apicid_to_node[MAX_LOCAL_APIC];
nodemask_t numa_nodes_parsed;

int apicid_to_node(int apicid)
{
	BUG_ON(apicid > MAX_LOCAL_APIC);
	return __apicid_to_node[apicid];
}

void set_apicid_to_node(int apicid, int node)
{
	BUG_ON(apicid > MAX_LOCAL_APIC || node > MAX_NUMNODES);
	__apicid_to_node[apicid] = node;
}

/* Mapping between cpu and node */
int cpu_to_node_map[NR_CPUS] = { NUMA_NO_NODE };

int cpu_to_node(int cpu)
{
	WARN_ON(cpu >= NR_CPUS);
	return cpu_to_node_map[cpu];
}

void numa_set_node(int cpu, int node)
{
	cpu_to_node_map[cpu] = node;
}

void numa_clear_node(int cpu)
{
	numa_set_node(cpu, NUMA_NO_NODE);
}

/*
 * Init CPU <--> Node mapping
 * Called after ACPI and APIC are finished
 */
void __init init_cpu_to_node(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		int apicid = cpu_to_apicid(cpu);
		int node = apicid_to_node(apicid);

		numa_set_node(cpu, node);
	}
}

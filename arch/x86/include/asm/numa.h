/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_NUMA_H_
#define _ASM_X86_NUMA_H_

#include <asm/apic.h>

#include <lego/cpumask.h>
#include <lego/nodemask.h>
#include <lego/compiler.h>

/*
 * Too small node sizes may confuse the VM badly. Usually they
 * result from BIOS bugs. So dont recognize nodes as standalone
 * NUMA entities that have less than this amount of RAM listed:
 */
#define NODE_MIN_SIZE (4*1024*1024)

#define NR_NODE_MEMBLKS		(MAX_NUMNODES*2)

extern int cpu_to_node_map[NR_CPUS];
extern int __apicid_to_node[MAX_LOCAL_APIC];
extern nodemask_t numa_nodes_parsed;

int apicid_to_node(int apicid);
void set_apicid_to_node(int apicid, int node);
int cpu_to_node(int cpu);
void numa_set_node(int cpu, int node);
void numa_clear_node(int cpu);
void __init init_cpu_to_node(void);
void __init x86_numa_init(void);

int __init numa_add_memblk(int nodeid, u64 start, u64 end);
int __init numa_set_distance(int from, int to, int distance);
int node_distance(int from, int to);

extern bool acpi_numa_disabled;

#endif /* _ASM_X86_NUMA_H_ */

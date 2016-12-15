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

#include <lego/acpi.h>
#include <lego/numa.h>
#include <lego/kernel.h>
#include <lego/nodemask.h>
#include <lego/memblock.h>

/*
 * __apicid_to_node[] stores the raw mapping between physical apicid
 * and node, and is used to initialize cpu_to_node mapping.
 */
int __apicid_to_node[MAX_LOCAL_APIC];

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

struct numa_memblk {
	u64			start;
	u64			end;
	int			nid;
};

struct numa_meminfo {
	int			nr_blks;
	struct numa_memblk	blk[NR_NODE_MEMBLKS];
};

static struct numa_meminfo numa_meminfo __initdata;

nodemask_t numa_nodes_parsed;

static int numa_distance_cnt;
static u8 *numa_distance;

static int __init numa_add_memblk_to(int nid, u64 start, u64 end,
				     struct numa_meminfo *mi)
{
	/* ignore zero length blks */
	if (start == end)
		return 0;

	/* whine about and ignore invalid blks */
	if (start > end || nid < 0 || nid >= MAX_NUMNODES) {
		pr_warn("NUMA: Warning: invalid memblk node %d [mem %#010Lx-%#010Lx]\n",
			   nid, start, end - 1);
		return 0;
	}

	if (mi->nr_blks >= NR_NODE_MEMBLKS) {
		pr_err("NUMA: too many memblk ranges\n");
		return -EINVAL;
	}

	mi->blk[mi->nr_blks].start = start;
	mi->blk[mi->nr_blks].end = end;
	mi->blk[mi->nr_blks].nid = nid;
	mi->nr_blks++;
	return 0;
}

/**
 * numa_add_memblk - Add one numa_memblk to numa_meminfo
 * @nid: NUMA node ID of the new memblk
 * @start: Start address of the new memblk
 * @end: End address of the new memblk
 *
 * Add a new memblk to the default numa_meminfo.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int __init numa_add_memblk(int nid, u64 start, u64 end)
{
	return numa_add_memblk_to(nid, start, end, &numa_meminfo);
}

/*
 * Set nodes, which have memory in @mi, in *@nodemask.
 */
static void __init numa_nodemask_from_meminfo(nodemask_t *nodemask,
					      const struct numa_meminfo *mi)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mi->blk); i++)
		if (mi->blk[i].start != mi->blk[i].end &&
		    mi->blk[i].nid != NUMA_NO_NODE)
			node_set(mi->blk[i].nid, *nodemask);
}

/**
 * numa_remove_memblk_from - Remove one numa_memblk from a numa_meminfo
 * @idx: Index of memblk to remove
 * @mi: numa_meminfo to remove memblk from
 *
 * Remove @idx'th numa_memblk from @mi by shifting @mi->blk[] and
 * decrementing @mi->nr_blks.
 */
void __init numa_remove_memblk_from(int idx, struct numa_meminfo *mi)
{
	mi->nr_blks--;
	memmove(&mi->blk[idx], &mi->blk[idx + 1],
		(mi->nr_blks - idx) * sizeof(mi->blk[0]));
}

static int __init numa_alloc_distance(void)
{
	nodemask_t nodes_parsed;
	size_t size;
	int i, j, cnt = 0;
	u64 phys;

	/* size the new table and allocate it */
	nodes_parsed = numa_nodes_parsed;
	numa_nodemask_from_meminfo(&nodes_parsed, &numa_meminfo);

	for_each_node_mask(i, nodes_parsed) {
		cnt = i;
	}

	cnt++;
	size = cnt * cnt * sizeof(numa_distance[0]);

	phys = memblock_find_in_range(0, PFN_PHYS(max_pfn_mapped),
				      size, PAGE_SIZE);
	if (!phys) {
		pr_warn("NUMA: Warning: can't allocate distance table!\n");
		/* don't retry until explicitly reset */
		numa_distance = (void *)1LU;
		return -ENOMEM;
	}
	memblock_reserve(phys, size);

	numa_distance = __va(phys);
	numa_distance_cnt = cnt;

	/* fill with the default distances */
	for (i = 0; i < cnt; i++)
		for (j = 0; j < cnt; j++)
			numa_distance[i * cnt + j] = i == j ?
				LOCAL_DISTANCE : REMOTE_DISTANCE;
	printk(KERN_DEBUG "NUMA: Initialized distance table, cnt=%d\n", cnt);

	return 0;
}

void __init numa_set_distance(int from, int to, int distance)
{
	if (!numa_distance && numa_alloc_distance() < 0)
		return;

	if (from >= numa_distance_cnt || to >= numa_distance_cnt ||
			from < 0 || to < 0) {
		pr_warn_once("NUMA: Warning: node ids are out of bound, from=%d to=%d distance=%d\n",
			    from, to, distance);
		return;
	}

	if ((u8)distance != distance ||
	    (from == to && distance != LOCAL_DISTANCE)) {
		pr_warn_once("NUMA: Warning: invalid distance parameter, from=%d to=%d distance=%d\n",
			     from, to, distance);
		return;
	}

	numa_distance[from * numa_distance_cnt + to] = distance;
}

void __init x86_numa_init(void)
{

}

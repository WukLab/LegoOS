/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/apic.h>
#include <asm/numa.h>

#include <lego/mm.h>
#include <lego/acpi.h>
#include <lego/numa.h>
#include <lego/kernel.h>
#include <lego/nodemask.h>
#include <lego/memblock.h>

struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;

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

/**
 * numa_reset_distance - Reset NUMA distance table
 *
 * The current table is freed.  The next numa_set_distance() call will
 * create a new one.
 */
static void __init numa_reset_distance(void)
{
	size_t size = numa_distance_cnt * numa_distance_cnt * sizeof(numa_distance[0]);

	/* numa_distance could be 1LU marking allocation failure, test cnt */
	if (numa_distance_cnt)
		memblock_free(__pa(numa_distance), size);
	numa_distance_cnt = 0;
	numa_distance = NULL;	/* enable table creation */
}

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
	pr_debug("NUMA: Initialized distance table, cnt=%d\n", cnt);

	return 0;
}

int __init numa_set_distance(int from, int to, int distance)
{
	if (!numa_distance && numa_alloc_distance() < 0)
		return -ENOMEM;

	if (from >= numa_distance_cnt || to >= numa_distance_cnt ||
			from < 0 || to < 0) {
		pr_warn_once("NUMA: Warning: node ids are out of bound, from=%d to=%d distance=%d\n",
			    from, to, distance);
		return -EINVAL;
	}

	if ((u8)distance != distance ||
	    (from == to && distance != LOCAL_DISTANCE)) {
		pr_warn_once("NUMA: Warning: invalid distance parameter, from=%d to=%d distance=%d\n",
			     from, to, distance);
		return -EINVAL;
	}

	numa_distance[from * numa_distance_cnt + to] = distance;

	return 0;
}

int node_distance(int from, int to)
{
	if (from >= numa_distance_cnt || to >= numa_distance_cnt)
		return from == to ? LOCAL_DISTANCE : REMOTE_DISTANCE;
	return numa_distance[from * numa_distance_cnt + to];
}

/**
 * numa_cleanup_meminfo - Cleanup a numa_meminfo
 * @mi: numa_meminfo to clean up
 *
 * Sanitize @mi by merging and removing unncessary memblks.  Also check for
 * conflicts and clear unused memblks.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int __init numa_cleanup_meminfo(struct numa_meminfo *mi)
{
	const u64 low = 0;
	const u64 high = PFN_PHYS(max_pfn);
	int i, j, k;

	if (mi->nr_blks == 0) {
		pr_debug("No NUMA memblk registered, fallback dummy\n");
		return -EINVAL;
	}

	/* first, trim all entries */
	for (i = 0; i < mi->nr_blks; i++) {
		struct numa_memblk *bi = &mi->blk[i];

		/* make sure all blocks are inside the limits */
		bi->start = max(bi->start, low);
		bi->end = min(bi->end, high);

		/* and there's no empty or non-exist block */
		if (bi->start >= bi->end ||
		    !memblock_overlaps_region(&memblock.memory,
			bi->start, bi->end - bi->start))
			numa_remove_memblk_from(i--, mi);
	}

	/* merge neighboring / overlapping entries */
	for (i = 0; i < mi->nr_blks; i++) {
		struct numa_memblk *bi = &mi->blk[i];

		for (j = i + 1; j < mi->nr_blks; j++) {
			struct numa_memblk *bj = &mi->blk[j];
			u64 start, end;

			/*
			 * See whether there are overlapping blocks.  Whine
			 * about but allow overlaps of the same nid.  They
			 * will be merged below.
			 */
			if (bi->end > bj->start && bi->start < bj->end) {
				if (bi->nid != bj->nid) {
					pr_err("NUMA: node %d [mem %#010Lx-%#010Lx] overlaps with node %d [mem %#010Lx-%#010Lx]\n",
					       bi->nid, bi->start, bi->end - 1,
					       bj->nid, bj->start, bj->end - 1);
					return -EINVAL;
				}
				pr_warn("NUMA: Warning: node %d [mem %#010Lx-%#010Lx] overlaps with itself [mem %#010Lx-%#010Lx]\n",
					   bi->nid, bi->start, bi->end - 1,
					   bj->start, bj->end - 1);
			}

			/*
			 * Join together blocks on the same node, holes
			 * between which don't overlap with memory on other
			 * nodes.
			 */
			if (bi->nid != bj->nid)
				continue;
			start = min(bi->start, bj->start);
			end = max(bi->end, bj->end);
			for (k = 0; k < mi->nr_blks; k++) {
				struct numa_memblk *bk = &mi->blk[k];

				if (bi->nid == bk->nid)
					continue;
				if (start < bk->end && end > bk->start)
					break;
			}
			if (k < mi->nr_blks)
				continue;
			printk(KERN_INFO "NUMA: Node %d [mem %#010Lx-%#010Lx] + [mem %#010Lx-%#010Lx] -> [mem %#010Lx-%#010Lx]\n",
			       bi->nid, bi->start, bi->end - 1, bj->start,
			       bj->end - 1, start, end - 1);
			bi->start = start;
			bi->end = end;
			numa_remove_memblk_from(j--, mi);
		}
	}

	/* clear unused ones */
	for (i = mi->nr_blks; i < ARRAY_SIZE(mi->blk); i++) {
		mi->blk[i].start = mi->blk[i].end = 0;
		mi->blk[i].nid = NUMA_NO_NODE;
	}

	return 0;
}

/* Allocate NODE_DATA for a node on the local memory */
static void __init alloc_node_data(int nid)
{
	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
	u64 nd_pa;
	void *nd;

	/*
	 * Allocate node data.  Try node-local memory and then any node.
	 * Never allocate in DMA zone.
	 */
	nd_pa = memblock_alloc_nid(nd_size, L1_CACHE_BYTES, nid);
	if (!nd_pa) {
		nd_pa = __memblock_alloc_base(nd_size, L1_CACHE_BYTES,
					      MEMBLOCK_ALLOC_ACCESSIBLE);
		if (!nd_pa) {
			pr_err("Cannot find %zu bytes in node %d\n",
			       nd_size, nid);
			return;
		}
	}
	nd = __va(nd_pa);

	/* report and initialize */
	pr_info("NODE_DATA(%d) allocated [mem %#010Lx-%#010Lx]\n", nid,
	       nd_pa, nd_pa + nd_size - 1);

	node_data[nid] = nd;
	memset(NODE_DATA(nid), 0, sizeof(pg_data_t));

	node_set_online(nid);
}

/*
 * This function register the [memory + node] in memblock
 * and allocate pglist data for each possible node.
 */
static int __init numa_register_memblks(struct numa_meminfo *mi)
{
	unsigned long uninitialized_var(pfn_align);
	int i, nid;

	/* Account for nodes with cpus and no memory */
	node_possible_map = numa_nodes_parsed;
	numa_nodemask_from_meminfo(&node_possible_map, mi);
	if (WARN_ON(nodes_empty(node_possible_map)))
		return -EINVAL;

	for (i = 0; i < mi->nr_blks; i++) {
		struct numa_memblk *mb = &mi->blk[i];

		memblock_set_node(mb->start, mb->end - mb->start,
				  &memblock.memory, mb->nid);
	}

	/* Finally register nodes. */
	for_each_node_mask(nid, node_possible_map) {
		u64 start = PFN_PHYS(max_pfn);
		u64 end = 0;

		for (i = 0; i < mi->nr_blks; i++) {
			if (nid != mi->blk[i].nid)
				continue;
			start = min(mi->blk[i].start, start);
			end = max(mi->blk[i].end, end);
		}

		if (start >= end)
			continue;

		/*
		 * Don't confuse VM with a node that doesn't have the
		 * minimum amount of memory:
		 */
		if (end && (end - start) < NODE_MIN_SIZE)
			continue;

		alloc_node_data(nid);
	}

	/* Dump memblock with node info and return. */
	memblock_dump_all();

	return 0;
}

/*
 * We have parsed ACPI tables before we reach here
 * If there is no NUMA info, then fake one node.
 */
void __init x86_numa_init(void)
{
	int ret;
	bool fake = false;

	if (acpi_numa_disabled)
		fake = true;

fake_numa:
	nodes_clear(node_possible_map);
	nodes_clear(node_online_map);

	/*
 	 * Used if there's no underlying NUMA architecture, NUMA initialization
 	 * fails, or NUMA is disabled on the command line.
 	 *
 	 * Must online at least one node and add memory blocks that cover all
 	 * allowed memory.  This function must not fail.
 	 */
	if (fake) {
		pr_info("No NUMA configuration found\n");
		pr_info("Faking a node at [mem %#018Lx-%#018Lx]\n",
		       0LLU, PFN_PHYS(max_pfn) - 1);

		WARN_ON(memblock_set_node(0, ULLONG_MAX, &memblock.memory,
					  MAX_NUMNODES));
		WARN_ON(memblock_set_node(0, ULLONG_MAX, &memblock.reserved,
					  MAX_NUMNODES));

		memset(&numa_meminfo, 0, sizeof(numa_meminfo));
		numa_reset_distance();
		nodes_clear(numa_nodes_parsed);

		/* Fake one node and that node has all memory */
		node_set(0, numa_nodes_parsed);
		numa_add_memblk(0, 0, PFN_PHYS(max_pfn));

		BUG_ON(numa_cleanup_meminfo(&numa_meminfo));
		BUG_ON(numa_register_memblks(&numa_meminfo));

		return;
	}

	ret = numa_cleanup_meminfo(&numa_meminfo);
	if (ret) {
		fake = true;
		goto fake_numa;
	}

	ret = numa_register_memblks(&numa_meminfo);
	if (ret) {
		fake = true;
		goto fake_numa;
	}
}

/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/acpi.h>
#include <lego/kernel.h>
#include <lego/percpu.h>
#include <lego/cpumask.h>
#include <lego/nodemask.h>
#include <lego/memblock.h>

/**
 * pcpu_alloc_alloc_info - allocate percpu allocation info
 * @nr_groups: the number of groups
 * @nr_units: the number of units
 *
 * Allocate ai which is large enough for @nr_groups groups containing
 * @nr_units units.  The returned ai's groups[0].cpu_map points to the
 * cpu_map array which is long enough for @nr_units and filled with
 * NR_CPUS.  It's the caller's responsibility to initialize cpu_map
 * pointer of other groups.
 *
 * RETURNS:
 * Pointer to the allocated pcpu_alloc_info on success, NULL on
 * failure.
 */
struct pcpu_alloc_info * __init pcpu_alloc_alloc_info(int nr_groups,
						      int nr_units)
{
	struct pcpu_alloc_info *ai;
	size_t base_size, ai_size;
	void *ptr;
	int unit;

	base_size = ALIGN(sizeof(*ai) + nr_groups * sizeof(ai->groups[0]),
			  __alignof__(ai->groups[0].cpu_map[0]));
	ai_size = base_size + nr_units * sizeof(ai->groups[0].cpu_map[0]);

	ptr = memblock_virt_alloc_nopanic(PFN_ALIGN(ai_size), 0);
	if (!ptr)
		return NULL;
	ai = ptr;
	ptr += base_size;

	ai->groups[0].cpu_map = ptr;

	for (unit = 0; unit < nr_units; unit++)
		ai->groups[0].cpu_map[unit] = NR_CPUS;

	ai->nr_groups = nr_groups;
	ai->__ai_size = PFN_ALIGN(ai_size);

	return ai;
}

/**
 * pcpu_build_alloc_info - build alloc_info considering distances between CPUs
 * @reserved_size: the size of reserved percpu area in bytes
 * @dyn_size: minimum free size for dynamic allocation in bytes
 * @atom_size: allocation atom size
 * @cpu_distance_fn: callback to determine distance between cpus, optional
 *
 * This function determines grouping of units, their mappings to cpus
 * and other parameters considering needed percpu size, allocation
 * atom size and distances between CPUs.
 *
 * Groups are always multiples of atom size and CPUs which are of
 * LOCAL_DISTANCE both ways are grouped together and share space for
 * units in the same group.  The returned configuration is guaranteed
 * to have CPUs on different nodes on different groups and >=75% usage
 * of allocated virtual address space.
 *
 * RETURNS:
 * On success, pointer to the new allocation_info is returned.  On
 * failure, ERR_PTR value is returned.
 */
static struct pcpu_alloc_info * __init pcpu_build_alloc_info(
				size_t reserved_size, size_t dyn_size,
				size_t atom_size,
				pcpu_fc_cpu_distance_fn_t cpu_distance_fn)
{
	static int group_map[NR_CPUS] __initdata;
	static int group_cnt[NR_CPUS] __initdata;
	const size_t static_size = __per_cpu_end - __per_cpu_start;
	int nr_groups = 1, nr_units = 0;
	size_t size_sum, min_unit_size, alloc_size;
	int upa, max_upa, uninitialized_var(best_upa);	/* units_per_alloc */
	int last_allocs, group, unit;
	unsigned int cpu, tcpu;
	struct pcpu_alloc_info *ai;
	unsigned int *cpu_map;

	/* this function may be called multiple times */
	memset(group_map, 0, sizeof(group_map));
	memset(group_cnt, 0, sizeof(group_cnt));

	/* calculate size_sum and ensure dyn_size is enough for early alloc */
	size_sum = PFN_ALIGN(static_size + reserved_size +
			    max_t(size_t, dyn_size, PERCPU_DYNAMIC_EARLY_SIZE));
	dyn_size = size_sum - static_size - reserved_size;

	/*
	 * Determine min_unit_size, alloc_size and max_upa such that
	 * alloc_size is multiple of atom_size and is the smallest
	 * which can accommodate 4k aligned segments which are equal to
	 * or larger than min_unit_size.
	 */
	min_unit_size = max_t(size_t, size_sum, PCPU_MIN_UNIT_SIZE);

	alloc_size = roundup(min_unit_size, atom_size);
	upa = alloc_size / min_unit_size;
	while (alloc_size % upa || (offset_in_page(alloc_size / upa)))
		upa--;
	max_upa = upa;

	/* group cpus according to their proximity */
	for_each_possible_cpu(cpu) {
		group = 0;
	next_group:
		for_each_possible_cpu(tcpu) {
			if (cpu == tcpu)
				break;
			if (group_map[tcpu] == group && cpu_distance_fn &&
			    (cpu_distance_fn(cpu, tcpu) > LOCAL_DISTANCE ||
			     cpu_distance_fn(tcpu, cpu) > LOCAL_DISTANCE)) {
				group++;
				nr_groups = max(nr_groups, group + 1);
				goto next_group;
			}
		}
		group_map[cpu] = group;
		group_cnt[group]++;
	}

	/*
	 * Expand unit size until address space usage goes over 75%
	 * and then as much as possible without using more address
	 * space.
	 */
	last_allocs = INT_MAX;
	for (upa = max_upa; upa; upa--) {
		int allocs = 0, wasted = 0;

		if (alloc_size % upa || (offset_in_page(alloc_size / upa)))
			continue;

		for (group = 0; group < nr_groups; group++) {
			int this_allocs = DIV_ROUND_UP(group_cnt[group], upa);
			allocs += this_allocs;
			wasted += this_allocs * upa - group_cnt[group];
		}

		/*
		 * Don't accept if wastage is over 1/3.  The
		 * greater-than comparison ensures upa==1 always
		 * passes the following check.
		 */
		if (wasted > num_possible_cpus() / 3)
			continue;

		/* and then don't consume more memory */
		if (allocs > last_allocs)
			break;
		last_allocs = allocs;
		best_upa = upa;
	}
	upa = best_upa;

	/* allocate and fill alloc_info */
	for (group = 0; group < nr_groups; group++)
		nr_units += roundup(group_cnt[group], upa);

	ai = pcpu_alloc_alloc_info(nr_groups, nr_units);
	if (!ai)
		return ERR_PTR(-ENOMEM);
	cpu_map = ai->groups[0].cpu_map;

	for (group = 0; group < nr_groups; group++) {
		ai->groups[group].cpu_map = cpu_map;
		cpu_map += roundup(group_cnt[group], upa);
	}

	ai->static_size = static_size;
	ai->reserved_size = reserved_size;
	ai->dyn_size = dyn_size;
	ai->unit_size = alloc_size / upa;
	ai->atom_size = atom_size;
	ai->alloc_size = alloc_size;

	for (group = 0, unit = 0; group_cnt[group]; group++) {
		struct pcpu_group_info *gi = &ai->groups[group];

		/*
		 * Initialize base_offset as if all groups are located
		 * back-to-back.  The caller should update this to
		 * reflect actual allocation.
		 */
		gi->base_offset = unit * ai->unit_size;

		for_each_possible_cpu(cpu)
			if (group_map[cpu] == group)
				gi->cpu_map[gi->nr_units++] = cpu;
		gi->nr_units = roundup(gi->nr_units, upa);
		unit += gi->nr_units;
	}
	BUG_ON(unit != nr_units);

	return ai;
}

int __init pcpu_setup_first_chunk(const struct pcpu_alloc_info *ai,
				  void *base_addr)
{
	return 0;
}

/**
 * pcpu_free_alloc_info - free percpu allocation info
 * @ai: pcpu_alloc_info to free
 *
 * Free @ai which was allocated by pcpu_alloc_alloc_info().
 */
void __init pcpu_free_alloc_info(struct pcpu_alloc_info *ai)
{
	memblock_free_early(__pa(ai), ai->__ai_size);
}

/**
 * pcpu_embed_first_chunk - embed the first percpu chunk into bootmem
 * @reserved_size: the size of reserved percpu area in bytes
 * @dyn_size: minimum free size for dynamic allocation in bytes
 * @atom_size: allocation atom size
 * @cpu_distance_fn: callback to determine distance between cpus, optional
 * @alloc_fn: function to allocate percpu page
 * @free_fn: function to free percpu page
 *
 * This is a helper to ease setting up embedded first percpu chunk and
 * can be called where pcpu_setup_first_chunk() is expected.
 *
 * If this function is used to setup the first chunk, it is allocated
 * by calling @alloc_fn and used as-is without being mapped into
 * vmalloc area.  Allocations are always whole multiples of @atom_size
 * aligned to @atom_size.
 *
 * This enables the first chunk to piggy back on the linear physical
 * mapping which often uses larger page size.  Please note that this
 * can result in very sparse cpu->unit mapping on NUMA machines thus
 * requiring large vmalloc address space.  Don't use this allocator if
 * vmalloc space is not orders of magnitude larger than distances
 * between node memory addresses (ie. 32bit NUMA machines).
 *
 * @dyn_size specifies the minimum dynamic area size.
 *
 * If the needed size is smaller than the minimum or specified unit
 * size, the leftover is returned using @free_fn.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int __init pcpu_embed_first_chunk(size_t reserved_size, size_t dyn_size,
				  size_t atom_size,
				  pcpu_fc_cpu_distance_fn_t cpu_distance_fn,
				  pcpu_fc_alloc_fn_t alloc_fn,
				  pcpu_fc_free_fn_t free_fn)
{
	void *base = (void *)ULONG_MAX;
	void **areas = NULL;
	struct pcpu_alloc_info *ai;
	size_t size_sum, areas_size;
	unsigned long max_distance;
	int group, i, highest_group, rc;

	ai = pcpu_build_alloc_info(reserved_size, dyn_size, atom_size,
				   cpu_distance_fn);
	if (IS_ERR(ai))
		return PTR_ERR(ai);

	size_sum = ai->static_size + ai->reserved_size + ai->dyn_size;
	areas_size = PFN_ALIGN(ai->nr_groups * sizeof(void *));

	areas = memblock_virt_alloc_nopanic(areas_size, 0);
	if (!areas) {
		rc = -ENOMEM;
		goto out_free;
	}

	/* allocate, copy and determine base address & max_distance */
	highest_group = 0;
	for (group = 0; group < ai->nr_groups; group++) {
		struct pcpu_group_info *gi = &ai->groups[group];
		unsigned int cpu = NR_CPUS;
		void *ptr;

		for (i = 0; i < gi->nr_units && cpu == NR_CPUS; i++)
			cpu = gi->cpu_map[i];
		BUG_ON(cpu == NR_CPUS);

		/* allocate space for the whole group */
		ptr = alloc_fn(cpu, gi->nr_units * ai->unit_size, atom_size);
		if (!ptr) {
			rc = -ENOMEM;
			goto out_free_areas;
		}
		areas[group] = ptr;

		base = min(ptr, base);
		if (ptr > areas[highest_group])
			highest_group = group;
	}
	max_distance = areas[highest_group] - base;
	max_distance += ai->unit_size * ai->groups[highest_group].nr_units;

	/* warn if maximum distance is further than 75% of vmalloc space */
	if (max_distance > (VMALLOC_END - VMALLOC_START) * 3 / 4) {
		pr_warn("max_distance=0x%lx too large for vmalloc space 0x%lx\n",
				max_distance, (VMALLOC_END - VMALLOC_START));
#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
		/* and fail if we have fallback */
		rc = -EINVAL;
		goto out_free_areas;
#endif
	}

	/*
	 * Copy data and free unused parts.  This should happen after all
	 * allocations are complete; otherwise, we may end up with
	 * overlapping groups.
	 */
	for (group = 0; group < ai->nr_groups; group++) {
		struct pcpu_group_info *gi = &ai->groups[group];
		void *ptr = areas[group];

		for (i = 0; i < gi->nr_units; i++, ptr += ai->unit_size) {
			if (gi->cpu_map[i] == NR_CPUS) {
				/* unused unit, free whole */
				free_fn(ptr, ai->unit_size);
				continue;
			}
			/* copy and return the unused part */
			memcpy(ptr, __per_cpu_load, ai->static_size);
			free_fn(ptr + size_sum, ai->unit_size - size_sum);
		}
	}

	/* base address is now known, determine group base offsets */
	for (group = 0; group < ai->nr_groups; group++) {
		ai->groups[group].base_offset = areas[group] - base;
	}

	pr_info("Embedded %zu pages/cpu @%p s%zu r%zu d%zu u%zu\n",
		PFN_DOWN(size_sum), base, ai->static_size, ai->reserved_size,
		ai->dyn_size, ai->unit_size);

	rc = pcpu_setup_first_chunk(ai, base);
	goto out_free;

out_free_areas:
	for (group = 0; group < ai->nr_groups; group++)
		if (areas[group])
			free_fn(areas[group],
				ai->groups[group].nr_units * ai->unit_size);
out_free:
	pcpu_free_alloc_info(ai);
	if (areas)
		memblock_free_early(__pa(areas), areas_size);
	return rc;
}

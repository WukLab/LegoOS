/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * mm/percpu.c - percpu memory allocator
 *
 * Copyright (C) 2009		SUSE Linux Products GmbH
 * Copyright (C) 2009		Tejun Heo <tj@kernel.org>
 *
 * This file is released under the GPLv2.
 *
 * This is percpu allocator which can handle both static and dynamic
 * areas.  Percpu areas are allocated in chunks.  Each chunk is
 * consisted of boot-time determined number of units and the first
 * chunk is used for static percpu variables in the kernel image
 * (special boot time alloc/init handling necessary as these areas
 * need to be brought up before allocation services are running).
 * Unit grows as necessary and all units grow or shrink in unison.
 * When a chunk is filled up, another chunk is allocated.
 *
 *  c0                           c1                         c2
 *  -------------------          -------------------        ------------
 * | u0 | u1 | u2 | u3 |        | u0 | u1 | u2 | u3 |      | u0 | u1 | u
 *  -------------------  ......  -------------------  ....  ------------
 *
 * Allocation is done in offset-size areas of single unit space.  Ie,
 * an area of 512 bytes at 6k in c1 occupies 512 bytes at 6k of c1:u0,
 * c1:u1, c1:u2 and c1:u3.  On UMA, units corresponds directly to
 * cpus.  On NUMA, the mapping can be non-linear and even sparse.
 * Percpu access can be done by configuring percpu base registers
 * according to cpu to unit mapping and pcpu_unit_size.
 *
 * There are usually many small percpu allocations many of them being
 * as small as 4 bytes.  The allocator organizes chunks into lists
 * according to free size and tries to allocate from the fullest one.
 * Each chunk keeps the maximum contiguous area size hint which is
 * guaranteed to be equal to or larger than the maximum contiguous
 * area in the chunk.  This helps the allocator not to iterate the
 * chunk maps unnecessarily.
 *
 * Allocation state in each chunk is kept using an array of integers
 * on chunk->map.  A positive value in the map represents a free
 * region and negative allocated.  Allocation inside a chunk is done
 * by scanning this map sequentially and serving the first matching
 * entry.  This is mostly copied from the percpu_modalloc() allocator.
 * Chunks can be determined from the address using the index field
 * in the page struct. The index field contains a pointer to the chunk.
 *
 * To use this allocator, arch code should do the following:
 *
 * - define __addr_to_pcpu_ptr() and __pcpu_ptr_to_addr() to translate
 *   regular address to percpu pointer and back if they need to be
 *   different from the default
 *
 * - use pcpu_setup_first_chunk() during percpu area initialization to
 *   setup the first chunk containing the kernel static percpu area
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/list.h>
#include <lego/acpi.h>
#include <lego/sched.h>
#include <lego/mutex.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/percpu.h>
#include <lego/vmalloc.h>
#include <lego/cpumask.h>
#include <lego/spinlock.h>
#include <lego/nodemask.h>
#include <lego/memblock.h>
#include <asm/numa.h>

#define PCPU_SLOT_BASE_SHIFT		5	/* 1-31 shares the same slot */
#define PCPU_DFL_MAP_ALLOC		16	/* start a map with 16 ents */
#define PCPU_ATOMIC_MAP_MARGIN_LOW	32
#define PCPU_ATOMIC_MAP_MARGIN_HIGH	64
#define PCPU_EMPTY_POP_PAGES_LOW	2
#define PCPU_EMPTY_POP_PAGES_HIGH	4

#ifdef CONFIG_SMP
/* default addr <-> pcpu_ptr mapping, override in asm/percpu.h if necessary */
#define __addr_to_pcpu_ptr(addr)					\
	(void __percpu *)((unsigned long)(addr) -			\
			  (unsigned long)pcpu_base_addr	+		\
			  (unsigned long)__per_cpu_start)
#define __pcpu_ptr_to_addr(ptr)						\
	(void __force *)((unsigned long)(ptr) +				\
			 (unsigned long)pcpu_base_addr -		\
			 (unsigned long)__per_cpu_start)
#else
/* on UP, it's always identity mapped */
#define __addr_to_pcpu_ptr(addr)	(void __percpu *)(addr)
#define __pcpu_ptr_to_addr(ptr)		(void __force *)(ptr)
#endif

struct pcpu_chunk {
	struct list_head	list;		/* linked to pcpu_slot lists */
	int			free_size;	/* free bytes in the chunk */
	int			contig_hint;	/* max contiguous size hint */
	void			*base_addr;	/* base address of this chunk */

	int			map_used;	/* # of map entries used before the sentry */
	int			map_alloc;	/* # of map entries allocated */
	int			*map;		/* allocation map */
	struct list_head	map_extend_list;/* on pcpu_map_extend_chunks */

	void			*data;		/* chunk data */
	int			first_free;	/* no free below this */
	bool			immutable;	/* no [de]population allowed */
	int			nr_populated;	/* # of populated pages */
	unsigned long		populated[];	/* populated bitmap */
};

/* the address of the first chunk which starts with the kernel static area */
void *pcpu_base_addr __read_mostly;

static int pcpu_unit_pages __read_mostly;
static int pcpu_unit_size __read_mostly;
static int pcpu_nr_units __read_mostly;
static int pcpu_atom_size __read_mostly;
static int pcpu_nr_slots __read_mostly;
static size_t pcpu_chunk_struct_size __read_mostly;

static const int *pcpu_unit_map __read_mostly;		/* cpu -> unit */
const unsigned long *pcpu_unit_offsets __read_mostly;	/* cpu -> unit offset */

/* group information, used for vm allocation */
static int pcpu_nr_groups __read_mostly;
static const unsigned long *pcpu_group_offsets __read_mostly;
static const size_t *pcpu_group_sizes __read_mostly;

/* cpus with the lowest and highest unit addresses */
static unsigned int pcpu_low_unit_cpu __read_mostly;
static unsigned int pcpu_high_unit_cpu __read_mostly;

/*
 * Optional reserved chunk.  This chunk reserves part of the first
 * chunk and serves it for reserved allocations.  The amount of
 * reserved offset is in pcpu_reserved_chunk_limit.  When reserved
 * area doesn't exist, the following variables contain NULL and 0
 * respectively.
 */
static struct pcpu_chunk *pcpu_reserved_chunk;
static int pcpu_reserved_chunk_limit;

static struct list_head *pcpu_slot __read_mostly;	/* chunk list slots */

static DEFINE_SPINLOCK(pcpu_lock);	/* all internal data structures */
static DEFINE_MUTEX(pcpu_alloc_mutex);	/* chunk create/destroy, [de]pop, map ext */

/* chunks which need their map areas extended, protected by pcpu_lock */
static LIST_HEAD(pcpu_map_extend_chunks);

/*
 * The number of empty populated pages, protected by pcpu_lock.  The
 * reserved chunk doesn't contribute to the count.
 */
static int pcpu_nr_empty_pop_pages;

/*
 * The first chunk which always exists.  Note that unlike other
 * chunks, this one can be allocated and mapped in several different
 * ways and thus often doesn't live in the vmalloc area.
 */
static struct pcpu_chunk *pcpu_first_chunk;

static int __pcpu_size_to_slot(int size)
{
	int highbit = fls(size);	/* size is in bytes */
	return max(highbit - PCPU_SLOT_BASE_SHIFT + 2, 1);
}

static int pcpu_size_to_slot(int size)
{
	if (size == pcpu_unit_size)
		return pcpu_nr_slots - 1;
	return __pcpu_size_to_slot(size);
}

static int pcpu_chunk_slot(const struct pcpu_chunk *chunk)
{
	if (chunk->free_size < sizeof(int) || chunk->contig_hint < sizeof(int))
		return 0;

	return pcpu_size_to_slot(chunk->free_size);
}

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
 * pcpu_count_occupied_pages - count the number of pages an area occupies
 * @chunk: chunk of interest
 * @i: index of the area in question
 *
 * Count the number of pages chunk's @i'th area occupies.  When the area's
 * start and/or end address isn't aligned to page boundary, the straddled
 * page is included in the count iff the rest of the page is free.
 */
static int pcpu_count_occupied_pages(struct pcpu_chunk *chunk, int i)
{
	int off = chunk->map[i] & ~1;
	int end = chunk->map[i + 1] & ~1;

	if (!PAGE_ALIGNED(off) && i > 0) {
		int prev = chunk->map[i - 1];

		if (!(prev & 1) && prev <= round_down(off, PAGE_SIZE))
			off = round_down(off, PAGE_SIZE);
	}

	if (!PAGE_ALIGNED(end) && i + 1 < chunk->map_used) {
		int next = chunk->map[i + 1];
		int nend = chunk->map[i + 2] & ~1;

		if (!(next & 1) && nend >= round_up(end, PAGE_SIZE))
			end = round_up(end, PAGE_SIZE);
	}

	return max_t(int, PFN_DOWN(end) - PFN_UP(off), 0);
}

/**
 * pcpu_chunk_relocate - put chunk in the appropriate chunk slot
 * @chunk: chunk of interest
 * @oslot: the previous slot it was on
 *
 * This function is called after an allocation or free changed @chunk.
 * New slot according to the changed state is determined and @chunk is
 * moved to the slot.  Note that the reserved chunk is never put on
 * chunk slots.
 *
 * CONTEXT:
 * pcpu_lock.
 */
static void pcpu_chunk_relocate(struct pcpu_chunk *chunk, int oslot)
{
	int nslot = pcpu_chunk_slot(chunk);

	if (chunk != pcpu_reserved_chunk && oslot != nslot) {
		if (oslot < nslot)
			list_move(&chunk->list, &pcpu_slot[nslot]);
		else
			list_move_tail(&chunk->list, &pcpu_slot[nslot]);
	}
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

	/* Units Per Allocation (chunk) ? */
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

/**
 * pcpu_dump_alloc_info - print out information about pcpu_alloc_info
 * @lvl: loglevel
 * @ai: allocation info to dump
 *
 * Print out information about @ai using loglevel @lvl.
 */
static void pcpu_dump_alloc_info(const char *lvl,
				 const struct pcpu_alloc_info *ai)
{
	int group_width = 1, cpu_width = 1, width;
	char empty_str[] = "--------";
	int alloc = 0, alloc_end = 0;
	int group, v;
	int upa, apl;	/* units per alloc, allocs per line */

	v = ai->nr_groups;
	while (v /= 10)
		group_width++;

	v = num_possible_cpus();
	while (v /= 10)
		cpu_width++;
	empty_str[min_t(int, cpu_width, sizeof(empty_str) - 1)] = '\0';

	upa = ai->alloc_size / ai->unit_size;
	width = upa * (cpu_width + 1) + group_width + 3;
	apl = rounddown_pow_of_two(max(60 / width, 1));

	printk("%spcpu-alloc: s%zu r%zu d%zu u%zu alloc=%zu*%zu",
	       lvl, ai->static_size, ai->reserved_size, ai->dyn_size,
	       ai->unit_size, ai->alloc_size / ai->atom_size, ai->atom_size);

	for (group = 0; group < ai->nr_groups; group++) {
		const struct pcpu_group_info *gi = &ai->groups[group];
		int unit = 0, unit_end = 0;

		BUG_ON(gi->nr_units % upa);
		for (alloc_end += gi->nr_units / upa;
		     alloc < alloc_end; alloc++) {
			if (!(alloc % apl)) {
				pr_cont("\n");
				printk("%spcpu-alloc: ", lvl);
			}
			pr_cont("[%0*d] ", group_width, group);

			for (unit_end += upa; unit < unit_end; unit++)
				if (gi->cpu_map[unit] != NR_CPUS)
					pr_cont("%0*d ",
						cpu_width, gi->cpu_map[unit]);
				else
					pr_cont("%s ", empty_str);
		}
	}
	pr_cont("\n");
}

/**
 * pcpu_setup_first_chunk - initialize the first percpu chunk
 * @ai: pcpu_alloc_info describing how to percpu area is shaped
 * @base_addr: mapped address
 *
 * Initialize the first percpu chunk which contains the kernel static
 * perpcu area.  This function is to be called from arch percpu area
 * setup path.
 *
 * @ai contains all information necessary to initialize the first
 * chunk and prime the dynamic percpu allocator.
 *
 * @ai->static_size is the size of static percpu area.
 *
 * @ai->reserved_size, if non-zero, specifies the amount of bytes to
 * reserve after the static area in the first chunk.  This reserves
 * the first chunk such that it's available only through reserved
 * percpu allocation.  This is primarily used to serve module percpu
 * static areas on architectures where the addressing model has
 * limited offset range for symbol relocations to guarantee module
 * percpu symbols fall inside the relocatable range.
 *
 * @ai->dyn_size determines the number of bytes available for dynamic
 * allocation in the first chunk.  The area between @ai->static_size +
 * @ai->reserved_size + @ai->dyn_size and @ai->unit_size is unused.
 *
 * @ai->unit_size specifies unit size and must be aligned to PAGE_SIZE
 * and equal to or larger than @ai->static_size + @ai->reserved_size +
 * @ai->dyn_size.
 *
 * @ai->atom_size is the allocation atom size and used as alignment
 * for vm areas.
 *
 * @ai->alloc_size is the allocation size and always multiple of
 * @ai->atom_size.  This is larger than @ai->atom_size if
 * @ai->unit_size is larger than @ai->atom_size.
 *
 * @ai->nr_groups and @ai->groups describe virtual memory layout of
 * percpu areas.  Units which should be colocated are put into the
 * same group.  Dynamic VM areas will be allocated according to these
 * groupings.  If @ai->nr_groups is zero, a single group containing
 * all units is assumed.
 *
 * The caller should have mapped the first chunk at @base_addr and
 * copied static data to each unit.
 *
 * If the first chunk ends up with both reserved and dynamic areas, it
 * is served by two chunks - one to serve the core static and reserved
 * areas and the other for the dynamic area.  They share the same vm
 * and page map but uses different area allocation map to stay away
 * from each other.  The latter chunk is circulated in the chunk slots
 * and available for dynamic allocation like any other chunks.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int __init pcpu_setup_first_chunk(const struct pcpu_alloc_info *ai,
				  void *base_addr)
{
	static int smap[PERCPU_DYNAMIC_EARLY_SLOTS] __initdata;
	static int dmap[PERCPU_DYNAMIC_EARLY_SLOTS] __initdata;
	size_t dyn_size = ai->dyn_size;
	size_t size_sum = ai->static_size + ai->reserved_size + dyn_size;
	struct pcpu_chunk *schunk, *dchunk = NULL;
	unsigned long *group_offsets;
	size_t *group_sizes;
	unsigned long *unit_off;
	unsigned int cpu;
	int *unit_map;
	int group, unit, i;

#define PCPU_SETUP_BUG_ON(cond)	do {					\
	if (unlikely(cond)) {						\
		pr_emerg("failed to initialize, %s\n", #cond);		\
		pcpu_dump_alloc_info(KERN_EMERG, ai);			\
		BUG();							\
	}								\
} while (0)

	/* sanity checks */
	PCPU_SETUP_BUG_ON(ai->nr_groups <= 0);
#ifdef CONFIG_SMP
	PCPU_SETUP_BUG_ON(!ai->static_size);
	PCPU_SETUP_BUG_ON(offset_in_page(__per_cpu_start));
#endif
	PCPU_SETUP_BUG_ON(!base_addr);
	PCPU_SETUP_BUG_ON(offset_in_page(base_addr));
	PCPU_SETUP_BUG_ON(ai->unit_size < size_sum);
	PCPU_SETUP_BUG_ON(offset_in_page(ai->unit_size));
	PCPU_SETUP_BUG_ON(ai->unit_size < PCPU_MIN_UNIT_SIZE);
	PCPU_SETUP_BUG_ON(ai->dyn_size < PERCPU_DYNAMIC_EARLY_SIZE);

	/* process group information and build config tables accordingly */
	group_offsets = memblock_virt_alloc(ai->nr_groups *
					     sizeof(group_offsets[0]), 0);
	group_sizes = memblock_virt_alloc(ai->nr_groups *
					   sizeof(group_sizes[0]), 0);
	unit_map = memblock_virt_alloc(nr_cpu_ids * sizeof(unit_map[0]), 0);
	unit_off = memblock_virt_alloc(nr_cpu_ids * sizeof(unit_off[0]), 0);

	for (cpu = 0; cpu < nr_cpu_ids; cpu++)
		unit_map[cpu] = UINT_MAX;

	pcpu_low_unit_cpu = NR_CPUS;
	pcpu_high_unit_cpu = NR_CPUS;

	for (group = 0, unit = 0; group < ai->nr_groups; group++, unit += i) {
		const struct pcpu_group_info *gi = &ai->groups[group];

		group_offsets[group] = gi->base_offset;
		group_sizes[group] = gi->nr_units * ai->unit_size;

		for (i = 0; i < gi->nr_units; i++) {
			cpu = gi->cpu_map[i];
			if (cpu == NR_CPUS)
				continue;

			PCPU_SETUP_BUG_ON(cpu >= nr_cpu_ids);
			PCPU_SETUP_BUG_ON(!cpu_possible(cpu));
			PCPU_SETUP_BUG_ON(unit_map[cpu] != UINT_MAX);

			unit_map[cpu] = unit + i;
			unit_off[cpu] = gi->base_offset + i * ai->unit_size;

			/* determine low/high unit_cpu */
			if (pcpu_low_unit_cpu == NR_CPUS ||
			    unit_off[cpu] < unit_off[pcpu_low_unit_cpu])
				pcpu_low_unit_cpu = cpu;
			if (pcpu_high_unit_cpu == NR_CPUS ||
			    unit_off[cpu] > unit_off[pcpu_high_unit_cpu])
				pcpu_high_unit_cpu = cpu;
		}
	}
	pcpu_nr_units = unit;

	for_each_possible_cpu(cpu)
		PCPU_SETUP_BUG_ON(unit_map[cpu] == UINT_MAX);

	/* we're done parsing the input, undefine BUG macro and dump config */
#undef PCPU_SETUP_BUG_ON
	pcpu_dump_alloc_info(KERN_DEBUG, ai);

	pcpu_nr_groups = ai->nr_groups;
	pcpu_group_offsets = group_offsets;
	pcpu_group_sizes = group_sizes;
	pcpu_unit_map = unit_map;
	pcpu_unit_offsets = unit_off;

	/* determine basic parameters */
	pcpu_unit_pages = ai->unit_size >> PAGE_SHIFT;
	pcpu_unit_size = pcpu_unit_pages << PAGE_SHIFT;
	pcpu_atom_size = ai->atom_size;
	pcpu_chunk_struct_size = sizeof(struct pcpu_chunk) +
		BITS_TO_LONGS(pcpu_unit_pages) * sizeof(unsigned long);

	/*
	 * Allocate chunk slots.  The additional last slot is for
	 * empty chunks.
	 */
	pcpu_nr_slots = __pcpu_size_to_slot(pcpu_unit_size) + 2;
	pcpu_slot = memblock_virt_alloc(
			pcpu_nr_slots * sizeof(pcpu_slot[0]), 0);
	for (i = 0; i < pcpu_nr_slots; i++)
		INIT_LIST_HEAD(&pcpu_slot[i]);

	/*
	 * Initialize static chunk.  If reserved_size is zero, the
	 * static chunk covers static area + dynamic allocation area
	 * in the first chunk.  If reserved_size is not zero, it
	 * covers static area + reserved area (mostly used for module
	 * static percpu allocation).
	 */
	schunk = memblock_virt_alloc(pcpu_chunk_struct_size, 0);
	INIT_LIST_HEAD(&schunk->list);
	INIT_LIST_HEAD(&schunk->map_extend_list);
	schunk->base_addr = base_addr;
	schunk->map = smap;
	schunk->map_alloc = ARRAY_SIZE(smap);
	schunk->immutable = true;
	bitmap_fill(schunk->populated, pcpu_unit_pages);
	schunk->nr_populated = pcpu_unit_pages;

	if (ai->reserved_size) {
		schunk->free_size = ai->reserved_size;
		pcpu_reserved_chunk = schunk;
		pcpu_reserved_chunk_limit = ai->static_size + ai->reserved_size;
	} else {
		schunk->free_size = dyn_size;
		dyn_size = 0;			/* dynamic area covered */
	}
	schunk->contig_hint = schunk->free_size;

	schunk->map[0] = 1;
	schunk->map[1] = ai->static_size;
	schunk->map_used = 1;
	if (schunk->free_size)
		schunk->map[++schunk->map_used] = ai->static_size + schunk->free_size;
	schunk->map[schunk->map_used] |= 1;

	/* init dynamic chunk if necessary */
	if (dyn_size) {
		dchunk = memblock_virt_alloc(pcpu_chunk_struct_size, 0);
		INIT_LIST_HEAD(&dchunk->list);
		INIT_LIST_HEAD(&dchunk->map_extend_list);
		dchunk->base_addr = base_addr;
		dchunk->map = dmap;
		dchunk->map_alloc = ARRAY_SIZE(dmap);
		dchunk->immutable = true;
		bitmap_fill(dchunk->populated, pcpu_unit_pages);
		dchunk->nr_populated = pcpu_unit_pages;

		dchunk->contig_hint = dchunk->free_size = dyn_size;
		dchunk->map[0] = 1;
		dchunk->map[1] = pcpu_reserved_chunk_limit;
		dchunk->map[2] = (pcpu_reserved_chunk_limit + dchunk->free_size) | 1;
		dchunk->map_used = 2;
	}

	/* link the first chunk in */
	pcpu_first_chunk = dchunk ?: schunk;
	pcpu_nr_empty_pop_pages +=
		pcpu_count_occupied_pages(pcpu_first_chunk, 1);
	pcpu_chunk_relocate(pcpu_first_chunk, -1);

	/* we're done */
	pcpu_base_addr = base_addr;
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
	 * !***!
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

/*
 * Dynamic Per-CPU Allocation
 */

static void __maybe_unused pcpu_next_unpop(struct pcpu_chunk *chunk,
					   int *rs, int *re, int end)
{
	*rs = find_next_zero_bit(chunk->populated, end, *rs);
	*re = find_next_bit(chunk->populated, end, *rs + 1);
}

static void __maybe_unused pcpu_next_pop(struct pcpu_chunk *chunk,
					 int *rs, int *re, int end)
{
	*rs = find_next_bit(chunk->populated, end, *rs);
	*re = find_next_zero_bit(chunk->populated, end, *rs + 1);
}

/*
 * (Un)populated page region iterators.  Iterate over (un)populated
 * page regions between @start and @end in @chunk.  @rs and @re should
 * be integer variables and will be set to start and end page index of
 * the current region.
 */
#define pcpu_for_each_unpop_region(chunk, rs, re, start, end)		    \
	for ((rs) = (start), pcpu_next_unpop((chunk), &(rs), &(re), (end)); \
	     (rs) < (re);						    \
	     (rs) = (re) + 1, pcpu_next_unpop((chunk), &(rs), &(re), (end)))

#define pcpu_for_each_pop_region(chunk, rs, re, start, end)		    \
	for ((rs) = (start), pcpu_next_pop((chunk), &(rs), &(re), (end));   \
	     (rs) < (re);						    \
	     (rs) = (re) + 1, pcpu_next_pop((chunk), &(rs), &(re), (end)))

/* set the pointer to a chunk in a page struct */
static void pcpu_set_page_chunk(struct page *page, struct pcpu_chunk *pcpu)
{
	page->index = (unsigned long)pcpu;
}

/* obtain pointer to a chunk from a page struct */
__used static struct pcpu_chunk *pcpu_get_page_chunk(struct page *page)
{
	return (struct pcpu_chunk *)page->index;
}

static int __maybe_unused pcpu_page_idx(unsigned int cpu, int page_idx)
{
	return pcpu_unit_map[cpu] * pcpu_unit_pages + page_idx;
}

static unsigned long pcpu_chunk_addr(struct pcpu_chunk *chunk,
				     unsigned int cpu, int page_idx)
{
	return (unsigned long)chunk->base_addr + pcpu_unit_offsets[cpu] +
		(page_idx << PAGE_SHIFT);
}

/**
 * pcpu_mem_zalloc - allocate memory
 * @size: bytes to allocate
 *
 * Allocate @size bytes.  If @size is smaller than PAGE_SIZE,
 * kzalloc() is used; otherwise, vzalloc() is used.  The returned
 * memory is always zeroed.
 *
 * CONTEXT:
 * Does GFP_KERNEL allocation.
 *
 * RETURNS:
 * Pointer to the allocated area on success, NULL on failure.
 */
static void *pcpu_mem_zalloc(size_t size)
{
	/* TODO */
#if 0
	if (size <= PAGE_SIZE)
		return kzalloc(size, GFP_KERNEL);
	else
		return vzalloc(size);
#else
	return kzalloc(size, GFP_KERNEL);
#endif
}

/**
 * pcpu_mem_free - free memory
 * @ptr: memory to free
 *
 * Free @ptr.  @ptr should have been allocated using pcpu_mem_zalloc().
 */
static void pcpu_mem_free(void *ptr)
{
#if 0
	kvfree(ptr);
#else
	kfree(ptr);
#endif
}

static struct pcpu_chunk *pcpu_alloc_chunk(void)
{
	struct pcpu_chunk *chunk;

	chunk = pcpu_mem_zalloc(pcpu_chunk_struct_size);
	if (!chunk)
		return NULL;

	chunk->map = pcpu_mem_zalloc(PCPU_DFL_MAP_ALLOC *
						sizeof(chunk->map[0]));
	if (!chunk->map) {
		pcpu_mem_free(chunk);
		return NULL;
	}

	chunk->map_alloc = PCPU_DFL_MAP_ALLOC;
	chunk->map[0] = 0;
	chunk->map[1] = pcpu_unit_size | 1;
	chunk->map_used = 1;

	INIT_LIST_HEAD(&chunk->list);
	INIT_LIST_HEAD(&chunk->map_extend_list);
	chunk->free_size = pcpu_unit_size;
	chunk->contig_hint = pcpu_unit_size;

	return chunk;
}

static void pcpu_free_chunk(struct pcpu_chunk *chunk)
{
	if (!chunk)
		return;
	pcpu_mem_free(chunk->map);
	pcpu_mem_free(chunk);
}

/**
 * is_kernel_percpu_address - test whether address is from static percpu area
 * @addr: address to test
 *
 * Test whether @addr belongs to in-kernel static percpu area.  Module
 * static percpu areas are not considered.  For those, use
 * is_module_percpu_address().
 *
 * RETURNS:
 * %true if @addr is from in-kernel static percpu area, %false otherwise.
 */
bool is_kernel_percpu_address(unsigned long addr)
{
#ifdef CONFIG_SMP
	const size_t static_size = __per_cpu_end - __per_cpu_start;
	void __percpu *base = __addr_to_pcpu_ptr(pcpu_base_addr);
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		void *start = per_cpu_ptr(base, cpu);

		if ((void *)addr >= start && (void *)addr < start + static_size)
			return true;
        }
#endif
	/* on UP, can't distinguish from other static vars, always false */
	return false;
}

/*
 * Chunk management implementation.
 *
 * To allow different implementations, chunk alloc/free and
 * [de]population are implemented in a separate file which is pulled
 * into this file and compiled together.  The following functions
 * should be implemented.
 *
 * pcpu_populate_chunk		- populate the specified range of a chunk
 * pcpu_create_chunk		- create a new chunk
 * pcpu_destroy_chunk		- destroy a chunk, always preceded by full depop
 * pcpu_addr_to_page		- translate address to physical address
 */
static int pcpu_populate_chunk(struct pcpu_chunk *chunk, int off, int size);
static struct pcpu_chunk *pcpu_create_chunk(void);
static void pcpu_destroy_chunk(struct pcpu_chunk *chunk);
static struct page *pcpu_addr_to_page(void *addr);

#include "percpu-vm.c"

/**
 * per_cpu_ptr_to_phys - convert translated percpu address to physical address
 * @addr: the address to be converted to physical address
 *
 * Given @addr which is dereferenceable address obtained via one of
 * percpu access macros, this function translates it into its physical
 * address.  The caller is responsible for ensuring @addr stays valid
 * until this function finishes.
 *
 * percpu allocator has special setup for the first chunk, which currently
 * supports either embedding in linear address space or vmalloc mapping,
 * and, from the second one, the backing allocator (currently either vm or
 * km) provides translation.
 *
 * The addr can be translated simply without checking if it falls into the
 * first chunk. But the current code reflects better how percpu allocator
 * actually works, and the verification can discover both bugs in percpu
 * allocator itself and per_cpu_ptr_to_phys() callers. So we keep current
 * code.
 *
 * RETURNS:
 * The physical address for @addr.
 */
phys_addr_t per_cpu_ptr_to_phys(void *addr)
{
	void __percpu *base = __addr_to_pcpu_ptr(pcpu_base_addr);
	bool in_first_chunk = false;
	unsigned long first_low, first_high;
	unsigned int cpu;

	/*
	 * The following test on unit_low/high isn't strictly
	 * necessary but will speed up lookups of addresses which
	 * aren't in the first chunk.
	 */
	first_low = pcpu_chunk_addr(pcpu_first_chunk, pcpu_low_unit_cpu, 0);
	first_high = pcpu_chunk_addr(pcpu_first_chunk, pcpu_high_unit_cpu,
				     pcpu_unit_pages);
	if ((unsigned long)addr >= first_low &&
	    (unsigned long)addr < first_high) {
		for_each_possible_cpu(cpu) {
			void *start = per_cpu_ptr(base, cpu);

			if (addr >= start && addr < start + pcpu_unit_size) {
				in_first_chunk = true;
				break;
			}
		}
	}

	if (in_first_chunk) {
		if (!is_vmalloc_addr(addr))
			return __pa(addr);
		else
			return page_to_phys(vmalloc_to_page(addr)) +
			       offset_in_page(addr);
	} else
		return page_to_phys(pcpu_addr_to_page(addr)) +
		       offset_in_page(addr);
}

/**
 * pcpu_need_to_extend - determine whether chunk area map needs to be extended
 * @chunk: chunk of interest
 * @is_atomic: the allocation context
 *
 * Determine whether area map of @chunk needs to be extended.  If
 * @is_atomic, only the amount necessary for a new allocation is
 * considered; however, async extension is scheduled if the left amount is
 * low.  If !@is_atomic, it aims for more empty space.  Combined, this
 * ensures that the map is likely to have enough available space to
 * accomodate atomic allocations which can't extend maps directly.
 *
 * CONTEXT:
 * pcpu_lock.
 *
 * RETURNS:
 * New target map allocation length if extension is necessary, 0
 * otherwise.
 */
static int pcpu_need_to_extend(struct pcpu_chunk *chunk, bool is_atomic)
{
	int margin, new_alloc;

	if (is_atomic) {
		margin = 3;

		if (chunk->map_alloc <
		    chunk->map_used + PCPU_ATOMIC_MAP_MARGIN_LOW) {
			if (list_empty(&chunk->map_extend_list)) {
				list_add_tail(&chunk->map_extend_list,
					      &pcpu_map_extend_chunks);
			}
		}
	} else {
		margin = PCPU_ATOMIC_MAP_MARGIN_HIGH;
	}

	if (chunk->map_alloc >= chunk->map_used + margin)
		return 0;

	new_alloc = PCPU_DFL_MAP_ALLOC;
	while (new_alloc < chunk->map_used + margin)
		new_alloc *= 2;

	return new_alloc;
}

/**
 * pcpu_extend_area_map - extend area map of a chunk
 * @chunk: chunk of interest
 * @new_alloc: new target allocation length of the area map
 *
 * Extend area map of @chunk to have @new_alloc entries.
 *
 * CONTEXT:
 * Does GFP_KERNEL allocation.  Grabs and releases pcpu_lock.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int pcpu_extend_area_map(struct pcpu_chunk *chunk, int new_alloc)
{
	int *old = NULL, *new = NULL;
	size_t old_size = 0, new_size = new_alloc * sizeof(new[0]);
	unsigned long flags;

	new = pcpu_mem_zalloc(new_size);
	if (!new)
		return -ENOMEM;

	/* acquire pcpu_lock and switch to new area map */
	spin_lock_irqsave(&pcpu_lock, flags);

	if (new_alloc <= chunk->map_alloc)
		goto out_unlock;

	old_size = chunk->map_alloc * sizeof(chunk->map[0]);
	old = chunk->map;

	memcpy(new, old, old_size);

	chunk->map_alloc = new_alloc;
	chunk->map = new;
	new = NULL;

out_unlock:
	spin_unlock_irqrestore(&pcpu_lock, flags);

	/*
	 * pcpu_mem_free() might end up calling vfree() which uses
	 * IRQ-unsafe lock and thus can't be called under pcpu_lock.
	 */
	pcpu_mem_free(old);
	pcpu_mem_free(new);

	return 0;
}

/**
 * pcpu_fit_in_area - try to fit the requested allocation in a candidate area
 * @chunk: chunk the candidate area belongs to
 * @off: the offset to the start of the candidate area
 * @this_size: the size of the candidate area
 * @size: the size of the target allocation
 * @align: the alignment of the target allocation
 * @pop_only: only allocate from already populated region
 *
 * We're trying to allocate @size bytes aligned at @align.  @chunk's area
 * at @off sized @this_size is a candidate.  This function determines
 * whether the target allocation fits in the candidate area and returns the
 * number of bytes to pad after @off.  If the target area doesn't fit, -1
 * is returned.
 *
 * If @pop_only is %true, this function only considers the already
 * populated part of the candidate area.
 */
static int pcpu_fit_in_area(struct pcpu_chunk *chunk, int off, int this_size,
			    int size, int align, bool pop_only)
{
	int cand_off = off;

	while (true) {
		int head = ALIGN(cand_off, align) - off;
		int page_start, page_end, rs, re;

		if (this_size < head + size)
			return -1;

		if (!pop_only)
			return head;

		/*
		 * If the first unpopulated page is beyond the end of the
		 * allocation, the whole allocation is populated;
		 * otherwise, retry from the end of the unpopulated area.
		 */
		page_start = PFN_DOWN(head + off);
		page_end = PFN_UP(head + off + size);

		rs = page_start;
		pcpu_next_unpop(chunk, &rs, &re, PFN_UP(off + this_size));
		if (rs >= page_end)
			return head;
		cand_off = re * PAGE_SIZE;
	}
}

/**
 * pcpu_alloc_area - allocate area from a pcpu_chunk
 * @chunk: chunk of interest
 * @size: wanted size in bytes
 * @align: wanted align
 * @pop_only: allocate only from the populated area
 * @occ_pages_p: out param for the number of pages the area occupies
 *
 * Try to allocate @size bytes area aligned at @align from @chunk.
 * Note that this function only allocates the offset.  It doesn't
 * populate or map the area.
 *
 * @chunk->map must have at least two free slots.
 *
 * CONTEXT:
 * pcpu_lock.
 *
 * RETURNS:
 * Allocated offset in @chunk on success, -1 if no matching area is
 * found.
 */
static int pcpu_alloc_area(struct pcpu_chunk *chunk, int size, int align,
			   bool pop_only, int *occ_pages_p)
{
	int oslot = pcpu_chunk_slot(chunk);
	int max_contig = 0;
	int i, off;
	bool seen_free = false;
	int *p;

	for (i = chunk->first_free, p = chunk->map + i; i < chunk->map_used; i++, p++) {
		int head, tail;
		int this_size;

		off = *p;
		if (off & 1)
			continue;

		this_size = (p[1] & ~1) - off;

		head = pcpu_fit_in_area(chunk, off, this_size, size, align,
					pop_only);
		if (head < 0) {
			if (!seen_free) {
				chunk->first_free = i;
				seen_free = true;
			}
			max_contig = max(this_size, max_contig);
			continue;
		}

		/*
		 * If head is small or the previous block is free,
		 * merge'em.  Note that 'small' is defined as smaller
		 * than sizeof(int), which is very small but isn't too
		 * uncommon for percpu allocations.
		 */
		if (head && (head < sizeof(int) || !(p[-1] & 1))) {
			*p = off += head;
			if (p[-1] & 1)
				chunk->free_size -= head;
			else
				max_contig = max(*p - p[-1], max_contig);
			this_size -= head;
			head = 0;
		}

		/* if tail is small, just keep it around */
		tail = this_size - head - size;
		if (tail < sizeof(int)) {
			tail = 0;
			size = this_size - head;
		}

		/* split if warranted */
		if (head || tail) {
			int nr_extra = !!head + !!tail;

			/* insert new subblocks */
			memmove(p + nr_extra + 1, p + 1,
				sizeof(chunk->map[0]) * (chunk->map_used - i));
			chunk->map_used += nr_extra;

			if (head) {
				if (!seen_free) {
					chunk->first_free = i;
					seen_free = true;
				}
				*++p = off += head;
				++i;
				max_contig = max(head, max_contig);
			}
			if (tail) {
				p[1] = off + size;
				max_contig = max(tail, max_contig);
			}
		}

		if (!seen_free)
			chunk->first_free = i + 1;

		/* update hint and mark allocated */
		if (i + 1 == chunk->map_used)
			chunk->contig_hint = max_contig; /* fully scanned */
		else
			chunk->contig_hint = max(chunk->contig_hint,
						 max_contig);

		chunk->free_size -= size;
		*p |= 1;

		*occ_pages_p = pcpu_count_occupied_pages(chunk, i);
		pcpu_chunk_relocate(chunk, oslot);
		return off;
	}

	chunk->contig_hint = max_contig;	/* fully scanned */
	pcpu_chunk_relocate(chunk, oslot);

	/* tell the upper layer that this chunk has no matching area */
	return -1;
}

/**
 * pcpu_free_area - free area to a pcpu_chunk
 * @chunk: chunk of interest
 * @freeme: offset of area to free
 * @occ_pages_p: out param for the number of pages the area occupies
 *
 * Free area starting from @freeme to @chunk.  Note that this function
 * only modifies the allocation map.  It doesn't depopulate or unmap
 * the area.
 *
 * CONTEXT:
 * pcpu_lock.
 */
static void pcpu_free_area(struct pcpu_chunk *chunk, int freeme,
			   int *occ_pages_p)
{
	int oslot = pcpu_chunk_slot(chunk);
	int off = 0;
	unsigned i, j;
	int to_free = 0;
	int *p;

	freeme |= 1;	/* we are searching for <given offset, in use> pair */

	i = 0;
	j = chunk->map_used;
	while (i != j) {
		unsigned k = (i + j) / 2;
		off = chunk->map[k];
		if (off < freeme)
			i = k + 1;
		else if (off > freeme)
			j = k;
		else
			i = j = k;
	}
	BUG_ON(off != freeme);

	if (i < chunk->first_free)
		chunk->first_free = i;

	p = chunk->map + i;
	*p = off &= ~1;
	chunk->free_size += (p[1] & ~1) - off;

	*occ_pages_p = pcpu_count_occupied_pages(chunk, i);

	/* merge with next? */
	if (!(p[1] & 1))
		to_free++;
	/* merge with previous? */
	if (i > 0 && !(p[-1] & 1)) {
		to_free++;
		i--;
		p--;
	}
	if (to_free) {
		chunk->map_used -= to_free;
		memmove(p + 1, p + 1 + to_free,
			(chunk->map_used - i) * sizeof(chunk->map[0]));
	}

	chunk->contig_hint = max(chunk->map[i + 1] - chunk->map[i] - 1, chunk->contig_hint);
	pcpu_chunk_relocate(chunk, oslot);
}

/**
 * pcpu_chunk_populated - post-population bookkeeping
 * @chunk: pcpu_chunk which got populated
 * @page_start: the start page
 * @page_end: the end page
 *
 * Pages in [@page_start,@page_end) have been populated to @chunk.  Update
 * the bookkeeping information accordingly.  Must be called after each
 * successful population.
 */
static void pcpu_chunk_populated(struct pcpu_chunk *chunk,
				 int page_start, int page_end)
{
	int nr = page_end - page_start;

	bitmap_set(chunk->populated, page_start, nr);
	chunk->nr_populated += nr;
	pcpu_nr_empty_pop_pages += nr;
}

/**
 * pcpu_alloc - the percpu allocator
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 * @reserved: allocate from the reserved chunk if available
 * @gfp: allocation flags
 *
 * Allocate percpu area of @size bytes aligned at @align.  If @gfp doesn't
 * contain %GFP_KERNEL, the allocation is atomic.
 *
 * RETURNS:
 * Percpu pointer to the allocated area on success, NULL on failure.
 */
static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved,
				 gfp_t gfp)
{
	static int warn_limit = 10;
	struct pcpu_chunk *chunk;
	const char *err;
	int occ_pages = 0;
	int slot, off, new_alloc, cpu, ret;
	unsigned long flags;
	void __percpu *ptr;
	bool is_atomic = (gfp & GFP_KERNEL) != GFP_KERNEL;

	/*
	 * We want the lowest bit of offset available for in-use/free
	 * indicator, so force >= 16bit alignment and make size even.
	 */
	if (unlikely(align < 2))
		align = 2;

	size = ALIGN(size, 2);

	if (unlikely(!size || size > PCPU_MIN_UNIT_SIZE || align > PAGE_SIZE ||
		     !is_power_of_2(align))) {
		WARN(true, "illegal size (%zu) or align (%zu) for percpu allocation\n",
		     size, align);
		return NULL;
	}

	if (!is_atomic)
		mutex_lock(&pcpu_alloc_mutex);

	spin_lock_irqsave(&pcpu_lock, flags);

restart:
	/* search through normal chunks */
	for (slot = pcpu_size_to_slot(size); slot < pcpu_nr_slots; slot++) {
		list_for_each_entry(chunk, &pcpu_slot[slot], list) {
			if (size > chunk->contig_hint)
				continue;

			new_alloc = pcpu_need_to_extend(chunk, is_atomic);
			if (new_alloc) {
				if (is_atomic)
					continue;
				spin_unlock_irqrestore(&pcpu_lock, flags);
				if (pcpu_extend_area_map(chunk,
							 new_alloc) < 0) {
					err = "failed to extend area map";
					goto fail;
				}
				spin_lock_irqsave(&pcpu_lock, flags);
				/*
				 * pcpu_lock has been dropped, need to
				 * restart cpu_slot list walking.
				 */
				goto restart;
			}

			off = pcpu_alloc_area(chunk, size, align, is_atomic,
					      &occ_pages);
			if (off >= 0)
				goto area_found;
		}
	}

	spin_unlock_irqrestore(&pcpu_lock, flags);

	if (list_empty(&pcpu_slot[pcpu_nr_slots - 1])) {
		chunk = pcpu_create_chunk();
		if (!chunk) {
			err = "failed to allocate new chunk";
			goto fail;
		}

		spin_lock_irqsave(&pcpu_lock, flags);
		pcpu_chunk_relocate(chunk, -1);
	} else {
		spin_lock_irqsave(&pcpu_lock, flags);
	}

	goto restart;

area_found:
	spin_unlock_irqrestore(&pcpu_lock, flags);

	/* populate if not all pages are already there */
	if (!is_atomic) {
		int page_start, page_end, rs, re;

		page_start = PFN_DOWN(off);
		page_end = PFN_UP(off + size);

		pcpu_for_each_unpop_region(chunk, rs, re, page_start, page_end) {
			WARN_ON(chunk->immutable);

			ret = pcpu_populate_chunk(chunk, rs, re);

			spin_lock_irqsave(&pcpu_lock, flags);
			if (ret) {
				pcpu_free_area(chunk, off, &occ_pages);
				err = "failed to populate";
				goto fail_unlock;
			}
			pcpu_chunk_populated(chunk, rs, re);
			spin_unlock_irqrestore(&pcpu_lock, flags);
		}

		mutex_unlock(&pcpu_alloc_mutex);
	}

	if (chunk != pcpu_reserved_chunk)
		pcpu_nr_empty_pop_pages -= occ_pages;

	/* clear the areas and return address relative to base address */
	for_each_possible_cpu(cpu)
		memset((void *)pcpu_chunk_addr(chunk, cpu, 0) + off, 0, size);

	ptr = __addr_to_pcpu_ptr(chunk->base_addr + off);
	return ptr;

fail_unlock:
	spin_unlock_irqrestore(&pcpu_lock, flags);
fail:
	if (!is_atomic && warn_limit) {
		pr_warn("allocation failed, size=%zu align=%zu atomic=%d, %s\n",
			size, align, is_atomic, err);
		dump_stack();
		if (!--warn_limit)
			pr_info("limit reached, disable warning\n");
	}
	if (!is_atomic)
		mutex_unlock(&pcpu_alloc_mutex);
	return NULL;
}

/**
 * __alloc_percpu_gfp - allocate dynamic percpu area
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 * @gfp: allocation flags
 *
 * Allocate zero-filled percpu area of @size bytes aligned at @align.  If
 * @gfp doesn't contain %GFP_KERNEL, the allocation doesn't block and can
 * be called from any context but is a lot more likely to fail.
 *
 * RETURNS:
 * Percpu pointer to the allocated area on success, NULL on failure.
 */
void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
{
	return pcpu_alloc(size, align, false, gfp);
}

/**
 * __alloc_percpu - allocate dynamic percpu area
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 *
 * Equivalent to __alloc_percpu_gfp(size, align, %GFP_KERNEL).
 */
void __percpu *__alloc_percpu(size_t size, size_t align)
{
	return pcpu_alloc(size, align, false, GFP_KERNEL);
}

/**
 * free_percpu - free percpu area
 * @ptr: pointer to area to free
 *
 * Free percpu area @ptr.
 *
 * CONTEXT:
 * Can be called from atomic context.
 */
void free_percpu(void __percpu *ptr)
{
}

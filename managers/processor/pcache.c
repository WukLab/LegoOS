/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Lego Processor Last-Level Cache Management
 */

#define pr_fmt(fmt)  "P$: " fmt

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>
#include <asm/io.h>

#include <processor/include/pcache.h>

static u64 llc_cache_start;
static u64 llc_cache_registered_size;

/* Final used size */
static u64 llc_cache_size;

static u32 llc_cacheline_size = PAGE_SIZE;
static u32 llc_cachemeta_size = CONFIG_PCACHE_METADATA_SIZE;

/* nr_cachelines = nr_cachesets * associativity */
static u64 nr_cachelines;
static u64 nr_cachesets;
static u32 llc_cache_associativity = 1 << CONFIG_PCACHE_ASSOCIATIVITY_SHIFT;

/* pages used by cacheline and metadata */
static u64 nr_pages_cacheline;
static u64 nr_pages_metadata;

/* original physical and ioremap'd virtual address */
static u64 phys_start_cacheline;
static u64 phys_start_metadata;
static u64 virt_start_cacheline;
static u64 virt_start_metadata;

/* Address bits usage */
static u64 nr_bits_cacheline;
static u64 nr_bits_set;
static u64 nr_bits_tag;

static u64 pcache_cacheline_mask;
static u64 pcache_set_mask;
static u64 pcache_tag_mask;

static u64 pcache_way_cache_stride;
static u64 pcache_way_meta_stride;

static inline unsigned long addr2set(unsigned long addr)
{
	return (addr & pcache_set_mask) >> nr_bits_cacheline;
}

/*
 * Walk through all N-way cachelines within a set
 * @addr: the address in question
 * @pa_cache: physical address of the cacheline 
 * @va_cache: virtual address of the cacheline 
 * @va_meta: virtual address of the metadata
 * @way: current way number (maximum is llc_cache_associativity)
 */
#define for_each_way_set(addr, pa_cache, va_cache, va_meta, way)			\
	for (va_cache = (void *)((addr & pcache_set_mask) + virt_start_cacheline),	\
	     pa_cache = (void *)((addr & pcache_set_mask) + phys_start_cacheline),	\
	     va_meta = (void *)(addr2set(addr) + virt_start_metadata), way = 0;		\
	     way < llc_cache_associativity;						\
	     way++,									\
	     pa_cache += pcache_way_cache_stride, 					\
	     va_cache += pcache_way_cache_stride, 					\
	     va_meta += pcache_way_meta_stride)

static int do_pcache_fill(unsigned long vaddr, unsigned long flags, void *pa_cache,
			  void *va_cache, void *va_meta, unsigned int way)
{
	struct p2m_llc_miss_struct payload;
	int ret;
	int i, nr_split = CONFIG_PCACHE_FILL_SPLIT_NR;
	u64 offset, slice;

#ifdef CONFIG_DEBUG_PCACHE_FILL
	pr_info("cpu:%d,pid:%u,va:%#lx,flag:%#lx,p$:%p,v$:%p,vM:%p,way:%u\n",
		smp_processor_id(), current->pid, vaddr, flags, pa_cache, va_cache,
		va_meta, way);
#endif

	payload.pid = current->tgid;
	payload.flags = flags;
	payload.missing_vaddr = vaddr;

	slice = PAGE_SIZE / nr_split;
	for (i = 0; i < nr_split; i++) {
		offset = i * slice;
		payload.offset = offset;

		ret = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_LLC_MISS,
				&payload, sizeof(payload),
				pa_cache + offset, slice, true,
				DEF_NET_TIMEOUT);

		if (unlikely(ret < slice)) {
			if (likely(ret == sizeof(int)))
				/* remote reported error */
				return -(*(int *)va_cache);
			else if (ret < 0)
				/* IB is not available */
				return -EIO;
			else
				WARN(1, "invalid retbuf size: %d\n", ret);
		}
	}

	pcache_mkvalid(va_meta);
	pcache_mkaccessed(va_meta);

	return 0;
}

/*
 * Fill a cacheline given a missing virtual address
 * Return 0 on success, others on failure
 *
 * TODO: sync in SMP
 */
int pcache_fill(unsigned long missing_vaddr, unsigned long flags,
		unsigned long *cache_paddr)
{
	void *pa_cache, *va_cache, *va_meta;
	unsigned int way;
	int ret;

	for_each_way_set(missing_vaddr, pa_cache, va_cache, va_meta, way) {
		if (!pcache_valid(va_meta))
			break;
	}

	if (unlikely(way == llc_cache_associativity)) {
		WARN(1, "Cache eviction needed!\n");
		return -ENOMEM;
	}

	ret = do_pcache_fill(missing_vaddr, flags, pa_cache, va_cache, va_meta, way);
	if (unlikely(ret)) {
		*cache_paddr = 0;
		return ret;
	}

	/* for establishing va->pa mapping */
	*cache_paddr = (unsigned long)pa_cache;
	return 0;
}

static void *find_vameta_by_pacache(void *pa_cache)
{
	u64 strides;
	if (unlikely(!llc_cache_size)) {
		panic("uninitilized cacheline size.\n");	
	}

	strides = ((u64) pa_cache - phys_start_cacheline) / llc_cacheline_size;
	return (void *) (virt_start_metadata + strides * llc_cachemeta_size);
}

/*static void *find_vameta_by_vacache(void *va_cache)
{
	u64 strides;
	if (unlikely(!llc_cacheline_size)) {
		panic("uninitilized cacheline size.\n");
	}

	strides = ((u64) va_cache -  virt_start_cacheline) / llc_cacheline_size;
	return (void *) (virt_start_metadata + strides * llc_cacheline_size);
}*/

/*static void *find_vameta_by_vaddr(unsigned long __user vaddr)
{
	u64 paddr;
	u64 pa_cache;
	//translate vaddr to 
	//???
	pa_cache = round_down(paddr, llc_cacheline_size);
	return find_vameta_by_pacache((void *) pa_cache);	
}*/

int pcache_flush_cacheline_va_user(unsigned long __user vaddr)
{
#define DEBUG_CACHE_TEST

	void *msg;
	u32 len_msg;
	int retval = 0;
	unsigned long __user round_down_vaddr;
	void *va_cacheline;
	void *pa_cache, *va_meta;
	pte_t *pte;

	int err;
	u64 offset = 0;

	struct p2m_flush_payload *payload;
	void *content;

	pte = addr2pte(vaddr);
	if (unlikely(!pte)) {
		panic("Flushing vaddr does not in LLC.\n");
	}

	round_down_vaddr = round_down(vaddr, llc_cacheline_size);
	va_cacheline = (void *) round_down_vaddr;
	pa_cache = (void *) (pte_val(*pte) & PTE_VFN_MASK);
	va_meta = find_vameta_by_pacache(pa_cache);

	/* 
	 * check dirty here or functions calling this.
	 */

	/*if (!pcache_dirty(va_meta)) {
#ifdef DEBUG_CACHE_TEST
		pr_info("cacheline is not dirty, unnecessary to flush.\n");
#endif
		return 0;
	}*/
	
	len_msg = sizeof(struct p2m_flush_payload) + llc_cacheline_size;
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		pr_info("No memory for copying flushing page to ib msg.\n");
		return -ENOMEM;
	}
	
	payload = (struct p2m_flush_payload *) msg;
	content = (void *) (msg + sizeof(struct p2m_flush_payload));
	  
	payload->flush_vaddr = vaddr;
	payload->pid = current->pid;
	payload->llc_cacheline_size = llc_cacheline_size; 

#ifdef DEBUG_CACHE_TEST
	pr_info("pcache_flush_single : vaddr : %#lx\nround_down_vaddr: %#lx\n",
			vaddr, round_down_vaddr);
	pr_info("pa_cache address is %#lx\n", (unsigned long) pa_cache);
#endif
	
	//memcpy(content, (void *) vaddr, llc_cacheline_size);
	err = copy_from_user(content, va_cacheline, llc_cacheline_size);
	if(unlikely(err)) {
		panic("Cannot copy cacheline content.\n");
	}

#ifdef DEBUG_CACHE_TEST
	offset = vaddr - round_down_vaddr;
	pr_info("pcache_flush_single : string from content [%s]\n", (char*) (content+offset));
#endif

	net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_LLC_FLUSH,
			msg, len_msg, &retval, sizeof(retval),
		       	false, DEF_NET_TIMEOUT);

	kfree(msg);
	return retval;
}

/* not used this time */
/*int pcache_flush_cacheline_va_cache(void *va_cache)
{
	void *msg;
	u32 len_msg;
	int retval = 0;

	struct p2m_flush_payload *payload;
	void *content;
	void *va_meta;
	
	va_meta = find_vameta_by_vacache(va_cache);

	if (!pcache_dirty(va_meta)) {
		return retval;
	}

	len_msg = sizeof(struct p2m_flush_payload) + llc_cacheline_size;
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		pr_info("No memory for copying flushing page to ib msg.\n");
		return -ENOMEM;
	}
	
	payload = (struct p2m_flush_payload *) msg;
	content = (void *) (msg + sizeof(struct p2m_flush_payload));
	  
	payload->flush_vaddr = (unsigned long) va_cache; // This should be wrong, should be vaddr of user page.
	payload->pid = current->pid; // This should be wrong, should be the pid current cacheline belongs to
	payload->llc_cacheline_size = llc_cacheline_size;

	
	memcpy(content, va_cache, llc_cacheline_size);

	net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_LLC_FLUSH,
			msg, len_msg, &retval, sizeof(retval),
		       	false, DEF_NET_TIMEOUT);

	kfree(msg);
	return retval;
}*/

/* backdoor syscall for testing pcache flush only */
SYSCALL_DEFINE1(pcache_flush, void __user *, vaddr)
{
	unsigned long __user address;
	address = (unsigned long __user) vaddr;
	return pcache_flush_cacheline_va_user(address);
}

void __init pcache_init(void)
{
	u64 nr_cachelines_per_page, nr_units;
	u64 unit_size;

	if (llc_cache_start == 0 || llc_cache_registered_size == 0)
		panic("Processor cache not registered.");

	nr_cachelines_per_page = PAGE_SIZE / llc_cachemeta_size;
	unit_size = nr_cachelines_per_page * llc_cacheline_size;
	unit_size += PAGE_SIZE;

	/*
	 * nr_cachelines_per_page must already be a power of 2.
	 * We must make nr_units a power of 2, then the total
	 * number of cache lines can be a power of 2, too.
	 */
	nr_units = llc_cache_registered_size / unit_size;
	nr_units = rounddown_pow_of_two(nr_units);

	/* final valid used size */
	llc_cache_size = nr_units * unit_size;

	virt_start_cacheline = (unsigned long)ioremap_cache(llc_cache_start,
							    llc_cache_size);
	if (!virt_start_cacheline) {
		pr_info("fail to ioremap: [%#llx - %#llx]\n", llc_cache_start,
			llc_cache_start + llc_cache_size);
	}

	/*
	 * Clear any stale value
	 * This may happen if running on QEMU.
	 * Not sure about physical machine.
	 */
	memset((void *)virt_start_cacheline, 0, llc_cache_size);

	nr_cachelines = nr_units * nr_cachelines_per_page;
	nr_cachesets = nr_cachelines / llc_cache_associativity;

	nr_pages_cacheline = nr_cachelines;
	nr_pages_metadata = nr_units;

	/* Save physical/virtual starting address */
	phys_start_cacheline = llc_cache_start;
	phys_start_metadata = phys_start_cacheline + nr_pages_cacheline * PAGE_SIZE;
	virt_start_metadata = virt_start_cacheline + nr_pages_cacheline * PAGE_SIZE;

	nr_bits_cacheline = ilog2(llc_cacheline_size);
	nr_bits_set = ilog2(nr_cachesets);
	nr_bits_tag = 64 - nr_bits_cacheline - nr_bits_set;

	pr_info("Processor LLC Configurations:\n");
	pr_info("    PhysStart:         %#llx\n",	llc_cache_start);
	pr_info("    VirtStart:         %#llx\n",	virt_start_cacheline);
	pr_info("    Registered Size:   %#llx\n",	llc_cache_registered_size);
	pr_info("    Actual Used Size:  %#llx\n",	llc_cache_size);
	pr_info("    NR cachelines:     %llu\n",	nr_cachelines);
	pr_info("    Associativity:     %u\n",		llc_cache_associativity);
	pr_info("    NR Sets:           %llu\n",	nr_cachesets);
	pr_info("    Cacheline size:    %u B\n",	llc_cacheline_size);
	pr_info("    Metadata size:     %u B\n",	llc_cachemeta_size);

	pcache_cacheline_mask = (1ULL << nr_bits_cacheline) - 1;
	pcache_set_mask = ((1ULL << (nr_bits_cacheline + nr_bits_set)) - 1) & ~pcache_cacheline_mask;
	pcache_tag_mask = ~((1ULL << (nr_bits_cacheline + nr_bits_set)) - 1);

	pr_info("    NR cacheline bits: %2llu [%2llu - %2llu] %#llx\n",
		nr_bits_cacheline,
		0ULL,
		nr_bits_cacheline - 1,
		pcache_cacheline_mask);
	pr_info("    NR set-index bits: %2llu [%2llu - %2llu] %#llx\n",
		nr_bits_set,
		nr_bits_cacheline,
		nr_bits_cacheline + nr_bits_set - 1,
		pcache_set_mask);
	pr_info("    NR tag bits:       %2llu [%2llu - %2llu] %#llx\n",
		nr_bits_tag,
		nr_bits_cacheline + nr_bits_set,
		nr_bits_cacheline + nr_bits_set + nr_bits_tag - 1,
		pcache_tag_mask);

	pr_info("    NR pages for data: %llu\n",	nr_pages_cacheline);
	pr_info("    NR pages for meta: %llu\n",	nr_pages_metadata);
	pr_info("    Cacheline (pa) range:   [%#18llx - %#18llx]\n",
		phys_start_cacheline, phys_start_metadata - 1);
	pr_info("    Metadata (pa) range:    [%#18llx - %#18llx]\n",
		phys_start_metadata, phys_start_metadata + nr_pages_metadata * PAGE_SIZE - 1);

	pr_info("    Cacheline (va) range:   [%#18llx - %#18llx]\n",
		virt_start_cacheline, virt_start_metadata - 1);
	pr_info("    Metadata (va) range:    [%#18llx - %#18llx]\n",
		virt_start_metadata, virt_start_metadata + nr_pages_metadata * PAGE_SIZE - 1);

	pcache_way_cache_stride = nr_cachesets * llc_cacheline_size;
	pcache_way_meta_stride =  nr_cachesets * llc_cachemeta_size;
	pr_info("    Way cache stride:  %#llx\n", pcache_way_cache_stride);
	pr_info("    Way meta stride:   %#llx\n", pcache_way_meta_stride);
}

/**
 * pcache_range_register
 * @start: physical address of the first byte of the cache
 * @size: size of the cache
 *
 * Register a consecutive physical memory range as the last-level cache for
 * processor component. It is invoked at early boot before everything about
 * memory is initialized. For x86, this is registered during the parsing of
 * memmap=N$N command line option.
 */
int __init pcache_range_register(u64 start, u64 size)
{
	if (WARN_ON(!start && !size))
		return -EINVAL;

	llc_cache_start = start;
	llc_cache_registered_size = size;

	return 0;
}

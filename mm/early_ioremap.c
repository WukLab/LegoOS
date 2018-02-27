/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Provide common bits of early_ioremap() support for architectures needing
 * temporary mappings during boot before ioremap() is available.
 */

#include <asm/fixmap.h>
#include <asm/pgtable.h>

#include <lego/mm.h>
#include <lego/bug.h>
#include <lego/init.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/early_ioremap.h>

int early_ioremap_debug;

static int __init setup_early_ioremap_debug(char *s)
{
	early_ioremap_debug = 1;
	return 0;
}
__setup("early_ioremap_debug", setup_early_ioremap_debug);

static void *prev_map[FIX_BTMAPS_SLOTS] __initdata;
static unsigned long prev_size[FIX_BTMAPS_SLOTS] __initdata;
static unsigned long slot_virt[FIX_BTMAPS_SLOTS] __initdata;

void __init early_ioremap_setup(void)
{
	int i;

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		if (WARN_ON(prev_map[i]))
			break;

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		slot_virt[i] = __fix_to_virt(FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*i);
}

static void __init *
__early_ioremap(resource_size_t phys_addr, unsigned long size, pgprot_t prot)
{
	resource_size_t orig_phys_addr = phys_addr;
	unsigned long offset;
	resource_size_t last_addr;
	unsigned int nrpages;
	enum fixed_addresses idx;
	int i, slot;

	slot = -1;
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++) {
		if (!prev_map[i]) {
			slot = i;
			break;
		}
	}

	if (WARN(slot < 0, "%s(%08llx, %08lx) not found slot",
		 __func__, (u64)phys_addr, size))
		return NULL;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (WARN_ON(!size || last_addr < phys_addr))
		return NULL;

	prev_size[slot] = size;
	/*
	 * Mappings have to be page-aligned
	 */
	offset = offset_in_page(phys_addr);
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr + 1) - phys_addr;

	/*
	 * Mappings have to fit in the FIX_BTMAP area.
	 */
	nrpages = size >> PAGE_SHIFT;
	if (WARN_ON(nrpages > NR_FIX_BTMAPS))
		return NULL;

	/*
	 * Ok, go for it..
	 */
	idx = FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*slot;
	while (nrpages > 0) {
		__early_ioremap_set_fixmap(idx, phys_addr, prot);
		phys_addr += PAGE_SIZE;
		--idx;
		--nrpages;
	}

	if (early_ioremap_debug)
		printk("%s(%08llx, %08lx) [%d] => %08lx + %08lx\n",
	     		__func__, (u64)orig_phys_addr, size, slot, offset, slot_virt[slot]);

	prev_map[slot] = (void *)(offset + slot_virt[slot]);
	return prev_map[slot];
}

void __init early_iounmap(void *addr, unsigned long size)
{
	unsigned long virt_addr;
	unsigned long offset;
	unsigned int nrpages;
	enum fixed_addresses idx;
	int i, slot;

	slot = -1;
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++) {
		if (prev_map[i] == addr) {
			slot = i;
			break;
		}
	}

	if (WARN(slot < 0, "early_iounmap(%p, %08lx) not found slot",
		 addr, size))
		return;

	if (WARN(prev_size[slot] != size,
		 "early_iounmap(%p, %08lx) [%d] size not consistent %08lx",
		 addr, size, slot, prev_size[slot]))
		return;

	virt_addr = (unsigned long)addr;
	if (WARN_ON(virt_addr < fix_to_virt(FIX_BTMAP_BEGIN)))
		return;

	offset = offset_in_page(virt_addr);
	nrpages = PAGE_ALIGN(offset + size) >> PAGE_SHIFT;

	idx = FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*slot;
	while (nrpages > 0) {
		/* clear */
		__early_ioremap_set_fixmap(idx, 0, __pgprot(0));
		--idx;
		--nrpages;
	}
	prev_map[slot] = NULL;

	if (early_ioremap_debug)
		printk("early_iounmap(%p, %08lx) [%d]\n", addr, size, slot);
}

/* Remap an IO device */
void __init *
early_ioremap(resource_size_t phys_addr, unsigned long size)
{
	return __early_ioremap(phys_addr, size, PAGE_KERNEL_IO);
}

/* Remap memory */
void __init *
early_memremap(resource_size_t phys_addr, unsigned long size)
{
	return __early_ioremap(phys_addr, size, PAGE_KERNEL);
}

#define MAX_MAP_CHUNK	(NR_FIX_BTMAPS << PAGE_SHIFT)

void __init copy_from_early_mem(void *dest, phys_addr_t src, unsigned long size)
{
	unsigned long slop, clen;
	char *p;

	while (size) {
		slop = offset_in_page(src);
		clen = size;
		if (clen > MAX_MAP_CHUNK - slop)
			clen = MAX_MAP_CHUNK - slop;
		p = early_memremap(src & PAGE_MASK, clen + slop);
		memcpy(dest, p + slop, clen);
		early_memunmap(p, clen + slop);
		dest += clen;
		src += clen;
		size -= clen;
	}
}

void __init early_memunmap(void *addr, unsigned long size)
{
	early_iounmap((void *)addr, size);
}

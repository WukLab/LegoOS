/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_E820_H_
#define _ASM_X86_E820_H_

#define E820MAP	0x2d0		/* our map */
#define E820MAX	128		/* number of entries in E820MAP */

/*
 * Legacy E820 BIOS limits us to 128 (E820MAX) nodes due to the
 * constrained space in the zeropage.  If we have more nodes than
 * that, and if we've booted off EFI firmware, then the EFI tables
 * passed us from the EFI firmware can list more nodes.  Size our
 * internal memory map tables to have room for these additional
 * nodes, based on up to three entries per node for which the
 * kernel was built: MAX_NUMNODES == (1 << CONFIG_NODES_SHIFT),
 * plus E820MAX, allowing space for the possible duplicate E820
 * entries that might need room in the same arrays, prior to the
 * call to sanitize_e820_map() to remove duplicates.  The allowance
 * of three memory map entries per node is "enough" entries for
 * the initial hardware platform motivating this mechanism to make
 * use of additional EFI map entries.  Future platforms may want
 * to allow more than three entries per node or otherwise refine
 * this size.
 */

#define E820NR	0x1e8		/* # entries in E820MAP */

#define E820_RAM	1
#define E820_RESERVED	2
#define E820_ACPI	3
#define E820_NVS	4
#define E820_UNUSABLE	5
#define E820_PMEM	7

/*
 * This is a non-standardized way to represent ADR or NVDIMM regions that
 * persist over a reboot.  The kernel will ignore their special capabilities
 * unless the CONFIG_X86_PMEM_LEGACY option is set.
 *
 * ( Note that older platforms also used 6 for the same type of memory,
 *   but newer versions switched to 12 as 6 was assigned differently.  Some
 *   time they will learn... )
 */
#define E820_PRAM	12

/*
 * reserved RAM used by kernel itself
 * if CONFIG_INTEL_TXT is enabled, memory of this type will be
 * included in the S3 integrity calculation and so should not include
 * any memory that BIOS might alter over the S3 transition
 */
#define E820_RESERVED_KERN        128

#ifndef __ASSEMBLY__

#include <lego/types.h>
struct e820entry {
	__u64 addr;	/* start of memory segment */
	__u64 size;	/* size of memory segment */
	__u32 type;	/* type of memory segment */
} __attribute__((packed));

struct e820map {
	__u32 nr_map;
	struct e820entry map[E820MAX];
};

extern int e820_any_mapped(u64 start, u64 end, unsigned type);
extern int e820_all_mapped(u64 start, u64 end, unsigned type);

#define ISA_START_ADDRESS	0xa0000
#define ISA_END_ADDRESS		0x100000

#define BIOS_BEGIN		0x000a0000
#define BIOS_END		0x00100000

#define BIOS_ROM_BASE		0xffe00000
#define BIOS_ROM_END		0xffffffff

void __init setup_physical_memory(void);
void __init finish_e820_parsing(void);
void __init e820_fill_memblock(void);
unsigned long __init e820_end_of_ram_pfn(void);

/*
 * Returns true iff the specified range [s,e) is completely contained inside
 * the ISA region.
 */
static inline bool is_ISA_range(u64 s, u64 e)
{
	return s >= ISA_START_ADDRESS && e <= ISA_END_ADDRESS;
}

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_E820_H_ */

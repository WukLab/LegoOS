/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * All kernel used type definitions.
 * Though, I would say typedef is evil.
 */

#ifndef _DISOS_TYPES_H_
#define _DISOS_TYPES_H_

#include <asm/types.h>

#define BITS_PER_LONG		__BITS_PER_LONG
#define BITS_PER_LONG_LONG	__BITS_PER_LONG_LONG

/* Special 64bit data type that is 8-byte aligned */
#define aligned_u64	__u64	__attribute__((aligned(8)))
#define aligned_be64	__be64	__attribute__((aligned(8)))
#define aligned_le64	__le64	__attribute__((aligned(8)))

/*
 * A dma_addr_t can hold any valid DMA address, i.e., any address returned
 * by the DMA API.
 *
 * If the DMA API only uses 32-bit addresses, dma_addr_t need only be 32
 * bits wide.  Bus addresses, e.g., PCI BARs, may be wider than 32 bits,
 * but drivers do memory-mapped I/O to ioremapped kernel virtual addresses,
 * so they don't care about the size of the actual bus addresses.
 */
#ifdef CONFIG_DMA_ADDR_T_64BIT
typedef u64 dma_addr_t;
#else
typedef u32 dma_addr_t;
#endif

#ifdef CONFIG_PHYS_ADDR_T_64BIT
typedef u64 phys_addr_t;
#else
typedef u32 phys_addr_t;
#endif

typedef phys_addr_t resource_size_t;

typedef struct {
	int counter;
} atomic_t;

struct list_head {
	struct list_head *next, *prev;
};

#endif /* _DISOS_TYPES_H_ */

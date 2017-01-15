/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TYPES_H_
#define _LEGO_TYPES_H_

#include <asm/types.h>

#define BITS_PER_LONG		__BITS_PER_LONG
#define BITS_PER_LONG_LONG	__BITS_PER_LONG_LONG

#define BIT(nr)			(1UL << (nr))
#define BIT_ULL(nr)		(1ULL << (nr))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)	(1ULL << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE		8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

/* Special 64bit data type that is 8-byte aligned */
#define aligned_u64	__u64	__attribute__((aligned(8)))
#define aligned_be64	__be64	__attribute__((aligned(8)))
#define aligned_le64	__le64	__attribute__((aligned(8)))

#ifndef __ASSEMBLY__
#include <lego/stddef.h>

typedef int bool;

/*
 * A dma_addr_t can hold any valid DMA address, i.e., any address returned
 * by the DMA API.
 *
 * If the DMA API only uses 32-bit addresses, dma_addr_t need only be 32
 * bits wide.  Bus addresses, e.g., PCI BARs, may be wider than 32 bits,
 * but drivers do memory-mapped I/O to ioremapped kernel virtual addresses,
 * so they don't care about the size of the actual bus addresses.
 */
typedef u64 dma_addr_t;

typedef u64 phys_addr_t;

typedef phys_addr_t resource_size_t;

/*
 * This type is the placeholder for a hardware interrupt number. It has to be
 * big enough to enclose whatever representation is used by a given platform.
 */
typedef unsigned long irq_hw_number_t;

/* Get free page */
typedef unsigned int gfp_t;

/* process id */
typedef int pid_t;

/* clocksource cycle base type */
typedef u64 cycle_t;

typedef struct {
	int counter;
} atomic_t;

struct list_head {
	struct list_head *next, *prev;
};

typedef u64	pgoff_t;

typedef s64	__kernel_time_t;
typedef s64	__kernel_clock_t;
typedef s64	__kernel_suseconds_t;
typedef s32	__kernel_timer_t;
typedef s32	__kernel_clockid_t;

typedef __kernel_time_t		time_t;
typedef __kernel_clock_t	clock_t;

#endif /* __ASSEMBLY__ */
#endif /* _LEGO_TYPES_H_ */

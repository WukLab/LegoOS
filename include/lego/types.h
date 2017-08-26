/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TYPES_H_
#define _LEGO_TYPES_H_

#include <asm/types.h>
#include <lego/compiler.h>

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

#ifdef CONFIG_64BIT
typedef struct {
	long counter;
} atomic64_t;
#endif

struct list_head {
	struct list_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

typedef		__u8		uint8_t;
typedef		__u16		uint16_t;
typedef		__u32		uint32_t;
typedef		__u64		uint64_t;

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#ifdef __CHECK_ENDIAN__
#define __bitwise __bitwise__
#else
#define __bitwise
#endif

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;

/*
 * aligned_u64 should be used in defining kernel<->userspace ABIs to avoid
 * common 32/64-bit compat problems.
 * 64-bit values align to 4-byte boundaries on x86_32 (and possibly other
 * architectures) and to 8-byte boundaries on 64-bit architectures.  The new
 * aligned_64 type enforces 8-byte alignment so that structs containing
 * aligned_64 values have the same alignment on 32-bit and 64-bit architectures.
 * No conversions are necessary between 32-bit user-space and a 64-bit kernel.
 */
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))

typedef long	off_t;

typedef u64	pgoff_t;

typedef s64	__kernel_time_t;
typedef s64	__kernel_clock_t;
typedef s64	__kernel_suseconds_t;
typedef s32	__kernel_timer_t;
typedef s32	__kernel_clockid_t;

typedef struct {
	int	val[2];
} __kernel_fsid_t;

typedef __kernel_suseconds_t	suseconds_t;
typedef __kernel_time_t		time_t;
typedef __kernel_clock_t	clock_t;
typedef __kernel_clockid_t	clockid_t;
typedef unsigned long		uintptr_t;
typedef long long		loff_t;
typedef unsigned short		umode_t;
typedef unsigned		fmode_t;
typedef u32			dev_t;

typedef u32	uid_t;
typedef u32	gid_t;
typedef uid_t	kuid_t;
typedef gid_t	kgid_t;

typedef unsigned long vm_flags_t;

/**
 * struct callback_head - callback structure for use with RCU and task_work
 * @next: next update requests in a list
 * @func: actual update function to call after the grace period.
 */
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
};

#define rcu_head callback_head

#undef __FD_SETSIZE
#define __FD_SETSIZE	1024

typedef struct {
	unsigned long fds_bits[__FD_SETSIZE / (8 * sizeof(long))];
} fd_set;

#endif /* __ASSEMBLY__ */
#endif /* _LEGO_TYPES_H_ */

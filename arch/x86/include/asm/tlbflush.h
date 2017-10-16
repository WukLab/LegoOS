/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_TLBFLUSH_H_
#define _ASM_X86_TLBFLUSH_H_

#include <lego/mm.h>
#include <lego/preempt.h>
#include <lego/cpumask.h>

#define TLB_FLUSH_ALL	-1UL

static inline void __flush_tlb_single(unsigned long addr)
{
	asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

static inline void __flush_tlb_one(unsigned long addr)
{
	__flush_tlb_single(addr);
}

static inline void __flush_tlb(void)
{
	preempt_disable();
	write_cr3(read_cr3());
	preempt_enable();
}

static inline void __flush_tlb_global(void)
{
	/* TODO: CR4 Global and local TLB differences */
	preempt_disable();
	write_cr3(read_cr3());
	preempt_enable();
}

static inline void __flush_tlb_all(void)
{
	if (cpu_has(X86_FEATURE_PGE))
		__flush_tlb_global();
	else
		__flush_tlb();
}

#ifdef CONFIG_SMP

#define local_flush_tlb()	__flush_tlb()

#define flush_tlb_mm(mm)		\
		flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL)

#define flush_tlb_range(mm, start, end) \
		flush_tlb_mm_range(mm, start, end)

void flush_tlb_all(void);
void flush_tlb_current_task(void);
void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start, unsigned long end);
void flush_tlb_kernel_range(unsigned long start, unsigned long end);

void flush_tlb_others(const struct cpumask *cpumask, struct mm_struct *mm,
			unsigned long start, unsigned long end);

#define flush_tlb()	flush_tlb_current_task()

#else
/* "_up" is for UniProcessor.
 *
 * This is a helper for other header functions.  *Not* intended to be called
 * directly.  All global TLB flushes need to either call this, or to bump the
 * vm statistics themselves.
 */
static inline void __flush_tlb_up(void)
{
	__flush_tlb();
}

static inline void flush_tlb_all(void)
{
	__flush_tlb_all();
}

static inline void flush_tlb(void)
{
	__flush_tlb_up();
}

static inline void local_flush_tlb(void)
{
	__flush_tlb_up();
}

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	__flush_tlb_up();
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	__flush_tlb_up();
}

static inline void flush_tlb_mm_range(struct mm_struct *mm,
	   unsigned long start, unsigned long end)
{
	__flush_tlb_up();
}

static inline void flush_tlb_others(const struct cpumask *cpumask,
				   struct mm_struct *mm,
				   unsigned long start,
				   unsigned long end)
{
}

static inline void flush_tlb_kernel_range(unsigned long start,
					  unsigned long end)
{
	flush_tlb_all();
}

#endif

#endif /* _ASM_X86_TLBFLUSH_H_ */

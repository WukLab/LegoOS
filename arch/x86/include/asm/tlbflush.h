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

#include <asm/asm.h>

struct tlb_state {
#ifdef CONFIG_SMP
	struct mm_struct *active_mm;
	int state;
#endif

	/*
	 * Access to this CR4 shadow and to H/W CR4 is protected by
	 * disabling interrupts when modifying either one.
	 */
	unsigned long cr4;
};
DECLARE_PER_CPU_SHARED_ALIGNED(struct tlb_state, cpu_tlbstate);

/* Initialize cr4 shadow for this CPU. */
static inline void cr4_init_shadow(void)
{
	this_cpu_write(cpu_tlbstate.cr4, read_cr4());
}

/* Set in this cpu's CR4. */
static inline void cr4_set_bits(unsigned long mask)
{
	unsigned long cr4;

	cr4 = this_cpu_read(cpu_tlbstate.cr4);
	if ((cr4 | mask) != cr4) {
		cr4 |= mask;
		this_cpu_write(cpu_tlbstate.cr4, cr4);
		write_cr4(cr4);
	}
}

/* Clear in this cpu's CR4. */
static inline void cr4_clear_bits(unsigned long mask)
{
	unsigned long cr4;

	cr4 = this_cpu_read(cpu_tlbstate.cr4);
	if ((cr4 & ~mask) != cr4) {
		cr4 &= ~mask;
		this_cpu_write(cpu_tlbstate.cr4, cr4);
		write_cr4(cr4);
	}
}

/* Read the CR4 shadow. */
static inline unsigned long cr4_read_shadow(void)
{
	return this_cpu_read(cpu_tlbstate.cr4);
}

/*
 * Save some of cr4 feature set we're using (e.g.  Pentium 4MB
 * enable and PPro Global page enable), so that any CPU's that boot
 * up after us can get the correct flags.  This should only be used
 * during boot on the boot cpu.
 */
extern unsigned long mmu_cr4_features;

static inline void cr4_set_bits_and_update_boot(unsigned long mask)
{
	mmu_cr4_features |= mask;
	cr4_set_bits(mask);
}

static inline void __native_flush_tlb_global_irq_disabled(void)
{
	unsigned long cr4;

	cr4 = this_cpu_read(cpu_tlbstate.cr4);
	/* clear PGE */
	write_cr4(cr4 & ~X86_CR4_PGE);
	/* write old PGE again and flush TLBs */
	write_cr4(cr4);
}

#define TLB_FLUSH_ALL	-1UL

static inline void __flush_tlb_single(unsigned long addr)
{
	asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

static inline void __flush_tlb_one(unsigned long addr)
{
	__flush_tlb_single(addr);
}

static inline void __flush_tlb_global(void)
{
	unsigned long flags;

	/*
	 * Read-modify-write to CR4 - protect it from preemption and
	 * from interrupts. (Use the raw variant because this code can
	 * be called from deep inside debugging code.)
	 */
	local_irq_save(flags);
	__native_flush_tlb_global_irq_disabled();
	local_irq_restore(flags);
}

static inline void __flush_tlb(void)
{
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

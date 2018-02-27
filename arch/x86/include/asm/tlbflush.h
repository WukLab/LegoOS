/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

/* Reference: SDM(vol3), sec4.10.4.1 */
static inline void __invpcid(unsigned long pcid, unsigned long addr,
			     unsigned long type)
{
	struct { u64 d[2]; } desc = { { pcid, addr } };

	/*
	 * The memory clobber is because the whole point is to invalidate
	 * stale TLB entries and, especially if we're flushing global
	 * mappings, we don't want the compiler to reorder any subsequent
	 * memory accesses before the TLB flush.
	 *
	 * The hex opcode is invpcid (%ecx), %eax in 32-bit mode and
	 * invpcid (%rcx), %rax in long mode.
	 */
	asm volatile (".byte 0x66, 0x0f, 0x38, 0x82, 0x01"
		      : : "m" (desc), "a" (type), "c" (&desc) : "memory");
}

#define INVPCID_TYPE_INDIV_ADDR		0
#define INVPCID_TYPE_SINGLE_CTXT	1
#define INVPCID_TYPE_ALL_INCL_GLOBAL	2
#define INVPCID_TYPE_ALL_NON_GLOBAL	3

/* Flush all mappings for a given pcid and addr, not including globals. */
static inline void invpcid_flush_one(unsigned long pcid,
				     unsigned long addr)
{
	__invpcid(pcid, addr, INVPCID_TYPE_INDIV_ADDR);
}

/* Flush all mappings for a given PCID, not including globals. */
static inline void invpcid_flush_single_context(unsigned long pcid)
{
	__invpcid(pcid, 0, INVPCID_TYPE_SINGLE_CTXT);
}

/* Flush all mappings, including globals, for all PCIDs. */
static inline void invpcid_flush_all(void)
{
	__invpcid(0, 0, INVPCID_TYPE_ALL_INCL_GLOBAL);
}

/* Flush all mappings for all PCIDs except globals. */
static inline void invpcid_flush_all_nonglobals(void)
{
	__invpcid(0, 0, INVPCID_TYPE_ALL_NON_GLOBAL);
}

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

/*
 * Intel SDM(vol3), Sec4.10.4 Invalidation of TLBs and Paging-Structure Caches:
 * ->
 *   The instruction invalidates all TLB entries (including global entries)
 *   and all entries in all paging-structure caches (for all PCIDs) if
 *   (1) it changes the value of CR4.PGE (If CR4.PGE is changing from 0 to 1,
 *   there were no global TLB entries before the execution; if CR4.PGE is
 *   changing from 1 to 0, there will be no global TLB entries after the
 *   execution.); or
 *   (2) it changes the value of the CR4.PCIDE from 1 to 0.
 */
static inline void __flush_tlb_global_irq_disabled(void)
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

	if (cpu_has(X86_FEATURE_INVPCID)) {
		/*
		 * Using INVPCID is considerably faster than a pair of writes
		 * to CR4 sandwiched inside an IRQ flag save/restore.
		 */
		invpcid_flush_all();
		return;
	}

	/*
	 * Read-modify-write to CR4 - protect it from preemption and
	 * from interrupts. (Use the raw variant because this code can
	 * be called from deep inside debugging code.)
	 */
	local_irq_save(flags);
	__flush_tlb_global_irq_disabled();
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

/*
 * TLB flushing:
 *
 *  - flush_tlb() flushes the current mm struct TLBs
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes a range of kernel pages
 *  - flush_tlb_others(cpumask, mm, start, end) flushes TLBs on other cpus
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

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

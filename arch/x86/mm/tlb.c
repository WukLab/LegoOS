/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/smp.h>
#include <lego/sched.h>
#include <lego/cpumask.h>
#include <lego/profile.h>
#include <asm/tlbflush.h>

DEFINE_PER_CPU_SHARED_ALIGNED(struct tlb_state, cpu_tlbstate) = {
#ifdef CONFIG_SMP
	.active_mm = &init_mm,
	.state = 0,
#endif
	.cr4 = ~0UL,	/* fail hard if we screw up cr4 shadow initialization */
};

struct flush_tlb_info {
	struct mm_struct *flush_mm;
	unsigned long flush_start;
	unsigned long flush_end;
};

/*
 * If CR4.PCIDE=0 (lego's case), the load_cr3 invalidates all TLB entries
 * associated with PCID 0000H except those for global pages.
 *
 * All kernel direct mapped pages are global pages. This at least ensures
 * kernel mapping entries won't go back and forth with respect to TLB.
 */
void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
			struct task_struct *tsk)
{
	unsigned int cpu = smp_processor_id();

	if (likely(prev != next)) {
		cpumask_set_cpu(cpu, mm_cpumask(next));

		/*
		 * Re-load page tables.
		 *
		 * This logic has an ordering constraint:
		 *
		 *  CPU 0: Write to a PTE for 'next'
		 *  CPU 0: load bit 1 in mm_cpumask.  if nonzero, send IPI.
		 *  CPU 1: set bit 1 in next's mm_cpumask
		 *  CPU 1: load from the PTE that CPU 0 writes (implicit)
		 *
		 * We need to prevent an outcome in which CPU 1 observes
		 * the new PTE value and CPU 0 observes bit 1 clear in
		 * mm_cpumask.  (If that occurs, then the IPI will never
		 * be sent, and CPU 1's TLB will contain a stale entry.)
		 *
		 * The bad outcome can occur if either CPU's load is
		 * reordered before that CPU's store, so both CPUs must
		 * execute full barriers to prevent this from happening.
		 *
		 * Thus, switch_mm needs a full barrier between the
		 * store to mm_cpumask and any operation that could load
		 * from next->pgd.  TLB fills are special and can happen
		 * due to instruction fetches or for no reason at all,
		 * and neither LOCK nor MFENCE orders them.
		 * Fortunately, load_cr3() is serializing and gives the
		 * ordering guarantee we need.
		 *
		 * And this is why we re-load cr3 after setting mm_cpumask.
		 */
		load_cr3(next->pgd);

		/*
		 * Stop flush IPIs for the previous mm
		 * Only do so if previous task is still alive
		 */
		if (likely(prev))
			cpumask_clear_cpu(cpu, mm_cpumask(prev));
	} else {
		if (unlikely(!cpumask_test_cpu(cpu, mm_cpumask(next)))) {
			cpumask_set_cpu(cpu, mm_cpumask(next));
			load_cr3(next->pgd);
		}
	}
}

void switch_mm(struct mm_struct *prev, struct mm_struct *next,
	       struct task_struct *tsk)
{
	unsigned long flags;

	local_irq_save(flags);
	switch_mm_irqs_off(prev, next, tsk);
	local_irq_restore(flags);
}

/*
 * TLB flush funcation:
 * Flush the tlb entries if the cpu uses the mm that's being flushed.
 */
static void flush_tlb_func(void *info)
{
	struct flush_tlb_info *f = info;

	if (f->flush_mm != current->mm)
		return;

	if (f->flush_end == TLB_FLUSH_ALL) {
		local_flush_tlb();
	} else {
		unsigned long addr;
		addr = f->flush_start;
		while (addr < f->flush_end) {
			__flush_tlb_single(addr);
			addr += PAGE_SIZE;
		}
	}
}

DEFINE_PROFILE_POINT(flush_tlb_others)

void flush_tlb_others(const struct cpumask *cpumask, struct mm_struct *mm,
		      unsigned long start, unsigned long end)
{
	struct flush_tlb_info info;
	PROFILE_POINT_TIME(flush_tlb_others)

	if (end == 0)
		end = start + PAGE_SIZE;
	info.flush_mm = mm;
	info.flush_start = start;
	info.flush_end = end;

	profile_point_start(flush_tlb_others);
	smp_call_function_many(cpumask, flush_tlb_func, &info, 1);
	profile_point_leave(flush_tlb_others);
}

void flush_tlb_current_task(void)
{
	struct mm_struct *mm = current->mm;

	preempt_disable();

	/* This is an implicit full barrier that synchronizes with switch_mm. */
	local_flush_tlb();

	if (cpumask_any_but(mm_cpumask(mm), smp_processor_id()) < nr_cpu_ids)
		flush_tlb_others(mm_cpumask(mm), mm, 0UL, TLB_FLUSH_ALL);

	preempt_enable();
}

/*
 * See Documentation/x86/tlb.txt for details.  We choose 33
 * because it is large enough to cover the vast majority (at
 * least 95%) of allocations, and is small enough that we are
 * confident it will not cause too much overhead.  Each single
 * flush is about 100 ns, so this caps the maximum overhead at
 * _about_ 3,000 ns.
 *
 * This is in units of pages.
 */
static unsigned long tlb_single_page_flush_ceiling __read_mostly = 33;

void flush_tlb_mm_range(struct mm_struct *mm,
			unsigned long start, unsigned long end)
{
	unsigned long addr;
	/* do a global flush by default */
	unsigned long base_pages_to_flush = TLB_FLUSH_ALL;

	if (end != TLB_FLUSH_ALL)
		base_pages_to_flush = (end - start) >> PAGE_SHIFT;

	preempt_disable();

	/*
	 * Both branches below are implicit full barriers (MOV to CR or
	 * INVLPG) that synchronize with switch_mm.
	 */
	if (base_pages_to_flush > tlb_single_page_flush_ceiling) {
		base_pages_to_flush = TLB_FLUSH_ALL;
		local_flush_tlb();
	} else {
		/* flush range by one by one 'invlpg' */
		for (addr = start; addr < end;	addr += PAGE_SIZE)
			__flush_tlb_single(addr);
	}

	if (base_pages_to_flush == TLB_FLUSH_ALL) {
		start = 0UL;
		end = TLB_FLUSH_ALL;
	}

	if (cpumask_any_but(mm_cpumask(mm), smp_processor_id()) < nr_cpu_ids)
		flush_tlb_others(mm_cpumask(mm), mm, start, end);

	preempt_enable();
}

void profile_tlb_shootdown(void)
{
	static int nr_profile_tlb_shootdown = 0;
	struct cpumask mask;
	u64 start, end;
	int cpu, i;

	pr_info("Profile (#%d) TLB Shootdown at CPU%d ...\n",
		nr_profile_tlb_shootdown++, smp_processor_id());

	pr_info(" FLUSH_ALL #nr_cpus\n");
	cpumask_copy(&mask, cpu_online_mask);
	for_each_online_cpu(cpu) {
		cpumask_clear_cpu(cpu, &mask);
		start = sched_clock();
		flush_tlb_others(&mask, current->mm, 0, TLB_FLUSH_ALL);
		end = sched_clock();

		pr_info(" ... nr_cpus: %3d latency: %9llu ns\n",
			cpumask_weight(&mask), end - start);
	}

	cpumask_copy(&mask, cpu_online_mask);
	cpu = cpumask_next(smp_processor_id(), &mask);
	cpumask_clear(&mask);
	cpumask_set_cpu(cpu, &mask);

	pr_info(" CPU%d -> CPU%d #ceiling=%lu #nr_pages\n",
		smp_processor_id(), cpu, tlb_single_page_flush_ceiling);
	for (i = 1; i <= tlb_single_page_flush_ceiling + 8; i++) {
		/* 0x000000 - 0x100000 is known to be mapped as 4KB */
		start = sched_clock();
		flush_tlb_others(&mask, current->mm, 0, PAGE_SIZE * i);
		end = sched_clock();

		pr_info(" ... nr_pages: %3d latency: %9llu ns\n",
			i, end - start);
	}

	pr_info("Profile TLB Shootdown at CPU%d ... done\n", smp_processor_id());
}

/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/traps.h>
#include <asm/pgtable.h>
#include <asm/current.h>

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/ptrace.h>
#include <lego/memory.h>
#include <lego/uaccess.h>
#include <lego/extable.h>
#include <lego/signal.h>
#include <lego/comp_processor.h>

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found	1: protection fault
 *   bit 1 ==	 0: read access		1: write access
 *   bit 2 ==	 0: kernel-mode access	1: user-mode access
 *   bit 3 ==				1: use of reserved bit detected
 *   bit 4 ==				1: fault was an instruction fetch
 *   bit 5 ==				1: protection keys block access
 */
enum x86_pf_error_code {
	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,
	PF_PK		=		1 << 5,
};

static int fault_in_kernel_space(unsigned long address)
{
	return address >= TASK_SIZE_MAX;
}

static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3() & PHYSICAL_PAGE_MASK);
	pgd_t *pgd = base + pgd_index(address);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	printk("PGD %lx ", pgd_val(*pgd));

	if (!pgd_present(*pgd))
		goto out;

	pud = pud_offset(pgd, address);

	pr_cont("PUD %lx ", pud_val(*pud));
	if (!pud_present(*pud) || pud_large(*pud))
		goto out;

	pmd = pmd_offset(pud, address);

	pr_cont("PMD %lx ", pmd_val(*pmd));
	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);

	pr_cont("PTE %lx", pte_val(*pte));
out:
	pr_cont("\n");
	return;
}

static int spurious_fault_check(unsigned long error_code, pte_t *pte)
{
	if ((error_code & PF_WRITE) && !pte_write(*pte))
		return 0;

	if ((error_code & PF_INSTR) && !pte_exec(*pte))
		return 0;
	/*
	 * Note: We do not do lazy flushing on protection key
	 * changes, so no spurious fault will ever set PF_PK.
	 */
	if ((error_code & PF_PK))
		return 1;

	return 1;
}

/*
 * Handle a spurious fault caused by a stale TLB entry.
 *
 * This allows us to lazily refresh the TLB when increasing the
 * permissions of a kernel page (RO -> RW or NX -> X).  Doing it
 * eagerly is very expensive since that implies doing a full
 * cross-processor TLB flush, even if no stale TLB entries exist
 * on other processors.
 *
 * Spurious faults may only occur if the TLB contains an entry with
 * fewer permission than the page table entry.  Non-present (P = 0)
 * and reserved bit (R = 1) faults are never spurious.
 *
 * There are no security implications to leaving a stale TLB when
 * increasing the permissions on a page.
 *
 * Returns non-zero if a spurious fault was handled, zero otherwise.
 *
 * See Intel Developer's Manual Vol 3 Section 4.10.4.3, bullet 3
 * (Optional Invalidation).
 */
static noinline int
spurious_fault(unsigned long error_code, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret;

	/*
	 * Only writes to RO or instruction fetches from NX may cause
	 * spurious faults.
	 *
	 * These could be from user or supervisor accesses but the TLB
	 * is only lazily flushed after a kernel mapping protection
	 * change, so user accesses are not expected to cause spurious
	 * faults.
	 */
	if (error_code != (PF_WRITE | PF_PROT)
	    && error_code != (PF_INSTR | PF_PROT))
		return 0;

	pgd = init_mm.pgd + pgd_index(address);
	if (!pgd_present(*pgd))
		return 0;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return 0;

	if (pud_large(*pud))
		return spurious_fault_check(error_code, (pte_t *) pud);

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return spurious_fault_check(error_code, (pte_t *) pmd);

	pte = pte_offset_kernel(pmd, address);
	if (!pte_present(*pte))
		return 0;

	ret = spurious_fault_check(error_code, pte);
	if (!ret)
		return 0;

	/*
	 * Make sure we have permissions in PMD.
	 * If not, then there's a bug in the page tables:
	 */
	ret = spurious_fault_check(error_code, (pte_t *) pmd);
	WARN_ONCE(!ret, "PMD has incorrect permission bits\n");

	return ret;
}
static noinline int vmalloc_fault(unsigned long address)
{
	pgd_t *pgd, *pgd_ref;
	pud_t *pud, *pud_ref;
	pmd_t *pmd, *pmd_ref;
	pte_t *pte, *pte_ref;

	/* Make sure we are in vmalloc area: */
	if (!(address >= VMALLOC_START && address < VMALLOC_END))
		return -1;

	/*
	 * Copy kernel mappings over when needed. This can also
	 * happen within a race in page table update. In the later
	 * case just flush:
	 */
	pgd = (pgd_t *)__va(read_cr3()) + pgd_index(address);
	pgd_ref = pgd_offset_k(address);
	if (pgd_none(*pgd_ref))
		return -1;

	if (pgd_none(*pgd)) {
		pgd_set(pgd, *pgd_ref);
	} else {
		BUG_ON(pgd_page_vaddr(*pgd) != pgd_page_vaddr(*pgd_ref));
	}

	/*
	 * Below here mismatches are bugs because these lower tables
	 * are shared:
	 */

	pud = pud_offset(pgd, address);
	pud_ref = pud_offset(pgd_ref, address);
	if (pud_none(*pud_ref))
		return -1;

	if (pud_none(*pud) || pud_pfn(*pud) != pud_pfn(*pud_ref))
		BUG();

	pmd = pmd_offset(pud, address);
	pmd_ref = pmd_offset(pud_ref, address);
	if (pmd_none(*pmd_ref))
		return -1;

	if (pmd_none(*pmd) || pmd_pfn(*pmd) != pmd_pfn(*pmd_ref))
		BUG();

	pte_ref = pte_offset_kernel(pmd_ref, address);
	if (!pte_present(*pte_ref))
		return -1;

	pte = pte_offset_kernel(pmd, address);

	/*
	 * Don't use pte_page here, because the mappings can point
	 * outside mem_map, and the NUMA hash lookup cannot handle
	 * that:
	 */
	if (!pte_present(*pte) || pte_pfn(*pte) != pte_pfn(*pte_ref))
		BUG();

	return 0;
}

static void show_fault_oops(struct pt_regs *regs, unsigned long error_code,
			    unsigned long address)
{
	printk(KERN_ALERT "BUG: unable to handle kernel ");
	if (address < PAGE_SIZE)
		printk(KERN_CONT "NULL pointer dereference");
	else
		printk(KERN_CONT "paging request");

	printk(KERN_CONT   " at %p\n", (void *)address);
	printk(KERN_ALERT "IP: [<%p>] %pS\n", (void *)address, (void *)address);

	dump_pagetable(address);
}

static int die_counter;

int __die(const char *str, struct pt_regs *regs, long err)
{
	printk(KERN_DEFAULT
	       "%s: %04lx [#%d]%s%s%s%s\n", str, err & 0xffff, ++die_counter,
	       IS_ENABLED(CONFIG_PREEMPT)	? " PREEMPT"	: "",
	       IS_ENABLED(CONFIG_SMP)		? " SMP"	: "",
	       IS_ENABLED(CONFIG_COMP_PROCESSOR)? " PROCESSOR"	: "",
	       IS_ENABLED(CONFIG_COMP_MEMORY)	? " MEMORY"	: "");

	show_regs(regs);

	/* Executive summary in case the oops scrolled away */
	printk(KERN_ALERT "RIP ");
	pr_cont(" [<%p>] %pS\n", (void *)regs->ip, (void *)regs->ip);
	printk(" RSP <%016lx>\n", regs->sp);

	return 0;
}

#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)

/*
 * A pgfault from kernel threads, either
 * 1) predefined exception
 * 2) kernel bug
 */
static noinline void
no_context(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address, int signal)
{
	struct task_struct *tsk = current;

	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs, X86_TRAP_PF))
		return;

	/*
	 * Well, kernel bugs!
	 */

	show_fault_oops(regs, error_code, address);

	if (task_stack_end_corrupted(current))
		printk(KERN_EMERG "Thread overran stack, or stack corrupted\n");

	tsk->thread.cr2		= address;
	tsk->thread.trap_nr	= X86_TRAP_PF;
	tsk->thread.error_code	= error_code;

	__die("Oops", regs, error_code);

	/* Executive summary in case the body of the oops scrolled away */
	printk(KERN_DEFAULT "CR2: %016lx\n", address);
	panic("Fatal exception");
}

static void
force_sig_info_fault(int si_signo, int si_code, unsigned long address,
		     struct task_struct *tsk, int fault)
{
	unsigned lsb = 0;
	siginfo_t info;

	info.si_signo	= si_signo;
	info.si_errno	= 0;
	info.si_code	= si_code;
	info.si_addr	= (void __user *)address;
	info.si_addr_lsb = lsb;

	force_sig_info(si_signo, &info, tsk);
}

/*
 * Print out info about fatal segfaults, if the show_unhandled_signals
 * sysctl is set:
 */
static inline void
show_signal_msg(struct pt_regs *regs, unsigned long error_code,
		unsigned long address, struct task_struct *tsk)
{
	printk("%s[%d]: segfault at %#lx ip %p sp %p error %lx",
		tsk->comm, tsk->pid, address,
		(void *)regs->ip, (void *)regs->sp, error_code);

	printk(KERN_CONT "\n");
}

static noinline void
__bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		       unsigned long address, int si_code)
{
	struct task_struct *tsk = current;

	/* User mode accesses just cause a SIGSEGV */
	if (error_code & PF_USER) {
		/*
		 * It's possible to have interrupts off here:
		 */
		local_irq_enable();

		/*
		 * To avoid leaking information about the kernel page table
		 * layout, pretend that user-mode accesses to kernel addresses
		 * are always protection faults.
		 */
		if (address >= TASK_SIZE_MAX)
			error_code |= PF_PROT;

		show_signal_msg(regs, error_code, address, current);

		tsk->thread.cr2		= address;
		tsk->thread.error_code	= error_code;
		tsk->thread.trap_nr	= X86_TRAP_PF;

		force_sig_info_fault(SIGSEGV, si_code, address, tsk, 0);

		return;
	}

	/*
	 * If it comes from kernel space, then there is
	 * user context attached:
	 */
	force_sig_info_fault(SIGSEGV, si_code, address, tsk, 0);
	no_context(regs, error_code, address, SIGSEGV);
}

static noinline void
bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		     unsigned long address)
{
	__bad_area_nosemaphore(regs, error_code, address, SEGV_MAPERR);
}

static void pgtable_bad(struct pt_regs *regs, unsigned long error_code,
			unsigned long address)
{
	struct task_struct *tsk = current;

	tsk = current;

	printk(KERN_ALERT "%s: Corrupted page table at address %lx\n",
	       tsk->comm, address);
	dump_pagetable(address);

	tsk->thread.cr2		= address;
	tsk->thread.trap_nr	= X86_TRAP_PF;
	tsk->thread.error_code	= error_code;

	__die("Bad pagetable", regs, error_code);
	panic("Fatal exception");
}

#if 0
static void user_hlt(void)
{
#if 1
	asm volatile (
		"movq $39, %rax\n\t"
		"syscall\n\t"
		"movq $39, %rax\n\t"
		"syscall\n\t"
	);
#endif
	for (;;)
		cpu_relax();
}
#endif

static inline void __do_page_fault(struct pt_regs *regs, unsigned long address,
				   long error_code)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	pte_t pte;
	pgprot_t pgprot;
	int ret;
	unsigned long cache_paddr;
	unsigned long flags = FAULT_FLAG_KILLABLE | FAULT_FLAG_USER;
	struct mm_struct *mm = current->mm;

	if (error_code & PF_WRITE)
		flags |= FAULT_FLAG_WRITE;
	if (error_code & PF_INSTR)
		flags |= FAULT_FLAG_INSTRUCTION;

	/* fetch cacheline from memory component */
	ret = pcache_fill(address, flags, &cache_paddr);
	if (unlikely(ret))
		panic("pcache fail to handle: ret: %d\n", ret);

	/*
	 * TODO: sync establishing and should sync before sending request
	 * so that request will be only sent once to memory
	 *
	 * establish pgtable mapping
	 */
	pgd = pgd_offset(mm, address);
	pud = pud_alloc(mm, pgd, address);
	if (unlikely(!pud))
		goto oom;
	pmd = pmd_alloc(mm, pud, address);
	if (unlikely(!pmd))
		goto oom;
	ptep = pte_alloc(mm, pmd, address);
	if (unlikely(!ptep))
		goto oom;

	if (!pte_none(*ptep)) {
		dump_pagetable(address);
		panic("BUG");
		return;
	}

	pgprot = PAGE_SHARED_EXEC;
	pte = pfn_pte(cache_paddr >> PAGE_SHIFT, pgprot);
	pte_set(ptep, pte);

	return;
oom:
	panic("oom\n");
}

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 */
dotraplinkage void do_page_fault(struct pt_regs *regs, long error_code)
{
	unsigned long address = read_cr2();

	if (unlikely(fault_in_kernel_space(address))) {
		if (!(error_code & (PF_RSVD | PF_USER | PF_PROT))) {
			if (vmalloc_fault(address) >= 0)
				return;
		}

		/* Can handle a stale RO->RW TLB: */
		if (spurious_fault(error_code, address))
			return;

		bad_area_nosemaphore(regs, error_code, address);
	}

	if (unlikely(error_code & PF_RSVD))
		pgtable_bad(regs, error_code, address);

#ifdef CONFIG_COMP_PROCESSOR
	__do_page_fault(regs, address, error_code);
#else
	bad_area_nosemaphore(regs, error_code, address);
#endif
}

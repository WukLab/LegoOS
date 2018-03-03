/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/msr.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/percpu.h>
#include <asm/pgtable.h>
#include <asm/segment.h>
#include <asm/irq_vectors.h>
#include <asm/processor-flags.h>
#include <lego/linkage.h>
#include <lego/compiler.h>

#define pud_index(x)	(((x) >> PUD_SHIFT) & (PTRS_PER_PUD-1))

L4_PAGE_OFFSET = pgd_index(__PAGE_OFFSET)
L3_PAGE_OFFSET = pud_index(__PAGE_OFFSET)
L4_START_KERNEL = pgd_index(__START_KERNEL_map)
L3_START_KERNEL = pud_index(__START_KERNEL_map)

#define pa(x)	((x) - __START_KERNEL_map)

	.text
	.section ".head.text","ax"
	.code64
ENTRY(startup_64)
	/*
	 * At this point the CPU runs in 64-bit mode CS.L = 1 CS.D = 0,
	 * and an identity mapped page table is loaded. These identity
	 * mapped page tables map [0, 4GB).
	 *
	 * %rsi holds a physical pointer to bootparam structure
	 */

	leaq	__text(%rip), %rbp
	subq	$__text - __START_KERNEL_map, %rbp

	/*
	 * If not relocatable, %rbp = 0
	 * Fixup the physical addresses in the page table
	 */
	addq	%rbp, early_level4_pgt + (L4_START_KERNEL*8)(%rip)

	addq	%rbp, level3_kernel_pgt + (510*8)(%rip)
	addq	%rbp, level3_kernel_pgt + (511*8)(%rip)

	addq	%rbp, level2_fixmap_pgt + (506*8)(%rip)

	/*
	 * Set up the identity mapping for the switchover.  These
	 * entries should *NOT* have the global bit set!  This also
	 * creates a bunch of nonsense entries but that is fine --
	 * it avoids problems around wraparound.
	 */
	leaq	__text(%rip), %rdi
	leaq	early_level4_pgt(%rip), %rbx

	movq	%rdi, %rax
	shrq	$PGDIR_SHIFT, %rax

	leaq	(4096 + _KERNPG_TABLE)(%rbx), %rdx
	movq	%rdx, 0(%rbx,%rax,8)
	movq	%rdx, 8(%rbx,%rax,8)

	addq	$4096, %rdx
	movq	%rdi, %rax
	shrq	$PUD_SHIFT, %rax
	andl	$(PTRS_PER_PUD-1), %eax
	movq	%rdx, 4096(%rbx,%rax,8)
	incl	%eax
	andl	$(PTRS_PER_PUD-1), %eax
	movq	%rdx, 4096(%rbx,%rax,8)

	addq	$8192, %rbx
	movq	%rdi, %rax
	shrq	$PMD_SHIFT, %rdi
	addq	$(__PAGE_KERNEL_LARGE_EXEC & ~_PAGE_GLOBAL), %rax
	leaq	(__end - 1)(%rip), %rcx
	shrq	$PMD_SHIFT, %rcx
	subq	%rdi, %rcx
	incl	%ecx

1:
	andq	$(PTRS_PER_PMD - 1), %rdi
	movq	%rax, (%rbx,%rdi,8)
	incq	%rdi
	addq	$PMD_SIZE, %rax
	decl	%ecx
	jnz	1b

	/*
	 * Fixup the kernel text+data virtual addresses. Note that
	 * we might write invalid pmds, when the kernel is relocated
	 * cleanup_highmap() fixes this up along with the mappings
	 * beyond _end.
	 */
	leaq	level2_kernel_pgt(%rip), %rdi
	leaq	4096(%rdi), %r8
	/* See if it is a valid page table entry */
1:	testb	$1, 0(%rdi)
	jz	2f
	addq	%rbp, 0(%rdi)
	/* Go to the next page */
2:	addq	$8, %rdi
	cmp	%r8, %rdi
	jne	1b

	/* Fixup phys_base */
	addq	%rbp, phys_base(%rip)

	movq	$(early_level4_pgt - __START_KERNEL_map), %rax
	jmp	1f

	/*
	 * This is triky.
	 * Since the above code won't be too big, so the align
	 * actually means the *absolute* offset from the beginning.
	 *
	 * Hence the trampoline code can jump to:
	 *	CONFIG_PHYSICAL_START + SECONDARY_STARTUP_64_ALIGN
	 * directly...
	 */
	.align SECONDARY_STARTUP_64_ALIGN
ENTRY(secondary_startup_64)
	/*
	 * At this point the CPU runs in 64bit mode CS.L = 1 CS.D = 0,
	 * and someone has loaded a mapped page table.
	 *
	 * %rsi holds a physical pointer to real_mode_data.
	 *
	 * We come here either from startup_64 (using physical addresses)
	 * or from trampoline.S (using virtual addresses).
	 *
	 * Using virtual addresses from trampoline.S removes the need
	 * to have any identity mapped pages in the kernel page table
	 * after the boot processor executes this code.
	 */

	movq	$(init_level4_pgt - __START_KERNEL_map), %rax
1:

	/*
	 * Enable PAE mode and PGE
	 *
	 * PAE: must be set before entering IA-32e mode.
	 * PGE: global pages are not flushed from the TLB on a
	 *      task switch or a write to register CR3.
	 */
	movl	$(X86_CR4_PAE | X86_CR4_PGE), %ecx
	movq	%rcx, %cr4

	/* Setup early boot stage 4 level pagetables. */
	addq	phys_base(%rip), %rax

	movq	%rax, %cr3

	/* Ensure I am executing from virtual addresses */
	movq	$1f, %rax
	jmp	*%rax
1:
	/* Check if nx is implemented */
	movl	$0x80000001, %eax
	cpuid
	movl	%edx,%edi

	/* Setup EFER (Extended Feature Enable Register) */
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$_EFER_SCE, %eax	/* Enable System Call */
	btl	$20,%edi		/* No Execute supported? */
	jnc     1f
	btsl	$_EFER_NX, %eax
	btsq	$_PAGE_BIT_NX,early_pmd_flags(%rip)
1:	wrmsr				/* Make changes effective */

	/* Setup cr0 */
#define CR0_STATE	(X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | \
			 X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | \
			 X86_CR0_PG)
	movl	$CR0_STATE, %eax
	/* Make changes effective */
	movq	%rax, %cr0

	/* Setup a boot time stack */
	movq	initial_stack(%rip), %rsp

	/* zero EFLAGS after setting rsp */
	pushq $0
	popfq

	/*
	 * We must switch to a new descriptor in kernel space for the GDT
	 * because soon the kernel won't have access anymore to the userspace
	 * addresses where we're currently running on. We have to do that here
	 * because in 32bit we couldn't load a 64bit linear address.
	 */
	lgdt	early_gdt_descr(%rip)

	/* set up data segments */
	xorl	%eax,%eax
	movl	%eax,%ds
	movl	%eax,%ss
	movl	%eax,%es

	/*
	 * We don't really need to load %fs or %gs, but load them anyway
	 * to kill any stale realmode selectors.  This allows execution
	 * under VT hardware.
	 */
	movl	%eax,%fs
	movl	%eax,%gs

	/* Set up %gs for per-cpu data structure */
	movl	$MSR_GS_BASE, %ecx
	movl	initial_gs(%rip),%eax
	movl	initial_gs+4(%rip),%edx
	wrmsr

	/*
	 * rsi is pointer to real mode structure with interesting info.
	 * pass it to C
	 */
	movq	%rsi, %rdi

	/*
	 * Finally jump to run C code and to be on real kernel address
	 * Since we are running on identity-mapped space we have to jump
	 * to the full 64bit address, this is only possible as indirect
	 * jump.  In addition we need to ensure %cs is set so we make this
	 * a far return.
	 *
	 * Note: do not change to far jump indirect with 64bit offset.
	 *
	 * Intel64 does support 64bit offset.
	 * Software Developer Manual Vol 2: states:
	 *	FF /5 JMP m16:16 Jump far, absolute indirect,
	 *		address given in m16:16
	 *	FF /5 JMP m16:32 Jump far, absolute indirect,
	 *		address given in m16:32.
	 *	REX.W + FF /5 JMP m16:64 Jump far, absolute indirect,
	 *		address given in m16:64.
	 */
	movq	initial_code(%rip),%rax
	pushq	$0		# fake return address to stop unwinder
	pushq	$__KERNEL_CS	# set correct cs
	pushq	%rax		# target address in negative space
	lretq

	.data
	.balign 8

	/*
	 * initial_code, initial_stack, initial_gs differ
	 * for BSP and secondary CPUs. They will be replaced by do_cpu_up()
	 * before booting secondary CPUs.
	 */
GLOBAL(initial_code)
	.quad	x86_64_start_kernel
GLOBAL(initial_stack)
	.quad	init_thread_union+THREAD_SIZE-8
	.word	0

	/*
	 * Make the per-cpu variable work on BSP before
	 * initilizing per-cpu setup.
	 *
	 * This is not a real variable, it is symbol defined
	 * and exported by linker script.
	 */
GLOBAL(initial_gs)
	.quad	INIT_PER_CPU_VAR(per_cpu_head_start)

	.section ".init.text"
ENTRY(early_idt_handler_array)
	# 104(%rsp) %rflags
	#  96(%rsp) %cs
	#  88(%rsp) %rip
	#  80(%rsp) error code
	i = 0
	.rept NUM_EXCEPTION_VECTORS
	.ifeq (EXCEPTION_ERRCODE_MASK >> i) & 1
	pushq	$0		# Dummy error code, to make stack frame uniform
	.endif
	pushq	$i		# 72(%rsp) Vector number
	jmp	early_idt_handler_common
	i = i + 1
	.fill early_idt_handler_array + i*EARLY_IDT_HANDLER_SIZE - ., 1, 0xcc
	.endr
ENDPROC(early_idt_handler_array)

early_idt_handler_common:
	/*
	 * The stack is the hardware frame, an error code or zero, and the
	 * vector number.
	 */
	cld

	incl	early_recursion_flag(%rip)

	/* The vector number is currently in the pt_regs->di slot. */
	pushq	%rsi				/* pt_regs->si */
	movq	8(%rsp), %rsi			/* RSI = vector number */
	movq	%rdi, 8(%rsp)			/* pt_regs->di = RDI */
	pushq	%rdx				/* pt_regs->dx */
	pushq	%rcx				/* pt_regs->cx */
	pushq	%rax				/* pt_regs->ax */
	pushq	%r8				/* pt_regs->r8 */
	pushq	%r9				/* pt_regs->r9 */
	pushq	%r10				/* pt_regs->r10 */
	pushq	%r11				/* pt_regs->r11 */
	pushq	%rbx				/* pt_regs->bx */
	pushq	%rbp				/* pt_regs->bp */
	pushq	%r12				/* pt_regs->r12 */
	pushq	%r13				/* pt_regs->r13 */
	pushq	%r14				/* pt_regs->r14 */
	pushq	%r15				/* pt_regs->r15 */

	cmpq	$14, %rsi			/* Page fault? */
	jnz	10f
	movq	%cr2, %rdi
	call	early_make_pgtable
	andl	%eax,%eax
	jz	20f				/* All good */

10:
	movq	%rsp,%rdi			/* RDI = pt_regs; RSI is already trapnr */
	call	early_fixup_exception

20:
	decl	early_recursion_flag(%rip)
	jmp	restore_regs_and_iret
ENDPROC(early_idt_handler_common)

	.balign 4
GLOBAL(early_recursion_flag)
	.long 0

#define NEXT_PAGE(name) \
	.balign	PAGE_SIZE; \
GLOBAL(name)

/* Automate the creation of 1 to 1 mapping pmd entries */
#define PMDS(START, PERM, COUNT)			\
	i = 0 ;						\
	.rept (COUNT) ;					\
	.quad	(START) + (i << PMD_SHIFT) + (PERM) ;	\
	i = i + 1 ;					\
	.endr

	.section ".init.data","aw",%progbits
NEXT_PAGE(early_level4_pgt)
	.fill	511,8,0
	.quad	level3_kernel_pgt - __START_KERNEL_map + _PAGE_TABLE

NEXT_PAGE(early_dynamic_pgts)
	.fill	512*EARLY_DYNAMIC_PAGE_TABLES,8,0

	.data
NEXT_PAGE(init_level4_pgt)
	.quad   level3_ident_pgt - __START_KERNEL_map + _KERNPG_TABLE
	.org    init_level4_pgt + L4_PAGE_OFFSET*8, 0
	.quad   level3_ident_pgt - __START_KERNEL_map + _KERNPG_TABLE
	.org    init_level4_pgt + L4_START_KERNEL*8, 0
	/* (2^48-(2*1024*1024*1024))/(2^39) = 511 */
	.quad   level3_kernel_pgt - __START_KERNEL_map + _PAGE_TABLE

NEXT_PAGE(level3_ident_pgt)
	.quad	level2_ident_pgt - __START_KERNEL_map + _KERNPG_TABLE
	.fill	511, 8, 0
NEXT_PAGE(level2_ident_pgt)
	/* Since I easily can, map the first 1G.
	 * Don't set NX because code runs from these pages.
	 */
	PMDS(0, __PAGE_KERNEL_IDENT_LARGE_EXEC, PTRS_PER_PMD)

/*
 * 0-510:	.fill L3_START_KERNEL
 * 511:		0xffffffff80000000 - 0xffffffffbffffff
 * 522:		0xffffffffc0000000 - 0xfffffffffffffff
 *
 * 511, which is level2_kernel_pgt, is for kernel code+data+bss
 * 522, which is level2_fixmap_pgt, is for fixmap + early_ioremap
 *
 * Check early_ioremap_init() for more explanations.
 */
NEXT_PAGE(level3_kernel_pgt)
	.fill	L3_START_KERNEL,8,0
	/* (2^48-(2*1024*1024*1024)-((2^39)*511))/(2^30) = 510 */
	.quad	level2_kernel_pgt - __START_KERNEL_map + _KERNPG_TABLE
	.quad	level2_fixmap_pgt - __START_KERNEL_map + _PAGE_TABLE

NEXT_PAGE(level2_kernel_pgt)
	/*
	 * 512 MB kernel mapping. We spend a full page on this pagetable
	 * anyway.
	 *
	 * The kernel code+data+bss must not be bigger than that.
	 *
	 * (NOTE: at +512MB starts the module area, see MODULES_VADDR.
	 *  If you want to increase this then increase MODULES_VADDR
	 *  too.)
	 */
	PMDS(0, __PAGE_KERNEL_LARGE_EXEC,
		KERNEL_IMAGE_SIZE/PMD_SIZE)

/*
 * We will have a bm_pte[] array for early_ioremap, which will
 * be initilized in early_ioremap_init(), so here we do not
 * need to allocate the L1 pgtable for it. But for the permanent
 * fixmap entries, we need to provide a L1 pgtable, which will
 * be the level1_fixmap_pgt.
 *
 * Also because the FIXADDR_TOP starts from vsyscall, which is
 * 0xfffffffff600000, thus we need to fill the level1_fixmap_pgt
 * into the right slot (507)
 */
NEXT_PAGE(level2_fixmap_pgt)
	.fill	506,8,0
	.quad	level1_fixmap_pgt - __START_KERNEL_map + _PAGE_TABLE
	/* 8MB reserved for vsyscalls + a 2MB hole = 4 + 1 entries */
	.fill	5,8,0

NEXT_PAGE(level1_fixmap_pgt)
	.fill	512,8,0

#undef PMDS

	.data
	.align 16
	.globl early_gdt_descr
early_gdt_descr:
	.word	GDT_ENTRIES*8-1
	.quad	INIT_PER_CPU_VAR(cpu_gdt_page)

ENTRY(phys_base)
	/* This must match the first entry in level2_kernel_pgt */
	.quad   0x0000000000000000

	.bss
NEXT_PAGE(empty_zero_page)
	.skip PAGE_SIZE

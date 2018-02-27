/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_IRQ_VECTORS_H_
#define _ASM_X86_IRQ_VECTORS_H_

#include <asm/apic_types.h>

/*
 * There are 256 IDT entries (per CPU - each entry is 8 bytes) which can
 * be defined by LegoOS. They are used as a jump table by the CPU when a
 * given vector is triggered - by a CPU-external, CPU-internal or
 * software-triggered event.
 *
 * LegoOS sets the kernel code address each entry jumps to early during
 * bootup, and never changes them. This is the general layout of the
 * IDT entries:
 *
 *  Vectors   0 ...  31 : system traps and exceptions - hardcoded events
 *  Vectors  32 ... 127 : device interrupts
 *  Vector  128         : legacy int80 syscall interface
 *  Vectors 129 ... INVALIDATE_TLB_VECTOR_START-1 except 204 : device interrupts
 *  Vectors INVALIDATE_TLB_VECTOR_START ... 255 : special interrupts
 *
 * 64-bit x86 has per CPU IDT tables, 32-bit has one shared IDT table.
 *
 * This file enumerates the exact layout of them:
 */

#define NMI_VECTOR			0x02
#define MCE_VECTOR			0x12

/*
 * IDT vectors usable for external interrupt sources start at 0x20.
 * (0x80 is the syscall vector, 0x30-0x3f are for ISA)
 */
#define FIRST_EXTERNAL_VECTOR		0x20

/*
 * We start allocating at 0x21 to spread out vectors evenly between
 * priority levels. (0x80 is the syscall vector)
 */
#define VECTOR_OFFSET_START		1

#define IA32_SYSCALL_VECTOR		0x80

/*
 * Special IRQ vectors used by the SMP architecture, 0xf0-0xff
 *
 *  some of the following vectors are 'rare', they are merged
 *  into a single vector (CALL_FUNCTION_VECTOR) to save vector space.
 *  TLB, reschedule and local APIC vectors are performance-critical.
 */

#define SPURIOUS_APIC_VECTOR		0xff
/*
 * Sanity check
 */
#if ((SPURIOUS_APIC_VECTOR & 0x0F) != 0x0F)
# error SPURIOUS_APIC_VECTOR definition error
#endif

#define ERROR_APIC_VECTOR		0xfe
#define RESCHEDULE_VECTOR		0xfd
#define CALL_FUNCTION_VECTOR		0xfc
#define CALL_FUNCTION_SINGLE_VECTOR	0xfb
#define THERMAL_APIC_VECTOR		0xfa
#define THRESHOLD_APIC_VECTOR		0xf9
#define REBOOT_VECTOR			0xf8

/*
 * Generic system vector for platform specific use
 */
#define X86_PLATFORM_IPI_VECTOR		0xf7

#define POSTED_INTR_WAKEUP_VECTOR	0xf1
/*
 * IRQ work vector:
 */
#define IRQ_WORK_VECTOR			0xf6

#define UV_BAU_MESSAGE			0xf5
#define DEFERRED_ERROR_VECTOR		0xf4

/*
 * Local APIC timer IRQ vector is on a different priority level,
 * to work around the 'lost local interrupt if more than 2 IRQ
 * sources per level' errata.
 */
#define LOCAL_TIMER_VECTOR		0xef

#define NR_VECTORS			 256

#ifdef CONFIG_X86_LOCAL_APIC
#define FIRST_SYSTEM_VECTOR		LOCAL_TIMER_VECTOR
#else
#define FIRST_SYSTEM_VECTOR		NR_VECTORS
#endif

/*
 * Vectors 0x30-0x3f are used for ISA interrupts.
 *   round up to the next 16-vector boundary
 */
#define ISA_IRQ_VECTOR(irq)		(((FIRST_EXTERNAL_VECTOR + 16) & ~15) + irq)

#define FPU_IRQ				  13

/*
 * Size the maximum number of interrupts.
 *
 * If the irq_desc[] array has a sparse layout, we can size things
 * generously - it scales up linearly with the maximum number of CPUs,
 * and the maximum number of IO-APICs, whichever is higher.
 *
 * In other cases we size more conservatively, to not create too large
 * static arrays.
 */

#define NR_IRQS_LEGACY			16

#define CPU_VECTOR_LIMIT		(64 * NR_CPUS)
#define IO_APIC_VECTOR_LIMIT		(32 * MAX_IO_APICS)

#if defined(CONFIG_X86_IO_APIC) && defined(CONFIG_PCI_MSI)
#define NR_IRQS						\
	(CPU_VECTOR_LIMIT > IO_APIC_VECTOR_LIMIT ?	\
		(NR_VECTORS + CPU_VECTOR_LIMIT)  :	\
		(NR_VECTORS + IO_APIC_VECTOR_LIMIT))
#elif defined(CONFIG_X86_IO_APIC)
#define	NR_IRQS				(NR_VECTORS + IO_APIC_VECTOR_LIMIT)
#elif defined(CONFIG_PCI_MSI)
#define NR_IRQS				(NR_VECTORS + CPU_VECTOR_LIMIT)
#else
#define NR_IRQS				NR_IRQS_LEGACY
#endif

#endif /* _ASM_X86_IRQ_VECTORS_H_ */

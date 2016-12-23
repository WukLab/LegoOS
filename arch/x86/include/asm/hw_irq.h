/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_HW_IRQ_H_
#define _ASM_X86_HW_IRQ_H_

#include <asm/ptrace.h>

/* Interrupt handlers registered during init_IRQ */
extern asmlinkage void apic_timer_interrupt(struct pt_regs *regs);
extern asmlinkage void x86_platform_ipi(struct pt_regs *regs);
extern asmlinkage void error_interrupt(struct pt_regs *regs);
extern asmlinkage void spurious_interrupt(struct pt_regs *regs);
extern asmlinkage void irq_work_interrupt(struct pt_regs *regs);
extern asmlinkage void call_function_interrupt(struct pt_regs *regs);
extern asmlinkage void call_function_single_interrupt(struct pt_regs *regs);
extern asmlinkage void reboot_interrupt(struct pt_regs *regs);

extern asmlinkage unsigned int do_IRQ(struct pt_regs *regs);

#ifdef CONFIG_X86_LOCAL_APIC
struct irq_data;
struct msi_desc;

enum irq_alloc_type {
	X86_IRQ_ALLOC_TYPE_IOAPIC = 1,
	X86_IRQ_ALLOC_TYPE_HPET,
	X86_IRQ_ALLOC_TYPE_MSI,
	X86_IRQ_ALLOC_TYPE_MSIX,
	X86_IRQ_ALLOC_TYPE_DMAR,
	X86_IRQ_ALLOC_TYPE_UV,
};

struct irq_alloc_info {
	enum irq_alloc_type	type;
	u32			flags;
	const struct cpumask	*mask;	/* CPU mask for vector allocation */
	union {
		int		unused;
#ifdef	CONFIG_HPET_TIMER
		struct {
			int		hpet_id;
			int		hpet_index;
			void		*hpet_data;
		};
#endif
#ifdef	CONFIG_PCI_MSI
		struct {
			struct pci_dev	*msi_dev;
			irq_hw_number_t	msi_hwirq;
		};
#endif
#ifdef	CONFIG_X86_IO_APIC
		struct {
			int		ioapic_id;
			int		ioapic_pin;
			int		ioapic_node;
			u32		ioapic_trigger : 1;
			u32		ioapic_polarity : 1;
			u32		ioapic_valid : 1;
			struct IO_APIC_route_entry *ioapic_entry;
		};
#endif
	};
};

struct irq_cfg {
	unsigned int		dest_apicid;
	u8			vector;
	u8			old_vector;
};

extern struct irq_cfg *irq_cfg(unsigned int irq);
extern struct irq_cfg *irqd_cfg(struct irq_data *irq_data);
extern void lock_vector_lock(void);
extern void unlock_vector_lock(void);
extern void setup_vector_irq(int cpu);

#ifdef CONFIG_SMP
extern void send_cleanup_vector(struct irq_cfg *);
extern void irq_complete_move(struct irq_cfg *cfg);
#else
static inline void send_cleanup_vector(struct irq_cfg *c) { }
static inline void irq_complete_move(struct irq_cfg *c) { }
#endif

extern void apic_ack_edge(struct irq_data *data);

#else	/* CONFIG_X86_LOCAL_APIC */
static inline void lock_vector_lock(void) {}
static inline void unlock_vector_lock(void) {}
#endif	/* CONFIG_X86_LOCAL_APIC */

#define VECTOR_UNUSED		NULL
#define VECTOR_RETRIGGERED	((void *)~0UL)

typedef struct irq_desc* vector_irq_t[NR_VECTORS];

extern char irq_entries_start[];

#endif /* _ASM_X86_HW_IRQ_H_ */

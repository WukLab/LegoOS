/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/i8259.h>
#include <asm/hw_irq.h>
#include <asm/io_apic.h>
#include <asm/irq_vectors.h>

#include <lego/irq.h>
#include <lego/acpi.h>
#include <lego/bitops.h>
#include <lego/irqdesc.h>
#include <lego/irqchip.h>

/* IRQ2 is cascade interrupt to second interrupt controller */
static struct irqaction irq2 = {
	.handler = no_action,
	.name = "cascade",
	.flags = IRQF_NO_THREAD,
};

DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
	[0 ... NR_VECTORS - 1] = VECTOR_UNUSED,
};

/*
 * Dealing with legacy i8259 chip
 */
static void __init pre_vector_init(void)
{
	struct irq_chip *chip = legacy_pic->chip;
	int i;

	/* init i8259 itself */
	legacy_pic->init(0);

	/* The chip data was set by x86_apic_ioapic_init() */
	for (i = 0; i < nr_legacy_irqs(); i++)
		irq_set_chip_and_handler(i, chip, handle_level_irq);
}

void __init arch_irq_init(void)
{
	int i;

	/*
	 * This function will register x86_vector_domain
	 * and pci_msi_domain. 
	 */
	x86_apic_ioapic_init();

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_LOCAL_APIC)
	/*
	 * An initial setup of the Virtual Wire Mode
	 * BSP LVT0's delivery mode is ExtINT
	 * BSP LVT1's delivery mode is NMI
	 */
	init_bsp_APIC();
#endif

	/*
	 * Set IRQ 0..nr_legacy_irqs()
	 */
	pre_vector_init();

	/*
	 * On cpu 0, Assign ISA_IRQ_VECTOR(irq) to IRQ 0..15.
	 *
	 * If these IRQ's are handled by legacy interrupt-controllers like PIC,
	 * then this configuration will likely be static after the boot. If
	 * these IRQ's are handled by more mordern controllers like IO-APIC,
	 * then this vector space can be freed and re-used dynamically as the
	 * irq's migrate etc.
	 */
	for (i = 0; i < nr_legacy_irqs(); i++)
		per_cpu(vector_irq, 0)[ISA_IRQ_VECTOR(i)] = irq_to_desc(i);

#ifdef CONFIG_SMP
	/*
	 * The reschedule interrupt is a CPU-to-CPU reschedule-helper
	 * IPI, driven by wakeup.
	 */
	alloc_intr_gate(RESCHEDULE_VECTOR, smp__reschedule_interrupt);

	/* IPI for generic function call */
	alloc_intr_gate(CALL_FUNCTION_VECTOR, smp__call_function_interrupt);

	/* IPI for generic single function call */
	alloc_intr_gate(CALL_FUNCTION_SINGLE_VECTOR,
			smp__call_function_single_interrupt);

	/* IPI used for rebooting/stopping */
	alloc_intr_gate(REBOOT_VECTOR, smp__reboot_interrupt);
#endif

	/*
	 * APIC
	 */

#ifdef CONFIG_X86_LOCAL_APIC
	/* self generated IPI for local APIC timer */
	alloc_intr_gate(LOCAL_TIMER_VECTOR, smp__apic_timer_interrupt);

	/* IPI for X86 platform specific use */
	alloc_intr_gate(X86_PLATFORM_IPI_VECTOR, smp__x86_platform_ipi);

	/* IPI vectors for APIC spurious and error interrupts */
	alloc_intr_gate(SPURIOUS_APIC_VECTOR, smp__spurious_interrupt);
	alloc_intr_gate(ERROR_APIC_VECTOR, smp__error_interrupt);
#endif

	/*
	 * Cover the whole vector space, no vector can escape
	 * us. (some of these will be overridden and become
	 * 'special' SMP interrupts)
	 */
	i = FIRST_EXTERNAL_VECTOR;
#ifndef CONFIG_X86_LOCAL_APIC
#define first_system_vector NR_VECTORS
#endif
	for_each_clear_bit_from(i, used_vectors, first_system_vector) {
		set_intr_gate(i, irq_entries_start +
				8 * (i - FIRST_EXTERNAL_VECTOR));
	}

#ifdef CONFIG_X86_LOCAL_APIC
	for_each_clear_bit_from(i, used_vectors, NR_VECTORS) {
		set_intr_gate(i, smp__spurious_interrupt);
	}
#endif

	if (!acpi_ioapic && nr_legacy_irqs())
		setup_irq(2, &irq2);
}

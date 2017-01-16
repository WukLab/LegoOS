/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/err.h>
#include <lego/smp.h>
#include <lego/irq.h>
#include <lego/irqdesc.h>
#include <lego/kernel.h>

#include <asm/apic.h>
#include <asm/ptrace.h>
#include <asm/hw_irq.h>

/* TODO Per-CPU */
struct pt_regs *irq_regs[NR_CPUS];

struct pt_regs *get_irq_regs(void)
{
	int cpu = smp_processor_id();

	BUG_ON(!cpu_online(cpu));
	return irq_regs[cpu];
}

struct pt_regs *set_irq_regs(struct pt_regs *new_regs)
{
	int cpu = smp_processor_id();
	struct pt_regs *old_regs;

	old_regs = get_irq_regs();
	irq_regs[cpu] = new_regs;

	return old_regs;
}

/*
 * 'what should we do if we get a hw irq event on an illegal vector'.
 * each architecture has to answer this themselves.
 */
void ack_bad_irq(unsigned int irq)
{
	pr_err("unexpected IRQ trap at vector %02x\n", irq);

	/*
	 * Currently unexpected vectors happen only on SMP and APIC.
	 * We _must_ ack these because every local APIC has only N
	 * irq slots per priority level, and a 'hanging, unacked' IRQ
	 * holds up an irq slot - in excessive cases (when multiple
	 * unexpected vectors occur) that might lock up the APIC
	 * completely.
	 * But only ack when the APIC is enabled -AK
	 */
	ack_APIC_irq();
}

/**
 * do_IRQ	-	Handles all normal device IRQ's
 *
 * do_IRQ is embedded in irq_entries_start[] array.
 * And handle all kinds of interrupts from devices.
 *
 * (The special SMP cross-CPU interrupts have their own
 * specific handlers.)
 */
asmlinkage __visible unsigned int
do_IRQ(struct pt_regs *regs)
{
	unsigned int vector;
	struct irq_desc *desc;
	struct irq_desc **vector_irq;
	struct pt_regs *old_regs = set_irq_regs(regs);

	/* Pushed in the prologue */
	vector = ~regs->orig_ax;

	vector_irq = per_cpu_vector_irq(smp_processor_id());
	desc = vector_irq[vector];

	pr_info("%s: vector %u\n", __func__, vector);

	if (IS_ERR_OR_NULL(desc)) {
		ack_APIC_irq();

		if (desc != VECTOR_RETRIGGERED) {
			pr_emerg("%s: cpu: %d vector: %d "
				"no irq handler for vector\n",
				__func__, smp_processor_id(), vector);
		}
		return 1;
	}

	desc->handle_irq(desc);

	set_irq_regs(old_regs);
	return 0;
}

asmlinkage __visible void
x86_platform_ipi(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	pr_info("x86_platform_ipi\n");

	set_irq_regs(old_regs);
}

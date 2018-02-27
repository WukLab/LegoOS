/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/err.h>
#include <lego/smp.h>
#include <lego/irq.h>
#include <lego/kernel.h>
#include <lego/percpu.h>
#include <lego/irqdesc.h>

#include <asm/apic.h>
#include <asm/ptrace.h>
#include <asm/hw_irq.h>

DEFINE_PER_CPU(struct pt_regs *, irq_regs);

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
	struct pt_regs *old_regs = set_irq_regs(regs);
	struct irq_desc * desc;
	/* high bit used in ret_from_ code  */
	unsigned vector = ~regs->orig_ax;

	desc = __this_cpu_read(vector_irq[vector]);

	if (IS_ERR_OR_NULL(desc)) {
		ack_APIC_irq();

		if (desc != VECTOR_RETRIGGERED) {
			pr_emerg("%s: cpu: %d vector: %d "
				"no irq handler for vector\n",
				__func__, smp_processor_id(), vector);
		} else {
			__this_cpu_write(vector_irq[vector], VECTOR_UNUSED);
		}
		set_irq_regs(old_regs);
		return 1;
	}

	/* Now call the chained handlers... */
	desc->handle_irq(desc);

	set_irq_regs(old_regs);
	return 1;
}

asmlinkage __visible void
x86_platform_ipi(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	pr_info("x86_platform_ipi\n");

	set_irq_regs(old_regs);
}

/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/ipi.h>
#include <asm/smp.h>
#include <asm/apic.h>
#include <asm/hw_irq.h>
#include <asm/ptrace.h>

#include <lego/sched.h>
#include <lego/kernel.h>

asmlinkage __visible void
reboot_interrupt(struct pt_regs *regs)
{
	ack_APIC_irq();
	pr_info("CPU(%d) PID(%d) in %s() IPI handler\n",
		smp_processor_id(), current->pid, __func__);

	local_irq_disable();
	set_cpu_online(smp_processor_id(), false);
	for (;;)
		hlt();
}

asmlinkage __visible void
call_function_single_interrupt(struct pt_regs *regs)
{
	ack_APIC_irq();
	pr_info("CPU(%d) PID(%d) in %s() IPI handler\n",
		smp_processor_id(), current->pid, __func__);
}

asmlinkage __visible void
call_function_interrupt(struct pt_regs *regs)
{
	ack_APIC_irq();
	pr_info("CPU(%d) PID(%d) in %s() IPI handler\n",
		smp_processor_id(), current->pid, __func__);
}

/* Handler for RESCHEDULE_VECTOR */
asmlinkage __visible void
reschedule_interrupt(struct pt_regs *regs)
{
	ack_APIC_irq();
	scheduler_ipi();
	pr_info("CPU(%d) PID(%d) in %s() IPI handler\n",
		smp_processor_id(), current->pid, __func__);
}

/*
 * this function sends a 'reschedule' IPI to another CPU.
 * it goes straight through and wastes no time serializing
 * anything. Worst case is that we lose a reschedule ...
 */
static void native_smp_send_reschedule(int cpu)
{
	if (unlikely(!cpu_online(cpu))) {
		WARN_ON(1);
		return;
	}
	apic->send_IPI_mask(cpumask_of(cpu), RESCHEDULE_VECTOR);
}

static void native_stop_other_cpus(int wait)
{
	if (num_online_cpus() > 1)
		apic->send_IPI_allbutself(REBOOT_VECTOR);
}

void native_send_call_func_single_ipi(int cpu)
{
	apic->send_IPI_mask(cpumask_of(cpu), CALL_FUNCTION_SINGLE_VECTOR);
}

void native_send_call_func_ipi(const struct cpumask *mask)
{
	cpumask_var_t allbutself;

	cpumask_copy(allbutself, cpu_online_mask);
	cpumask_clear_cpu(smp_processor_id(), allbutself);

	if (cpumask_equal(mask, allbutself))
		apic->send_IPI_allbutself(CALL_FUNCTION_VECTOR);
	else
		apic->send_IPI_mask(mask, CALL_FUNCTION_VECTOR);
}

struct smp_ops smp_ops = {
	.smp_send_reschedule		= native_smp_send_reschedule,

	.stop_other_cpus		= native_stop_other_cpus,

	.send_call_func_ipi		= native_send_call_func_ipi,
	.send_call_func_single_ipi	= native_send_call_func_single_ipi,
};

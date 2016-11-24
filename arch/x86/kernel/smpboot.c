/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/ipi.h>
#include <asm/numa.h>
#include <asm/apic.h>
#include <asm/setup.h>
#include <asm/bootparam.h>
#include <asm/trampoline.h>

#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/nodemask.h>
#include <lego/early_ioremap.h>

unsigned int trampoline_base;
unsigned int trampoline_size;

/*
 * Copy trampoline code to below 1MB, prepare the
 * playground for secondary CPUs.
 */
void __init copy_trampoline_code(void)
{
	void *dst;

	trampoline_base = boot_params.trampoline_base;
	trampoline_size = (unsigned int)((void *)&trampoline_end - (void *)&trampoline_start);

	dst = early_ioremap(trampoline_base, trampoline_size);
	if (!dst)
		panic("fail to copy trampoline");
	memcpy(dst, &trampoline_start, trampoline_size);
	early_iounmap(dst, trampoline_size);

	printk("Trampoline: [%p - %p] -> [%#x - %#x]\n",
		&trampoline_start, &trampoline_end,
		trampoline_base, trampoline_base + trampoline_size);
}

/*
 * Wakeup secondary CPUs or application CPUs via INIT
 */
static int wakeup_cpu_via_init(int phys_apicid, unsigned long start_ip)
{
	unsigned long send_status = 0, accept_status = 0;
	int num_starts, j;

	/*
	 * Turn INIT on target chip
	 */
	/*
	 * Send IPI
	 */
	apic_icr_write(APIC_INT_LEVELTRIG | APIC_INT_ASSERT | APIC_DM_INIT,
		       phys_apicid);

	pr_debug("Waiting for send to finish...\n");
	send_status = safe_apic_wait_icr_idle();

	//udelay(init_udelay);

	pr_debug("Deasserting INIT\n");

	/* Target chip */
	/* Send IPI */
	apic_icr_write(APIC_INT_LEVELTRIG | APIC_DM_INIT, phys_apicid);

	pr_debug("Waiting for send to finish...\n");
	send_status = safe_apic_wait_icr_idle();

	/*
	 * Should we send STARTUP IPIs ?
	 *
	 * Determine this based on the APIC version.
	 * If we don't have an integrated APIC, don't send the STARTUP IPIs.
	 */
	if (APIC_INTEGRATED(boot_cpu_apic_version))
		num_starts = 2;
	else
		num_starts = 0;

	/*
	 * Run STARTUP IPI loop.
	 */
	pr_debug("#startup loops: %d\n", num_starts);

	for (j = 1; j <= num_starts; j++) {
		pr_debug("Sending STARTUP #%d\n", j);
		apic_read(APIC_ESR);
		pr_debug("After apic_write\n");

		/*
		 * STARTUP IPI
		 */

		/* Target chip */
		/* Boot on the stack */
		/* Kick the second */
		apic_icr_write(APIC_DM_STARTUP | (start_ip >> 12),
			       phys_apicid);

		/*
		 * Give the other CPU some time to accept the IPI.
		 */
		//if (init_udelay == 0)
		//	udelay(10);
		//else
		//	udelay(300);

		pr_debug("Startup point 1\n");

		pr_debug("Waiting for send to finish...\n");
		send_status = safe_apic_wait_icr_idle();

		/*
		 * Give the other CPU some time to accept the IPI.
		 */
		//if (init_udelay == 0)
		//	udelay(10);
		//else
		//	udelay(200);

		accept_status = (apic_read(APIC_ESR) & 0xEF);
		if (send_status || accept_status)
			break;
	}
	pr_debug("After Startup\n");

	if (send_status)
		pr_err("APIC never delivered???\n");
	if (accept_status)
		pr_err("APIC delivery error (%lx)\n", accept_status);

	return (send_status | accept_status);
}

static int do_cpu_up(int apicid, int cpu)
{
	unsigned long start_ip = trampoline_base;

	wakeup_cpu_via_init(apicid, start_ip);

	return 0;
}

int native_cpu_up(int cpu)
{
	int ret;
	int apicid = cpu_to_apicid(cpu);

	ret = do_cpu_up(apicid, cpu);

	return 0;
}

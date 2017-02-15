/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

#include <lego/sched.h>
#include <lego/delay.h>
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
 * The Multiprocessor Specification 1.4 (1997) example code suggests
 * that there should be a 10ms delay between the BSP asserting INIT
 * and de-asserting INIT, when starting a remote processor.
 * But that slows boot and resume on modern processors, which include
 * many cores and don't require that delay.
 *
 * Modern processor families are quirked to remove the delay entirely.
 */
#define UDELAY_10MS_DEFAULT 10000

static unsigned int init_udelay = UDELAY_10MS_DEFAULT;

static void __init smp_quirk_init_udelay(void)
{
	/* if modern processor, use no delay */
	if (((default_cpu_info.x86_vendor == X86_VENDOR_INTEL) && (default_cpu_info.x86 == 6)) ||
	    ((default_cpu_info.x86_vendor == X86_VENDOR_AMD) && (default_cpu_info.x86 >= 0xF))) {
		init_udelay = 0;
		return;
	}
	/* else, use legacy delay */
	init_udelay = UDELAY_10MS_DEFAULT;
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

	udelay(init_udelay);

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
		if (init_udelay == 0)
			udelay(10);
		else
			udelay(300);

		pr_debug("Startup point 1\n");

		pr_debug("Waiting for send to finish...\n");
		send_status = safe_apic_wait_icr_idle();

		/*
		 * Give the other CPU some time to accept the IPI.
		 */
		if (init_udelay == 0)
			udelay(10);
		else
			udelay(200);

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

static int do_cpu_up(int apicid, int cpu, struct task_struct *idle)
{
	unsigned long start_ip = trampoline_base;

	wakeup_cpu_via_init(apicid, start_ip);

	return 0;
}

/**
 * native_cpu_up
 *
 * Boot a CPU, do the necessary
 */
int native_cpu_up(int cpu, struct task_struct *idle)
{
	int ret;
	int apicid = cpu_to_apicid(cpu);

	pr_debug("++++++++++++++++++++=_---CPU UP  %u\n", cpu);
	ret = do_cpu_up(apicid, cpu, idle);
	if (ret) {
		pr_err("native_cpu_up failed(%d) to wakeup CPU#%u\n", ret, cpu);
		return -EIO;
	}

	while (!cpu_online(cpu))
		cpu_relax();

	return 0;
}

static int cpu0_logical_apicid;

/*
 * Prepare for SMP bootup.  The MP table or ACPI has been read
 * earlier.  Just do some sanity checking here and enable APIC mode.
 */
void __init smp_prepare_cpus(unsigned int maxcpus)
{
	if (read_apic_id() != boot_cpu_physical_apicid) {
		panic("Boot APIC ID in local APIC unexpected (%d vs %d)",
		     read_apic_id(), boot_cpu_physical_apicid);
		/* Or can we switch back to PIC here? */
	}

	cpu0_logical_apicid = apic_bsp_setup();

	/* Adjust delay, see comment above */
	smp_quirk_init_udelay();
}

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "LAPIC: " fmt

#include <lego/irq.h>
#include <lego/smp.h>
#include <lego/init.h>
#include <lego/delay.h>
#include <lego/kernel.h>
#include <lego/bitops.h>
#include <lego/percpu.h>
#include <lego/jiffies.h>
#include <lego/cpumask.h>
#include <lego/clockevent.h>

#include <asm/msr.h>
#include <asm/tsc.h>
#include <asm/asm.h>
#include <asm/apic.h>
#include <asm/time.h>
#include <asm/hw_irq.h>
#include <asm/ptrace.h>
#include <asm/io_apic.h>
#include <asm/processor.h>
#include <asm/irq_vectors.h>

unsigned int apic_verbosity = APIC_QUIET;

static int __init apic_set_verbosity(char *arg)
{
	if (strcmp("debug", arg) == 0)
		apic_verbosity = APIC_DEBUG;
	else if (strcmp("verbose", arg) == 0)
		apic_verbosity = APIC_VERBOSE;
	else {
		pr_warn("APIC Verbosity level %s not recognised"
			" use apic=verbose or apic=debug\n", arg);
		return -EINVAL;
	}
	return 0;
}
__setup("apic", apic_set_verbosity);

unsigned int nr_cpus;

/* Processor that is doing the boot up */
unsigned int boot_cpu_physical_apicid = -1U;
u8 boot_cpu_apic_version;

/* The highest APIC ID seen during enumaration */
unsigned int max_physical_apicid;

static unsigned long mp_lapic_addr;

static unsigned long apic_phys;

/*
 * Get the LAPIC version
 */
static inline int lapic_get_version(void)
{
	return GET_APIC_VERSION(apic_read(APIC_LVR));
}

/*
 * Check, whether this is a modern or a first generation APIC
 */
static int modern_apic(void)
{
	/* AMD systems use old APIC versions, so check the CPU */
	if (default_cpu_info.x86_vendor == X86_VENDOR_AMD &&
	    default_cpu_info.x86 >= 0xf)
		return 1;
	return lapic_get_version() >= 0x14;
}

#ifdef CONFIG_X86_X2APIC
int x2apic_mode;

void __init x2apic_enable(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_APICBASE, msr);
	if (msr & X2APIC_ENABLE)
		return;
	wrmsrl(MSR_IA32_APICBASE, msr | X2APIC_ENABLE);
	printk(KERN_INFO "x2apic enabled\n");
}

void __init check_x2apic(void)
{
	if (x2apic_enabled())
		pr_info("x2apic: enabled by BIOS, switching to x2apic\n");
	else if (!x2apic_supported())
		pr_info("x2apic: not supported by your CPU\n");
	else
		pr_info("x2apic: disabled by your BIOS\n");
}
#endif

void __init setup_apic_driver(void)
{
	struct apic **drv;

	pr_info("Original APIC routing is %s\n", apic->name);
	for (drv = __apicdrivers; drv < __apicdrivers_end; drv++) {
		if ((*drv)->probe && (*drv)->probe()) {
			if (apic != *drv) {
				apic = *drv;
				pr_info("Switched APIC routing to %s\n",
					apic->name);
			}
			return;
		}
	}
	panic("APIC: no driver found");
}

void native_apic_icr_write(u32 low, u32 id)
{
	unsigned long flags;

	local_irq_save(flags);
	apic_write(APIC_ICR2, SET_APIC_DEST_FIELD(id));
	apic_write(APIC_ICR, low);
	local_irq_restore(flags);
}

u64 native_apic_icr_read(void)
{
	u32 icr1, icr2;

	icr2 = apic_read(APIC_ICR2);
	icr1 = apic_read(APIC_ICR);

	return icr1 | ((u64)icr2 << 32);
}

void native_apic_wait_icr_idle(void)
{
	while (apic_read(APIC_ICR) & APIC_ICR_BUSY)
		cpu_relax();
}

u32 native_safe_apic_wait_icr_idle(void)
{
	u32 send_status;
	int timeout;

	timeout = 0;
	do {
		send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
		if (!send_status)
			break;
		udelay(100);
	} while (timeout++ < 1000);

	return send_status;
}

/*
 * The number of allocated logical CPU IDs.
 * Since logical CPU IDs are allocated contiguously, it equals to current
 * allocated max logical CPU ID plus 1. All allocated CPU ID should be
 * in [0, nr_logical_cpuidi), so the maximum of nr_logical_cpuids is nr_cpu_ids.
 *
 * NOTE: Reserve 0 for BSP.
 */
static int nr_logical_cpuids = 1;

/* Used to store mapping between logical CPU IDs and APIC IDs */
static int cpuid_to_apicid[] = {
	[0 ... NR_CPUS - 1] = -1,
};

/* Present physical APIC IDs */
static DECLARE_BITMAP(phys_apicid_present_map, MAX_LOCAL_APIC);

int cpu_to_apicid(int cpu)
{
	BUG_ON(cpu >= NR_CPUS);
	return cpuid_to_apicid[cpu];
}

static int allocate_logical_cpuid(int apicid)
{
	int i;

	/*
	 * cpuid <-> apicid mapping is persistent, so when a cpu is up,
	 * check if the kernel has allocated a cpuid for it.
	 */
	for (i = 0; i < nr_logical_cpuids; i++) {
		if (cpuid_to_apicid[i] == apicid)
			return i;
	}

	/* Allocate a new cpuid. */
	if (nr_logical_cpuids >= nr_cpu_ids) {
		WARN_ONCE(1, "Only %d processors supported."
			     "Processor %d/0x%x and the rest are ignored.\n",
			     nr_cpu_ids - 1, nr_logical_cpuids, apicid);
		return -1;
	}

	cpuid_to_apicid[nr_logical_cpuids] = apicid;
	return nr_logical_cpuids++;
}

/**
 * apic_register_new_cpu - Register a new CPU with APIC ID
 * @apicid: APIC ID
 * @enabled: is this CPU enabled
 * return: the logical cpu number
 */
int apic_register_new_cpu(int apicid, int enabled)
{
	int cpu;
	bool boot_cpu_detected;

	boot_cpu_detected = test_bit(boot_cpu_physical_apicid, phys_apicid_present_map);

	/*
	 * If boot cpu has not been detected yet, then only allow upto
	 * nr_cpu_ids - 1 processors and keep one slot free for boot cpu
	 */
	if (!boot_cpu_detected && nr_cpus >= nr_cpu_ids - 1 &&
	    apicid != boot_cpu_physical_apicid) {
		pr_warn("NR_CPUS/possible_cpus limit of %i almost"
			" reached. Keeping one slot for boot cpu."
			"  Processor 0x%x ignored.\n", nr_cpu_ids, apicid);
		return -ENODEV;
	}

	if (nr_cpus >= nr_cpu_ids) {
		if (enabled) {
			pr_warn("NR_CPUS/possible_cpus limit of %i "
				"reached. Processor 0x%x ignored.\n",
				nr_cpu_ids, apicid);
		}
		return -EINVAL;
	}

	if (apicid == boot_cpu_physical_apicid) {
		/*
		 * x86_bios_cpu_apicid is required to have processors listed
		 * in same order as logical cpu numbers. Hence the first
		 * entry is BSP, and so on.
		 * boot_cpu_init() already hold bit 0 in cpu_present_mask
		 * for BSP.
		 */
		cpu = 0;

		/* Logical cpuid 0 is reserved for BSP. */
		cpuid_to_apicid[0] = apicid;
	} else {
		cpu = allocate_logical_cpuid(apicid);
		if (cpu < 0) {
			pr_warn("fail to allocate logical cpuid\n");
			return -EINVAL;
		}
	}

	if (apicid > max_physical_apicid)
		max_physical_apicid = apicid;

	set_cpu_possible(cpu, true);
	if (enabled) {
		nr_cpus++;
		set_bit(apicid, phys_apicid_present_map);
		set_cpu_present(cpu, true);
	}

	return cpu;
}

/**
 * lapic_get_maxlvt
 * Get the maximum number of local vector table entries
 */
int lapic_get_maxlvt(void)
{
	unsigned int v;

	v = apic_read(APIC_LVR);
	return GET_APIC_MAXLVT(v);
}

void __init register_lapic_address(unsigned long address)
{
	mp_lapic_addr = address;

	if (!x2apic_mode) {
		set_fixmap_nocache(FIX_APIC_BASE, address);
		pr_info("Mapped APIC to %#16lx (%#16lx)\n", APIC_BASE, address);
	}
	if (boot_cpu_physical_apicid == -1U) {
		boot_cpu_physical_apicid  = read_apic_id();
		boot_cpu_apic_version = GET_APIC_VERSION(apic_read(APIC_LVR));
	}
}

void __init init_apic_mappings(void)
{
	int new_apicid;

	apic_phys = mp_lapic_addr;

	/*
	 * Fetch the APIC ID of the BSP in case we have a
	 * default configuration (or the MP table is broken).
	 */
	new_apicid = read_apic_id();
	if (boot_cpu_physical_apicid != new_apicid) {
		boot_cpu_physical_apicid = new_apicid;
		boot_cpu_apic_version = GET_APIC_VERSION(apic_read(APIC_LVR));
	}
}

/*
 * This variable controls which CPUs receive external NMIs.  By default,
 * external NMIs are delivered only to the BSP.
 */
static int apic_extnmi = APIC_EXTNMI_BSP;

/**
 * clear_local_apic - shutdown the local apic
 *
 * this is called, when a cpu is disabled and before rebooting, so the state of
 * the local apic has no dangling leftovers. also used to cleanout any bios
 * leftovers during boot.
 */
void clear_local_APIC(void)
{
	int maxlvt;
	u32 v;

	/* APIC hasn't been mapped yet */
	if (!x2apic_mode && !apic_phys)
		return;

	maxlvt = lapic_get_maxlvt();
	/*
	 * Masking an LVT entry can trigger a local APIC error
	 * if the vector is zero. Mask LVTERR first to prevent this.
	 */
	if (maxlvt >= 3) {
		v = ERROR_APIC_VECTOR; /* any non-zero vector will do */
		apic_write(APIC_LVTERR, v | APIC_LVT_MASKED);
	}
	/*
	 * Careful: we have to set masks only first to deassert
	 * any level-triggered sources.
	 */
	v = apic_read(APIC_LVTT);
	apic_write(APIC_LVTT, v | APIC_LVT_MASKED);
	v = apic_read(APIC_LVT0);
	apic_write(APIC_LVT0, v | APIC_LVT_MASKED);
	v = apic_read(APIC_LVT1);
	apic_write(APIC_LVT1, v | APIC_LVT_MASKED);
	if (maxlvt >= 4) {
		v = apic_read(APIC_LVTPC);
		apic_write(APIC_LVTPC, v | APIC_LVT_MASKED);
	}

	/*
	 * Clean APIC state for other OSs:
	 */
	apic_write(APIC_LVTT, APIC_LVT_MASKED);
	apic_write(APIC_LVT0, APIC_LVT_MASKED);
	apic_write(APIC_LVT1, APIC_LVT_MASKED);
	if (maxlvt >= 3)
		apic_write(APIC_LVTERR, APIC_LVT_MASKED);
	if (maxlvt >= 4)
		apic_write(APIC_LVTPC, APIC_LVT_MASKED);

	if (maxlvt > 3) {
		/* Clear ESR due to Pentium errata 3AP and 11AP */
		apic_write(APIC_ESR, 0);
	}
	apic_read(APIC_ESR);
}

/**
 * disable_local_APIC - clear and disable the local APIC
 */
void disable_local_APIC(void)
{
	unsigned int value;

	/* APIC hasn't been mapped yet */
	if (!x2apic_mode && !apic_phys)
		return;

	clear_local_APIC();

	/*
	 * Disable APIC (implies clearing of registers
	 * for 82489DX!).
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_SPIV_APIC_ENABLED;
	apic_write(APIC_SPIV, value);
}

static void lapic_setup_esr(void)
{
	unsigned int oldvalue, value, maxlvt;

	maxlvt = lapic_get_maxlvt();
	if (maxlvt > 3)		/* Due to the Pentium erratum 3AP. */
		apic_write(APIC_ESR, 0);
	oldvalue = apic_read(APIC_ESR);

	/* enables sending errors */
	value = ERROR_APIC_VECTOR;
	apic_write(APIC_LVTERR, value);

	/*
	 * spec says clear errors after enabling vector.
	 */
	if (maxlvt > 3)
		apic_write(APIC_ESR, 0);
	value = apic_read(APIC_ESR);
	if (value != oldvalue)
		apic_printk(APIC_VERBOSE, "ESR value before enabling "
			"vector: 0x%08x  after: 0x%08x\n",
			oldvalue, value);
}

static void end_local_APIC_setup(void)
{
	/* LVTERR, ESR */
	lapic_setup_esr();
#ifdef CONFIG_X86_32
	{
		unsigned int value;
		/* Disable the local apic timer */
		value = apic_read(APIC_LVTT);
		value |= (APIC_LVT_MASKED | LOCAL_TIMER_VECTOR);
		apic_write(APIC_LVTT, value);
	}
#endif
}

/**
 * sync_Arb_IDs - synchronize APIC bus arbitration IDs
 */
void __init sync_Arb_IDs(void)
{
	/*
	 * Unsupported on P4 - see Intel Dev. Manual Vol. 3, Ch. 8.6.1 And not
	 * needed on AMD.
	 */
	if (modern_apic() || default_cpu_info.x86_vendor == X86_VENDOR_AMD)
		return;

	/*
	 * Wait for idle.
	 */
	apic_wait_icr_idle();

	apic_printk(APIC_VERBOSE, "%s: Synchronizing Arb IDs\n", __func__);

	apic_write(APIC_ICR, APIC_DEST_ALLINC | APIC_INT_LEVELTRIG | APIC_DM_INIT);
}

asmlinkage __visible void
error_interrupt(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	pr_info("error_interrupt\n");

	set_irq_regs(old_regs);
}

asmlinkage __visible void
spurious_interrupt(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	pr_info("spurious_interrupt\n");

	set_irq_regs(old_regs);
}

/*
 * An initial setup of the Virtual Wire Mode.
 *
 * Note:
 * Virtual Wire Mode provides a uniprocessor hardware environment
 * capable of booting and running all DOS shrink-wrapped software.
 * For detailed explaination, check sec 3.6.2.2 of MultiProcessor
 * Specification, Intel.
 */
void __init init_bsp_APIC(void)
{
	unsigned int value;

	/*
	 * Do not trust the local APIC being empty at bootup.
	 */
	clear_local_APIC();

	/*
	 * Enable APIC.
	 *
	 * via the Spurious-interrupt vector
	 * (bit 8: APIC software enable/disable)
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;
	value |= APIC_SPIV_APIC_ENABLED;

	value |= APIC_SPIV_FOCUS_DISABLED;
	value |= SPURIOUS_APIC_VECTOR;
	apic_write(APIC_SPIV, value);

	/*
	 * LVT0, set up the Virtual Wire Mode:
	 *
	 * ExtINT:
	 * Cause the processor to respond to the interrupt
	 * as if the interrupt originated in an externally
	 * connected (i8259) interrupt controller.
	 *
	 * Only one processor in the system should have
	 * an LVT entry configured to use the ExtINT delivery mode.
	 */
	apic_write(APIC_LVT0, APIC_DM_EXTINT);

	/*
	 * LVT1, BSP
	 */
	value = APIC_DM_NMI;
	if (apic_extnmi == APIC_EXTNMI_NONE)
		value |= APIC_LVT_MASKED;
	apic_write(APIC_LVT1, value);
}

/**
 * setup_local_APIC - setup the local APIC
 *
 * Used to setup local APIC while initializing BSP or bringin up APs.
 * Always called with preemption disabled.
 *
 * Things to do:
 *	Set DFR, LDR registers
 *	Set TPR register to accept all
 *	Enable APIC
 *	Set LVT0
 *	Set LVT1
 */
void setup_local_APIC(void)
{
	int cpu = smp_processor_id();
	unsigned int value, queued;
	int i, j, acked = 0;
	unsigned long long tsc = 0, ntsc;
	long long max_loops = cpu_khz ? cpu_khz : 1000000;

	if (cpu_has(X86_FEATURE_TSC))
		tsc = rdtsc();

	/*
	 * Intel recommends to set DFR, LDR and TPR before enabling
	 * an APIC.  See e.g. "AP-388 82489DX User's Manual" (Intel
	 * document number 292116).  So here it goes...
	 */
	apic->init_apic_ldr();

	/*
	 * Set Task Priority to 'accept all'.
	 * We never change this later on.
	 */
	value = apic_read(APIC_TASKPRI);
	value &= ~APIC_TPRI_MASK;
	apic_write(APIC_TASKPRI, value);

	/*
	 * After a crash, we no longer service the interrupts and a pending
	 * interrupt from previous kernel might still have ISR bit set.
	 *
	 * Most probably by now CPU has serviced that pending interrupt and
	 * it might not have done the ack_APIC_irq() because it thought,
	 * interrupt came from i8259 as ExtInt. LAPIC did not get EOI so it
	 * does not clear the ISR bit and cpu thinks it has already serivced
	 * the interrupt. Hence a vector might get locked. It was noticed
	 * for timer irq (vector 0x31). Issue an extra EOI to clear ISR.
	 */
	do {
		queued = 0;
		for (i = APIC_ISR_NR - 1; i >= 0; i--)
			queued |= apic_read(APIC_IRR + i*0x10);

		for (i = APIC_ISR_NR - 1; i >= 0; i--) {
			value = apic_read(APIC_ISR + i*0x10);
			for (j = 31; j >= 0; j--) {
				if (value & (1<<j)) {
					ack_APIC_irq();
					acked++;
				}
			}
		}
		if (acked > 256) {
			printk(KERN_ERR "LAPIC pending interrupts after %d EOI\n",
			       acked);
			break;
		}
		if (queued) {
			if (cpu_has(X86_FEATURE_TSC) && cpu_khz) {
				ntsc = rdtsc();
				max_loops = (cpu_khz << 10) - (ntsc - tsc);
			} else
				max_loops--;
		}
	} while (queued && max_loops > 0);
	WARN_ON(max_loops <= 0);

	/*
	 * Now that we are all set up, enable the APIC
	 * Using the APIC software enable/disable bit of SPIV
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;

	/* Enable APIC */
	value |= APIC_SPIV_APIC_ENABLED;

	/* Set spurious IRQ vector, by the way :-) */
	value |= SPURIOUS_APIC_VECTOR;
	apic_write(APIC_SPIV, value);

	/*
	 * Set up LVT0, LVT1:
	 *
	 * set up through-local-APIC on the BP's LINT0. This is not
	 * strictly necessary in pure symmetric-IO mode, but sometimes
	 * we delegate interrupts to the 8259A.
	 *
	 * The APIC architecture supports only one ExtINT source in a system,
	 * usually contained in the compatibility bridge (a 8259A, seriously?).
	 * Only one processor in the system should have an LVT entry configured
	 * to use the ExtINT delivery.
	 *
	 * So in Lego, only BSP's LVT0 is configured to ExtINT, all other CPUs
	 * LVT0 will be masked.
	 */
	value = apic_read(APIC_LVT0) & APIC_LVT_MASKED;
	if (!cpu && !value) {
		value = APIC_DM_EXTINT;
		apic_printk(APIC_VERBOSE, "enabled ExtINT on CPU#%d\n", cpu);
	} else {
		value = APIC_DM_EXTINT | APIC_LVT_MASKED;
		apic_printk(APIC_VERBOSE, "masked ExtINT on CPU#%d\n", cpu);
	}
	apic_write(APIC_LVT0, value);

	/*
	 * Only the BSP sees the LINT1 NMI signal by default.
	 * This can be modified by apic_extnmi= boot option.
	 */
	if ((!cpu && apic_extnmi != APIC_EXTNMI_NONE) ||
	    apic_extnmi == APIC_EXTNMI_ALL)
		value = APIC_DM_NMI;
	else
		value = APIC_DM_NMI | APIC_LVT_MASKED;
	apic_write(APIC_LVT1, value);
}

/* Local APIC Timer Part */

unsigned int lapic_timer_frequency;

#define TSC_DIVISOR	8

/*
 * APIC has a configuration register (APIC_TDCR) to set the
 * the divide value.
 * We choose 16 here, and will write it to APIC_TDCR.
 */
#define APIC_DIVISOR	16

/*
 * This function sets up the local APIC timer, with a timeout of
 * 'clocks' APIC bus clock. During calibration we actually call
 * this function twice on the boot CPU, once with a bogus timeout
 * value, second time for real. The other (noncalibrating) CPUs
 * call this function only once, with the real, calibrated value.
 *
 * We do reads before writes even if unnecessary, to get around the
 * P5 APIC double write bug.
 */
static void __setup_APIC_LVTT(unsigned int clocks, int oneshot, int irqen)
{
	unsigned int lvtt_value, tmp_value;

	lvtt_value = LOCAL_TIMER_VECTOR;
	if (!oneshot)
		lvtt_value |= APIC_LVT_TIMER_PERIODIC;
	else if (cpu_has(X86_FEATURE_TSC_DEADLINE_TIMER))
		lvtt_value |= APIC_LVT_TIMER_TSCDEADLINE;

	if (!irqen)
		lvtt_value |= APIC_LVT_MASKED;

	apic_write(APIC_LVTT, lvtt_value);

	if (lvtt_value & APIC_LVT_TIMER_TSCDEADLINE) {
		/*
		 * See Intel SDM: TSC-Deadline Mode chapter. In xAPIC mode,
		 * writing to the APIC LVTT and TSC_DEADLINE MSR isn't serialized.
		 * According to Intel, MFENCE can do the serialization here.
		 */
		asm volatile("mfence" : : : "memory");

		printk_once(KERN_DEBUG "TSC deadline timer enabled\n");
		return;
	}

	/*
	 * Divide PICLK by 16
	 */
	tmp_value = apic_read(APIC_TDCR);
	apic_write(APIC_TDCR,
		(tmp_value & ~(APIC_TDR_DIV_1 | APIC_TDR_DIV_TMBASE)) |
		APIC_TDR_DIV_16);

	/*
	 * In periodic mode, the current-count register is automatically
	 * reloaded from the initial-count register when the count reaches 0,
	 * and a timer interrupt is generated, and the count-down is repeated.
	 */
	if (!oneshot)
		apic_write(APIC_TMICT, clocks / APIC_DIVISOR);
}

/* Program the next event, relative to now */
static int lapic_next_event(unsigned long delta,
			    struct clock_event_device *evt)
{
	apic_write(APIC_TMICT, delta);
	return 0;
}

static int lapic_next_deadline(unsigned long delta,
			       struct clock_event_device *evt)
{
	u64 tsc;

	tsc = rdtsc();
	wrmsrl(MSR_IA32_TSC_DEADLINE, tsc + (((u64) delta) * TSC_DIVISOR));
	return 0;
}

/*
 * A write of 0 to the APIC_TMICT resgiter effectively
 * stops the local APIC timer, in both period and one-shot mode.
 */
static int lapic_timer_shutdown(struct clock_event_device *evt)
{
	unsigned int v;

	/* Lapic used as dummy for broadcast ? */
	if (evt->features & CLOCK_EVT_FEAT_DUMMY)
		return 0;

	v = apic_read(APIC_LVTT);
	v |= (APIC_LVT_MASKED | LOCAL_TIMER_VECTOR);
	apic_write(APIC_LVTT, v);
	apic_write(APIC_TMICT, 0);
	return 0;
}

static inline int
lapic_timer_set_periodic_oneshot(struct clock_event_device *evt, bool oneshot)
{
	__setup_APIC_LVTT(lapic_timer_frequency, oneshot, 1);
	return 0;
}

static int lapic_timer_set_periodic(struct clock_event_device *evt)
{
	return lapic_timer_set_periodic_oneshot(evt, false);
}

static int lapic_timer_set_oneshot(struct clock_event_device *evt)
{
	return lapic_timer_set_periodic_oneshot(evt, true);
}

/**
 * lapic_clockevent
 *
 * Your local APIC timer device
 */
static struct clock_event_device lapic_clockevent = {
	.name			= "lapic",
	.features		= CLOCK_EVT_FEAT_PERIODIC |
				  CLOCK_EVT_FEAT_ONESHOT,
	.shift			= 32,
	.set_state_shutdown	= lapic_timer_shutdown,
	.set_state_periodic	= lapic_timer_set_periodic,
	.set_state_oneshot	= lapic_timer_set_oneshot,
	.set_next_event		= lapic_next_event,
	.rating			= 100,
	.irq			= -1,
};

static DEFINE_PER_CPU(struct clock_event_device, lapic_events);

/**
 * apic_timer_interrupt
 *
 * Local APIC timer interrupt.
 * This is the most natural way for doing local interrupts.
 *
 */
asmlinkage __visible void
apic_timer_interrupt(struct pt_regs *regs)
{
	int cpu = smp_processor_id();
	struct clock_event_device *levt = &per_cpu(lapic_events, cpu);
	struct pt_regs *old_regs = set_irq_regs(regs);

	/*
	 * NOTE! We'd better ACK the irq immediately,
	 * because timer handling can be slow.
	 */
	ack_APIC_irq();

	if (unlikely(!levt->event_handler)) {
		pr_warn("Spurious LAPIC timer interrupt on cpu %d\n", cpu);
		/* Switch it off */
		lapic_timer_shutdown(levt);
		set_irq_regs(old_regs);
		return;
	}

	/*
	 * Callback to clockevent framework, hmm, yummy
	 * Since deadline TSC and one-shot is not supported now,
	 * hence the handler is tick_handle_periodic():
	 */
	levt->event_handler(levt);

	set_irq_regs(old_regs);
}

/*
 * Setup the local APIC timer for this CPU.
 * Copy the initialized values from the boot CPU
 * and register the clock event in the framework.
 */
static void setup_APIC_timer(void)
{
	int cpu = smp_processor_id();
	struct clock_event_device *levt = this_cpu_ptr(&lapic_events);

	if (cpu_has(X86_FEATURE_ARAT)) {
		lapic_clockevent.features &= ~CLOCK_EVT_FEAT_C3STOP;
		/* Make LAPIC timer preferrable over percpu HPET */
		lapic_clockevent.rating = 150;
	} else {
		apic_printk(APIC_VERBOSE,
			"ARAT not supported. The APIC timer may temporarily "
			"stop while the processor in deep C-states.\n");
	}

	memcpy(levt, &lapic_clockevent, sizeof(*levt));
	levt->cpumask = cpumask_of(cpu);

	if (cpu_has(X86_FEATURE_TSC_DEADLINE_TIMER)) {
		printk_once(
			"TSC deadline mode is supported by your CPU. "
			"But Lego currently does not support one-shot tick mode. "
			"Fall back to TSC periodic mode\n");
		goto
			REMOVEME;

		levt->features &= ~(CLOCK_EVT_FEAT_PERIODIC |
				    CLOCK_EVT_FEAT_DUMMY);
		levt->set_next_event = lapic_next_deadline;

		/* Register tick-common handler */
		clockevents_config_and_register(levt,
						tsc_khz * (1000 / TSC_DIVISOR),
						0xF, ~0UL);
	} else {
REMOVEME:
		apic_printk(APIC_VERBOSE, "Using TSC periodic mode\n");

		/* Register tick-common handler */
		clockevents_register_device(levt);
	}
}

/*
 * In this functions we calibrate APIC bus clocks to the external timer.
 *
 * We want to do the calibration only once since we want to have local timer
 * irqs syncron. CPUs connected by the same APIC bus have the very same bus
 * frequency.
 *
 * This was previously done by reading the PIT/HPET and waiting for a wrap
 * around to find out, that a tick has elapsed. I have a box, where the PIT
 * readout is broken, so it never gets out of the wait loop again. This was
 * also reported by others.
 *
 * Monitoring the jiffies value is inaccurate and the clockevents
 * infrastructure allows us to do a simple substitution of the interrupt
 * handler.
 *
 * The calibration routine also uses the pm_timer when possible, as the PIT
 * happens to run way too slow (factor 2.3 on my VAIO CoreDuo, which goes
 * back to normal later in the boot process).
 */
#define LAPIC_CAL_LOOPS		(HZ/10)

static __initdata int lapic_cal_loops = -1;
static __initdata long lapic_cal_t1, lapic_cal_t2;
static __initdata unsigned long long lapic_cal_tsc1, lapic_cal_tsc2;
static __initdata unsigned long lapic_cal_j1, lapic_cal_j2;

/* Temporary timer interrupt handler */
static void __init lapic_cal_handler(struct clock_event_device *dev)
{
	unsigned long long tsc = 0;
	long tapic = apic_read(APIC_TMCCT);

	if (cpu_has(X86_FEATURE_TSC))
		tsc = rdtsc();

	switch (lapic_cal_loops++) {
	case 0:
		lapic_cal_t1 = tapic;
		lapic_cal_tsc1 = tsc;
		lapic_cal_j1 = jiffies;
		break;

	case LAPIC_CAL_LOOPS:
		lapic_cal_t2 = tapic;
		lapic_cal_tsc2 = tsc;
		lapic_cal_j2 = jiffies;
		break;
	}
}

static int __init calibrate_APIC_clock(void)
{
	struct clock_event_device *levt = this_cpu_ptr(&lapic_events);
	void (*real_handler)(struct clock_event_device *dev);
	unsigned long deltaj;
	long delta, deltatsc;

	/*
	 * Check if lapic timer has already been calibrated by platform
	 * specific routine, such as tsc calibration code. if so, we just fill
	 * in the clockevent structure and return.
	 */
	if (lapic_timer_frequency) {
		apic_printk(APIC_VERBOSE, "lapic timer already calibrated %d\n",
				lapic_timer_frequency);
		lapic_clockevent.mult = div_sc(lapic_timer_frequency/APIC_DIVISOR,
					TICK_NSEC, lapic_clockevent.shift);
		lapic_clockevent.max_delta_ns =
			clockevent_delta2ns(0x7FFFFF, &lapic_clockevent);
		lapic_clockevent.min_delta_ns =
			clockevent_delta2ns(0xF, &lapic_clockevent);
		lapic_clockevent.features &= ~CLOCK_EVT_FEAT_DUMMY;
		return 0;
	}

	apic_printk(APIC_VERBOSE, "Using local APIC timer interrupts.\n");
	apic_printk(APIC_VERBOSE, "Calibrating APIC timer ...\n");

	local_irq_disable();

	/* Replace the global timer interrupt handler */
	real_handler = global_clock_event->event_handler;
	global_clock_event->event_handler = lapic_cal_handler;

	/*
	 * Setup the APIC counter to maximum.
	 *
	 * There is no way the lapic can underflow in
	 * the 100ms detection time frame
	 */
	__setup_APIC_LVTT(0xffffffff, 0, 0);

	/* Let the interrupts run */
	local_irq_enable();

	/* Wait to finish... */
	while (lapic_cal_loops <= LAPIC_CAL_LOOPS)
		cpu_relax();

	local_irq_disable();

	/* Restore the real event handler */
	global_clock_event->event_handler = real_handler;

	/* Build delta t1-t2 as apic timer counts down */
	delta = lapic_cal_t1 - lapic_cal_t2;
	apic_printk(APIC_VERBOSE, "... lapic delta = %ld\n", delta);

	deltatsc = (long)(lapic_cal_tsc2 - lapic_cal_tsc1);

	/* Calculate the scaled math multiplication factor */
	lapic_clockevent.mult = div_sc(delta, TICK_NSEC * LAPIC_CAL_LOOPS,
				       lapic_clockevent.shift);
	lapic_clockevent.max_delta_ns =
		clockevent_delta2ns(0x7FFFFFFF, &lapic_clockevent);
	lapic_clockevent.min_delta_ns =
		clockevent_delta2ns(0xF, &lapic_clockevent);

	/*
	 * The APIC timer frequency will be the processor's bus clock
	 * or core crystal clock frequency divided by the value specified
	 * in the divide configuration register.
	 */
	lapic_timer_frequency = (delta * APIC_DIVISOR) / LAPIC_CAL_LOOPS;

	apic_printk(APIC_VERBOSE, "..... delta %ld\n", delta);
	apic_printk(APIC_VERBOSE, "..... mult: %u\n", lapic_clockevent.mult);
	apic_printk(APIC_VERBOSE, "..... lapic_timer_frequency: %u\n",
		    lapic_timer_frequency);

	if (cpu_has(X86_FEATURE_TSC)) {
		apic_printk(APIC_VERBOSE, "..... CPU clock speed is "
			    "%ld.%04ld MHz.\n",
			    (deltatsc / LAPIC_CAL_LOOPS) / (1000000 / HZ),
			    (deltatsc / LAPIC_CAL_LOOPS) % (1000000 / HZ));
	}

	apic_printk(APIC_VERBOSE, "..... host bus clock speed is "
		    "%u.%04u MHz.\n",
		    lapic_timer_frequency / (1000000 / HZ),
		    lapic_timer_frequency % (1000000 / HZ));

	/*
	 * Do a sanity check on the APIC calibration result
	 */
	if (lapic_timer_frequency < (1000000 / HZ)) {
		local_irq_enable();
		pr_warn("APIC frequency too slow, disabling apic timer\n");
		return -1;
	}

	levt->features &= ~CLOCK_EVT_FEAT_DUMMY;

	/*
	 * XXX:
	 * Verify APIC timer, because Lego currently is not using
	 * any PM timer, which is used by Linux by default.
	 *
	 * PM timer is reported by ACPI.
	 */
	apic_printk(APIC_VERBOSE, "... verify APIC timer\n");

	/*
	 * Setup the apic timer manually
	 */
	levt->event_handler = lapic_cal_handler;
	lapic_timer_set_periodic(levt);
	lapic_cal_loops = -1;

	/* Let the interrupts run */
	local_irq_enable();

	/* Wait to finish... */
	while (lapic_cal_loops <= LAPIC_CAL_LOOPS)
		cpu_relax();

	/* Stop the lapic timer */
	local_irq_disable();
	lapic_timer_shutdown(levt);

	/* Jiffies delta */
	deltaj = lapic_cal_j2 - lapic_cal_j1;
	apic_printk(APIC_VERBOSE, "... jiffies delta = %lu\n", deltaj);

	/* Check, if the jiffies result is consistent */
	if (deltaj >= LAPIC_CAL_LOOPS-2 && deltaj <= LAPIC_CAL_LOOPS+2)
		apic_printk(APIC_VERBOSE, "... jiffies result ok\n");
	else
		levt->features |= CLOCK_EVT_FEAT_DUMMY;

	local_irq_enable();

	if (levt->features & CLOCK_EVT_FEAT_DUMMY) {
		pr_warn("APIC timer disabled due to verification failure\n");
			return -1;
	}

	return 0;
}

/*
 * Setup the boot APIC
 *
 * Calibrate and verify the result.
 */
void __init setup_boot_APIC_clock(void)
{
	WARN_ON(calibrate_APIC_clock());

	/* Setup the lapic at BSP */
	setup_APIC_timer();
}

void setup_secondary_APIC_clock(void)
{
	setup_APIC_timer();
}

/**
 * apic_bsp_setup - Setup function for local apic and io-apic
 *
 * Returns:
 * apic_id of BSP APIC
 */
int __init apic_bsp_setup(void)
{
	int id;

	setup_local_APIC();

	if (x2apic_mode)
		id = apic_read(APIC_LDR);
	else
		id = GET_APIC_LOGICAL_ID(apic_read(APIC_LDR));

	/* This is not real enable, just regular checking.. */
	enable_IO_APIC();

	end_local_APIC_setup();

	/*
	 * Fully initialize IO-APIC
	 * Setup pin -> IRQ -> vector mapping
	 * and fill interrupt redirectiont table
	 */
	setup_IO_APIC();

	setup_boot_APIC_clock();

	return id;
}

/*
 * APIC setup function for application processors. Called from smpboot.c
 */
void __init apic_ap_setup(void)
{
	setup_local_APIC();
	end_local_APIC_setup();
}

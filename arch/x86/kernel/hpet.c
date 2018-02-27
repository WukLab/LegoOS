/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "HPET: " fmt

#include <lego/mm.h>
#include <lego/irq.h>
#include <lego/smp.h>
#include <lego/slab.h>
#include <lego/time.h>
#include <lego/delay.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/cpumask.h>
#include <lego/irqchip.h>
#include <lego/irqdesc.h>
#include <lego/irqdomain.h>
#include <lego/clockevent.h>
#include <lego/clocksource.h>

#include <asm/io.h>
#include <asm/msr.h>
#include <asm/hpet.h>
#include <asm/time.h>
#include <asm/apic.h>
#include <asm/processor.h>

#define HPET_MASK			CLOCKSOURCE_MASK(32)

/* FSEC = 10^-15
   NSEC = 10^-9 */
#define FSEC_PER_NSEC			1000000L

#define HPET_DEV_USED_BIT		2
#define HPET_DEV_USED			(1 << HPET_DEV_USED_BIT)
#define HPET_DEV_VALID			0x8
#define HPET_DEV_FSB_CAP		0x1000
#define HPET_DEV_PERI_CAP		0x2000

#define HPET_MIN_CYCLES			128
#define HPET_MIN_PROG_DELTA		(HPET_MIN_CYCLES + (HPET_MIN_CYCLES >> 1))

/* HPET address is set by ACPI, when an ACPI entry exists */
unsigned long hpet_address;

/* OS timer block num */
u8 hpet_blockid;

static unsigned long hpet_freq;
static void __iomem *hpet_virt_address;

/*
 * HPET timer interrupt enable / disable
 */
static bool hpet_legacy_int_enabled;

struct hpet_dev {
	struct clock_event_device	evt;
	unsigned int			num;
	int				cpu;
	unsigned int			irq;
	unsigned int			flags;
	char				name[10];
};

static inline struct hpet_dev *EVT_TO_HPET_DEV(struct clock_event_device *evtdev)
{
	return container_of(evtdev, struct hpet_dev, evt);
}

inline unsigned int hpet_readl(unsigned int a)
{
	return readl(hpet_virt_address + a);
}

static inline void hpet_writel(unsigned int d, unsigned int a)
{
	writel(d, hpet_virt_address + a);
}

bool hpet_verbose = false;

static void _hpet_print_config(const char *function, int line)
{
	u32 i, timers, l, h;
	printk(KERN_INFO "HPET: ----------------------------------\n");
	printk(KERN_INFO "HPET: called from %s(%d):\n", function, line);
	l = hpet_readl(HPET_ID);
	h = hpet_readl(HPET_PERIOD);
	timers = ((l & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT) + 1;
	printk(KERN_INFO "HPET: ID: 0x%x, PERIOD: 0x%x\n", l, h);
	l = hpet_readl(HPET_CFG);
	h = hpet_readl(HPET_STATUS);
	printk(KERN_INFO "HPET: CFG: 0x%x, STATUS: 0x%x\n", l, h);
	l = hpet_readl(HPET_COUNTER);
	h = hpet_readl(HPET_COUNTER+4);
	printk(KERN_INFO "HPET: COUNTER_l: 0x%x, COUNTER_h: 0x%x\n", l, h);

	for (i = 0; i < timers; i++) {
		l = hpet_readl(HPET_Tn_CFG(i));
		h = hpet_readl(HPET_Tn_CFG(i)+4);
		printk(KERN_INFO "HPET: T%d: CFG_l: 0x%x, CFG_h: 0x%x\n",
		       i, l, h);
		l = hpet_readl(HPET_Tn_CMP(i));
		h = hpet_readl(HPET_Tn_CMP(i)+4);
		printk(KERN_INFO "HPET: T%d: CMP_l: 0x%x, CMP_h: 0x%x\n",
		       i, l, h);
		l = hpet_readl(HPET_Tn_ROUTE(i));
		h = hpet_readl(HPET_Tn_ROUTE(i)+4);
		printk(KERN_INFO "HPET: T%d ROUTE_l: 0x%x, ROUTE_h: 0x%x\n",
		       i, l, h);
	}
}

#define hpet_print_config()					\
do {								\
	if (hpet_verbose)					\
		_hpet_print_config(__func__, __LINE__);	\
} while (0)

static inline void hpet_set_mapping(void)
{
	hpet_virt_address = ioremap_nocache(hpet_address, HPET_MMAP_SIZE);
}

static inline void hpet_clear_mapping(void)
{
	iounmap(hpet_virt_address);
	hpet_virt_address = NULL;
}

/* Reset main counter */
static void hpet_reset_counter(void)
{
	hpet_writel(0, HPET_COUNTER);
	hpet_writel(0, HPET_COUNTER + 4);
}

/* Halt main counter and disable all timer interrupts */
static void hpet_stop_counter(void)
{
	u32 cfg = hpet_readl(HPET_CFG);
	cfg &= ~HPET_CFG_ENABLE;
	hpet_writel(cfg, HPET_CFG);
}

/* Allow main counter to run and allow timer interrupts to fire */
static void hpet_start_counter(void)
{
	unsigned int cfg = hpet_readl(HPET_CFG);
	cfg |= HPET_CFG_ENABLE;
	hpet_writel(cfg, HPET_CFG);
}

static void hpet_restart_counter(void)
{
	hpet_stop_counter();
	hpet_reset_counter();
	hpet_start_counter();
}

/*
 * Legacy Replacement Route Mode:
 *  - Timer 0 will be routed to IRQ0 in non-APIC or IRQ2 in the I/O APIC
 *  - Timer 1 will be routed to IRQ8 in non-APIC or IRQ8 in the I/O APIC
 */
static void hpet_enable_legacy_int(void)
{
	unsigned int cfg = hpet_readl(HPET_CFG);

	cfg |= HPET_CFG_LEGACY;
	hpet_writel(cfg, HPET_CFG);
	hpet_legacy_int_enabled = true;
}

static int hpet_set_periodic(struct clock_event_device *evt, int timer)
{
	unsigned int cfg, cmp, now;
	u64 delta;

	hpet_stop_counter();
	delta = ((u64)(NSEC_PER_SEC / HZ)) * evt->mult;
	delta >>= evt->shift;
	now = hpet_readl(HPET_COUNTER);
	cmp = now + (unsigned int)delta;
	cfg = hpet_readl(HPET_Tn_CFG(timer));
	cfg |= HPET_TN_ENABLE | HPET_TN_PERIODIC | HPET_TN_SETVAL |
	       HPET_TN_32BIT;
	hpet_writel(cfg, HPET_Tn_CFG(timer));
	hpet_writel(cmp, HPET_Tn_CMP(timer));
	udelay(1);
	/*
	 * HPET on AMD 81xx needs a second write (with HPET_TN_SETVAL
	 * cleared) to T0_CMP to set the period. The HPET_TN_SETVAL
	 * bit is automatically cleared after the first write.
	 * (See AMD-8111 HyperTransport I/O Hub Data Sheet,
	 * Publication # 24674)
	 */
	hpet_writel((unsigned int)delta, HPET_Tn_CMP(timer));
	hpet_start_counter();
	hpet_print_config();

	return 0;
}

static int hpet_set_oneshot(struct clock_event_device *evt, int timer)
{
	unsigned int cfg;

	cfg = hpet_readl(HPET_Tn_CFG(timer));
	cfg &= ~HPET_TN_PERIODIC;
	cfg |= HPET_TN_ENABLE | HPET_TN_32BIT;
	hpet_writel(cfg, HPET_Tn_CFG(timer));

	return 0;
}

static int hpet_shutdown(struct clock_event_device *evt, int timer)
{
	unsigned int cfg;

	pr_debug("hpet shutdown\n");

	cfg = hpet_readl(HPET_Tn_CFG(timer));
	cfg &= ~HPET_TN_ENABLE;
	hpet_writel(cfg, HPET_Tn_CFG(timer));

	return 0;
}

static int hpet_resume(struct clock_event_device *evt, int timer)
{
	if (!timer) {
		hpet_enable_legacy_int();
	} else {
		struct hpet_dev *hdev = EVT_TO_HPET_DEV(evt);

		irq_domain_activate_irq(irq_get_irq_data(hdev->irq));
		disable_irq(hdev->irq);
		irq_set_affinity(hdev->irq, cpumask_of(hdev->cpu));
		enable_irq(hdev->irq);
	}
	hpet_print_config();

	return 0;
}

static int hpet_next_event(unsigned long delta,
			   struct clock_event_device *evt, int timer)
{
	u32 cnt;
	s32 res;

	cnt = hpet_readl(HPET_COUNTER);
	cnt += (u32) delta;
	hpet_writel(cnt, HPET_Tn_CMP(timer));

	/*
	 * HPETs are a complete disaster. The compare register is
	 * based on a equal comparison and neither provides a less
	 * than or equal functionality (which would require to take
	 * the wraparound into account) nor a simple count down event
	 * mode. Further the write to the comparator register is
	 * delayed internally up to two HPET clock cycles in certain
	 * chipsets (ATI, ICH9,10). Some newer AMD chipsets have even
	 * longer delays. We worked around that by reading back the
	 * compare register, but that required another workaround for
	 * ICH9,10 chips where the first readout after write can
	 * return the old stale value. We already had a minimum
	 * programming delta of 5us enforced, but a NMI or SMI hitting
	 * between the counter readout and the comparator write can
	 * move us behind that point easily. Now instead of reading
	 * the compare register back several times, we make the ETIME
	 * decision based on the following: Return ETIME if the
	 * counter value after the write is less than HPET_MIN_CYCLES
	 * away from the event or if the counter is already ahead of
	 * the event. The minimum programming delta for the generic
	 * clockevents code is set to 1.5 * HPET_MIN_CYCLES.
	 */
	res = (s32)(cnt - hpet_readl(HPET_COUNTER));

	return res < HPET_MIN_CYCLES ? -ETIME : 0;
}

static int hpet_legacy_set_periodic(struct clock_event_device *evt)
{
	return hpet_set_periodic(evt, 0);
}

static int hpet_legacy_set_oneshot(struct clock_event_device *evt)
{
	return hpet_set_oneshot(evt, 0);
}

static int hpet_legacy_shutdown(struct clock_event_device *evt)
{
	return hpet_shutdown(evt, 0);
}

static int hpet_legacy_resume(struct clock_event_device *evt)
{
	return hpet_resume(evt, 0);
}

static int hpet_legacy_next_event(unsigned long delta,
			struct clock_event_device *evt)
{
	return hpet_next_event(delta, evt, 0);
}

/*
 * The hpet clock event device
 */
static struct clock_event_device hpet_clockevent = {
	.name			= "hpet",
	.event_handler		= tick_handle_periodic,
	.features		= CLOCK_EVT_FEAT_PERIODIC |
				  CLOCK_EVT_FEAT_ONESHOT,
	.set_state_periodic	= hpet_legacy_set_periodic,
	.set_state_oneshot	= hpet_legacy_set_oneshot,
	.set_state_shutdown	= hpet_legacy_shutdown,
	.tick_resume		= hpet_legacy_resume,
	.set_next_event		= hpet_legacy_next_event,
	.irq			= 0,
	.rating			= 50,
};

static void hpet_legacy_clockevent_register(void)
{
	/*
	 * Enable HPET legacy interrupts
	 * But the HPET is still disabled to run
	 */
	hpet_enable_legacy_int();

	/*
	 * Start hpet with the boot cpu mask and make it
	 * global after the IO_APIC has been initialized.
	 */
	hpet_clockevent.cpumask = cpumask_of(smp_processor_id());

	/*
	 * Register hpet clockevent, and it will callback to
	 * set hpet run and afterwards, timer interrupt is alive!
	 */
	clockevents_config_and_register(&hpet_clockevent, hpet_freq,
					HPET_MIN_PROG_DELTA, 0x7FFFFFFF);

	global_clock_event = &hpet_clockevent;
	pr_info("hpet clockevent registered\n");
}

static u64 read_hpet(struct clocksource *cs)
{
	return (u64)hpet_readl(HPET_COUNTER);
}

static struct clocksource clocksource_hpet = {
	.name		= "hpet",
	.rating		= 250,
	.read		= read_hpet,
	.mask		= HPET_MASK,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

static int hpet_clocksource_register(void)
{
	u64 start, now;
	u64 t1;

	/* Start the counter */
	hpet_restart_counter();

	/* Verify whether hpet counter works */
	t1 = hpet_readl(HPET_COUNTER);
	start = rdtsc();

	/*
	 * We don't know the TSC frequency yet, but waiting for
	 * 200000 TSC cycles is safe:
	 * 4 GHz == 50us
	 * 1 GHz == 200us
	 */
	do {
		rep_nop();
		now = rdtsc();
	} while ((now - start) < 200000UL);

	if (t1 == hpet_readl(HPET_COUNTER)) {
		printk(KERN_WARNING
		       "HPET counter not counting. HPET disabled\n");
		return -ENODEV;
	}

	clocksource_register_hz(&clocksource_hpet, (u32)hpet_freq);

	return 0;
}

static u32 *hpet_boot_cfg;

/**
 * hpet_enable
 *
 * Try to setup the HPET timer.
 * Returns 0 on success.
 */
int hpet_enable(void)
{
	u32 hpet_period, cfg, id;
	u64 freq;
	unsigned int i, last;

	if (!hpet_address)
		return -ENODEV;

	hpet_set_mapping();

	/*
	 * Read main counter tick period
	 * This field indicates the period at which the counter
	 * increments in femptoseconds (10^-15 seconds).
	 */
	hpet_period = hpet_readl(HPET_PERIOD);

	if (hpet_period < HPET_MIN_PERIOD || hpet_period > HPET_MAX_PERIOD)
		goto out_nohpet;

	/*
	 * The period is a femto seconds value. Convert it to a
	 * frequency.
	 */
	freq = FSEC_PER_SEC;
	do_div(freq, hpet_period);
	hpet_freq = freq;

	pr_info("Detected %lu.%03lu MHz HPET\n",
		(unsigned long)hpet_freq / 1000,
		(unsigned long)hpet_freq % 1000);

	/*
	 * Read the HPET ID register to retrieve the IRQ routing
	 * information and the number of channels
	 */
	id = hpet_readl(HPET_ID);
	hpet_print_config();

	last = (id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT;

	cfg = hpet_readl(HPET_CFG);
	hpet_boot_cfg = kmalloc((last + 2) * sizeof(*hpet_boot_cfg),
				GFP_KERNEL);
	if (hpet_boot_cfg)
		*hpet_boot_cfg = cfg;
	else
		pr_warn("initial state will not be saved\n");

	/*
	 * Disable HPET first
	 *
	 * HPET_CFG_ENABLE: Overall enable, this bit must be
	 * set to enable any of the timers to generate interrupts
	 *	0 - halt
	 *	1 - enable
	 */
	cfg &= ~(HPET_CFG_ENABLE | HPET_CFG_LEGACY);
	hpet_writel(cfg, HPET_CFG);
	if (cfg)
		pr_warn("Unrecognized bits %#x set in global cfg\n",
			cfg);

	for (i = 0; i <= last; ++i) {
		cfg = hpet_readl(HPET_Tn_CFG(i));
		if (hpet_boot_cfg)
			hpet_boot_cfg[i + 1] = cfg;

		/*
		 * Disable each timer counter first
		 *
		 * HPET_TN_ENABLE: This bit must be set to enable
		 * timer n to cause an interrupt when timer event fires.
		 *	0 - operate, no interrupt
		 *	1 - operate, interrupt
		 */
		cfg &= ~(HPET_TN_ENABLE | HPET_TN_LEVEL | HPET_TN_FSB);
		hpet_writel(cfg, HPET_Tn_CFG(i));

		cfg &= ~(HPET_TN_PERIODIC | HPET_TN_PERIODIC_CAP
			 | HPET_TN_64BIT_CAP | HPET_TN_32BIT | HPET_TN_ROUTE
			 | HPET_TN_FSB | HPET_TN_FSB_CAP);
		if (cfg)
			pr_warn("Unrecognized bits %#x set in cfg#%u\n",
				cfg, i);
	}
	hpet_print_config();

	/*
	 * Check if HPET is really working,
	 * if yes, register HPET's clocksource
	 */
	if (hpet_clocksource_register())
		goto out_nohpet;

	/*
	 * If this bit is 1, it indicates that the hardware supports
	 * the Legacy Replacement Interrupt Route option.
	 *
	 * If so, we can use this HPET. (why?)
	 * and register the clockevent and enable HPET
	 */
	if (id & HPET_ID_LEGSUP) {
		hpet_legacy_clockevent_register();

		/* Success */
		return 0;
	}

	return -ENODEV;

out_nohpet:
	hpet_clear_mapping();
	hpet_address = 0;
	return -ENODEV;
}

static inline int is_hpet_capable(void)
{
	return !!hpet_address;
}

/**
 * is_hpet_enabled - check whether the hpet timer interrupt is enabled
 */
int is_hpet_enabled(void)
{
	return is_hpet_capable() && hpet_legacy_int_enabled;
}

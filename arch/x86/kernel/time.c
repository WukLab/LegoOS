/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/irqdesc.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>

#include <asm/hpet.h>
#include <asm/i8259.h>

__visible volatile unsigned long jiffies __cacheline_aligned = INITIAL_JIFFIES;

/*
 * Default timer interrupt handler for PIT/HPET
 */
static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	return IRQ_HANDLED;
}

static struct irqaction irq0  = {
	.name		= "timer",
	.handler	= timer_interrupt,
	.flags		= IRQF_NOBALANCING | IRQF_IRQPOLL | IRQF_TIMER,
};

void __init setup_default_timer_irq(void)
{
	if (!nr_legacy_irqs())
		return;
	setup_irq(0, &irq0);
}

/* Default timer init function */
void __init hpet_time_init(void)
{
	if (hpet_enable())
		// setup_pit_timer();
		panic("HPET fails");
	setup_default_timer_irq();
}

void __init time_init(void)
{
	hpet_time_init();
	//tsc_init();
}

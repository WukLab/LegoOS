/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/kernel.h>
#include <lego/irqdesc.h>
#include <lego/spinlock.h>

int nr_irqs = NR_IRQS;

static DECLARE_BITMAP(allocated_irqs, NR_IRQS);

struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned = {
	[0 ... NR_IRQS-1] = {
		.handle_irq	= handle_bad_irq,
		.depth		= 1,
		.lock		= __SPIN_LOCK_UNLOCKED(irq_desc->lock),
	}
};

void __init irq_init(void)
{

}

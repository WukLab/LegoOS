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

#include <asm/hw_irq.h>

#include "debug.h"

/*
 * Special, empty irq handler:
 */
irqreturn_t no_action(int cpl, void *dev_id)
{
	return IRQ_NONE;
}

/**
 *	handle_bad_irq - handle spurious and unhandled irqs
 *	@desc:      description of the interrupt
 *
 *	Handles spurious and unhandled IRQ's. It also prints a debugmessage.
 */
void handle_bad_irq(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);

	print_irq_desc(irq, desc);
	ack_bad_irq(irq);
}

/**
 *	handle_level_irq - Level type irq handler
 *	@desc:	the interrupt description structure for this irq
 *
 *	Level type interrupts are active as long as the hardware line has
 *	the active level. This may require to mask the interrupt and unmask
 *	it after the associated handler has acknowledged the device, so the
 *	interrupt line is back to inactive.
 */
void handle_level_irq(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);

	print_irq_desc(irq, desc);
}

/**
 *	handle_fasteoi_irq - irq handler for transparent controllers
 *	@desc:	the interrupt description structure for this irq
 *
 *	Only a single callback will be issued to the chip: an ->eoi()
 *	call when the interrupt has been serviced. This enables support
 *	for modern forms of interrupt handlers, which handle the flow
 *	details in hardware, transparently.
 */
void handle_fasteoi_irq(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);

	print_irq_desc(irq, desc);
}

/**
 *	handle_edge_irq - edge type IRQ handler
 *	@desc:	the interrupt description structure for this irq
 *
 *	Interrupt occures on the falling and/or rising edge of a hardware
 *	signal. The occurrence is latched into the irq controller hardware
 *	and must be acked in order to be reenabled. After the ack another
 *	interrupt can happen on the same source even before the first one
 *	is handled by the associated event handler. If this happens it
 *	might be necessary to disable (mask) the interrupt depending on the
 *	controller hardware. This requires to reenable the interrupt inside
 *	of the loop which handles the interrupts which have arrived while
 *	the handler was running. If all pending interrupts are handled, the
 *	loop is left.
 */
void handle_edge_irq(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);

	print_irq_desc(irq, desc);
}

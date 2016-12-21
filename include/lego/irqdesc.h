/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_IRQDESC_H_
#define _LEGO_IRQDESC_H_

#include <lego/irq.h>
#include <lego/spinlock.h>

/**
 * enum irqreturn
 * @IRQ_NONE		interrupt was not from this device or was not handled
 * @IRQ_HANDLED		interrupt was handled by this device
 * @IRQ_WAKE_THREAD	handler requests to wake the handler thread
 */
enum irqreturn {
	IRQ_NONE,
	IRQ_HANDLED,
	IRQ_WAKE_THREAD,
};

#define IRQ_RETVAL(x)	((x) ? IRQ_HANDLED : IRQ_NONE)

typedef enum irqreturn irqreturn_t;
typedef irqreturn_t (*irq_handler_t)(int, void *);
typedef	void (*irq_flow_handler_t)(struct irq_desc *desc);

/**
 * struct irqaction - per interrupt action descriptor
 * @handler:	interrupt handler function
 * @next:	pointer to the next irqaction for shared interrupts
 * @irq:	interrupt number
 * @flags:	flags (see IRQF_* above)
 * @thread_fn:	interrupt handler function for threaded interrupts
 * @thread:	thread pointer for threaded interrupts
 * @secondary:	pointer to secondary irqaction (force threading)
 * @thread_flags:	flags related to @thread
 * @thread_mask:	bitmask for keeping track of @thread activity
 * @name:	name of the device
 */
struct irqaction {
	irq_handler_t		handler;
	struct irqaction	*next;
	irq_handler_t		thread_fn;
	struct task_struct	*thread;
	struct irqaction	*secondary;
	unsigned int		irq;
	unsigned int		flags;
	unsigned long		thread_flags;
	unsigned long		thread_mask;
	const char		*name;
} ____cacheline_aligned;

/**
 * struct irq_desc - interrupt descriptor
 * @name:		flow handler name for /proc/interrupts output
 * @handle_irq:		highlevel irq-events handler
 * @action:		the irq action chain
 * @depth:		disable-depth, for nested irq_disable() calls
 * @lock:		locking for SMP
 */
struct irq_desc {
	const char		*name;
	irq_flow_handler_t	handle_irq;
	struct irqaction	*action;
	unsigned int		depth;
	spinlock_t		lock;
};

#endif /* _LEGO_IRQDESC_H_ */

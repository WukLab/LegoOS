/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_IRQ_H_
#define _LEGO_IRQ_H_

#include <asm/irq.h>
#include <asm/irq_vectors.h>

#include <lego/types.h>
#include <lego/typecheck.h>

static inline void local_irq_disable(void)
{
	arch_local_irq_disable();
}

static inline void local_irq_enable(void)
{
	arch_local_irq_enable();
}

#define local_irq_save(flags)			\
	do {					\
		typecheck(unsigned long, flags);\
		flags = arch_local_irq_save();	\
	} while (0)

#define local_irq_restore(flags)		\
	do {					\
		typecheck(unsigned long, flags);\
		arch_local_irq_restore(flags);	\
	} while (0)

void __init irq_init(void);
void __init arch_irq_init(void);

struct irq_desc;

/*
 * Built-in IRQ handlers for various IRQ types,
 * callable via desc->handle_irq()
 */
void handle_level_irq(struct irq_desc *desc);
void handle_bad_irq(struct irq_desc *desc);

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

#endif /* _LEGO_IRQ_H_ */

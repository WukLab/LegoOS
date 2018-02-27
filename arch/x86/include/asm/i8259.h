/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_I8259_H_
#define _ASM_X86_I8259_H_

#include <asm/io.h>
#include <lego/delay.h>
#include <lego/spinlock.h>

/*
 * Not all IRQs can be routed through the IO-APIC, eg. on certain (older)
 * boards the timer interrupt is not really connected to any IO-APIC pin,
 * it's fed to the master 8259A's IR0 line only.
 *
 * Any '1' bit in this mask means the IRQ is routed through the IO-APIC.
 * this 'mixed mode' IRQ handling costs nothing because it's only used
 * at IRQ setup time.
 */
extern unsigned long io_apic_irqs;

extern unsigned int cached_irq_mask;

#define __byte(x, y)		(((unsigned char *)&(y))[x])
#define cached_master_mask	(__byte(0, cached_irq_mask))
#define cached_slave_mask	(__byte(1, cached_irq_mask))

/* i8259A PIC registers */
#define PIC_MASTER_CMD		0x20
#define PIC_MASTER_IMR		0x21
#define PIC_MASTER_ISR		PIC_MASTER_CMD
#define PIC_MASTER_POLL		PIC_MASTER_ISR
#define PIC_MASTER_OCW3		PIC_MASTER_ISR
#define PIC_SLAVE_CMD		0xa0
#define PIC_SLAVE_IMR		0xa1

/* i8259A PIC related value */
#define PIC_CASCADE_IR		2
#define MASTER_ICW4_DEFAULT	0x01
#define SLAVE_ICW4_DEFAULT	0x01
#define PIC_ICW4_AEOI		2

extern spinlock_t i8259A_lock;

/* the PIC may need a careful delay on some platforms, hence specific calls */
static inline unsigned char inb_pic(unsigned int port)
{
	unsigned char value = inb(port);

	/*
	 * delay for some accesses to PIC on motherboard or in chipset
	 * must be at least one microsecond, so be safe here:
	 */
	udelay(2);

	return value;
}

static inline void outb_pic(unsigned char value, unsigned int port)
{
	outb(value, port);
	/*
	 * delay for some accesses to PIC on motherboard or in chipset
	 * must be at least one microsecond, so be safe here:
	 */
	udelay(2);
}

extern struct irq_chip i8259A_chip;

struct legacy_pic {
	int nr_legacy_irqs;

	/* Generic link to irq_chip */
	struct irq_chip *chip;

	void (*mask)(unsigned int irq);
	void (*unmask)(unsigned int irq);
	void (*mask_all)(void);
	void (*restore_mask)(void);
	void (*init)(int auto_eoi);
	int (*probe)(void);
	int (*irq_pending)(unsigned int irq);
	void (*make_irq)(unsigned int irq);
};

extern struct legacy_pic *legacy_pic;
extern struct legacy_pic null_legacy_pic;

static inline int nr_legacy_irqs(void)
{
	return legacy_pic->nr_legacy_irqs;
}

#endif /* _ASM_X86_I8259_H_ */

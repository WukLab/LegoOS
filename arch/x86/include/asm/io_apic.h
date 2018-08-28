/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_IO_APIC_H_
#define _ASM_X86_IO_APIC_H_

#include <asm/fixmap.h>
#include <asm/apic_types.h>
#include <asm/irq_vectors.h>

#include <lego/irqdomain.h>

enum {
	/* Allocate contiguous CPU vectors */
	X86_IRQ_ALLOC_CONTIGUOUS_VECTORS		= 0x1,
};

struct pci_dev;

enum irq_alloc_type {
	X86_IRQ_ALLOC_TYPE_IOAPIC = 1,
	X86_IRQ_ALLOC_TYPE_HPET,
	X86_IRQ_ALLOC_TYPE_MSI,
	X86_IRQ_ALLOC_TYPE_MSIX,
	X86_IRQ_ALLOC_TYPE_DMAR,
	X86_IRQ_ALLOC_TYPE_UV,
};

struct irq_alloc_info {
	enum irq_alloc_type	type;
	u32			flags;
	const struct cpumask	*mask;	/* CPU mask for vector allocation */
	union {
		int		unused;
#ifdef	CONFIG_HPET_TIMER
		struct {
			int		hpet_id;
			int		hpet_index;
			void		*hpet_data;
		};
#endif
#ifdef	CONFIG_PCI_MSI
		struct {
			struct pci_dev	*msi_dev;
			irq_hw_number_t	msi_hwirq;
		};
#endif
#ifdef	CONFIG_X86_IO_APIC
		struct {
			int		ioapic_id;
			int		ioapic_pin;
			int		ioapic_node;
			u32		ioapic_trigger : 1;
			u32		ioapic_polarity : 1;
			u32		ioapic_valid : 1;
			struct IO_APIC_route_entry *ioapic_entry;
		};
#endif
	};
};

extern void init_irq_alloc_info(struct irq_alloc_info *info,
				const struct cpumask *mask);
extern void copy_irq_alloc_info(struct irq_alloc_info *dst,
				struct irq_alloc_info *src);

/* I/O Unit Redirection Table */
#define IO_APIC_REDIR_VECTOR_MASK	0x000FF
#define IO_APIC_REDIR_DEST_LOGICAL	0x00800
#define IO_APIC_REDIR_DEST_PHYSICAL	0x00000
#define IO_APIC_REDIR_SEND_PENDING	(1 << 12)
#define IO_APIC_REDIR_REMOTE_IRR	(1 << 14)
#define IO_APIC_REDIR_LEVEL_TRIGGER	(1 << 15)
#define IO_APIC_REDIR_MASKED		(1 << 16)

/*
 * The structure of the IO-APIC:
 */
union IO_APIC_reg_00 {
	u32	raw;
	struct {
		u32	__reserved_2	: 14,
			LTS		:  1,
			delivery_type	:  1,
			__reserved_1	:  8,
			ID		:  8;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_01 {
	u32	raw;
	struct {
		u32	version		:  8,
			__reserved_2	:  7,
			PRQ		:  1,
			entries		:  8,
			__reserved_1	:  8;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_02 {
	u32	raw;
	struct {
		u32	__reserved_2	: 24,
			arbitration	:  4,
			__reserved_1	:  4;
	} __attribute__ ((packed)) bits;
};

union IO_APIC_reg_03 {
	u32	raw;
	struct {
		u32	boot_DT		:  1,
			__reserved_1	: 31;
	} __attribute__ ((packed)) bits;
};

/*
 * IOREDTBL
 * I/O Redirection Table Registers
 */
struct IO_APIC_route_entry {
	__u32	vector		:  8,
		delivery_mode	:  3,	/* 000: FIXED
					 * 001: lowest prio
					 * 111: ExtINT
					 */
		dest_mode	:  1,	/* 0: physical, 1: logical */
		delivery_status	:  1,
		polarity	:  1,
		irr		:  1,
		trigger		:  1,	/* 0: edge, 1: level */
		mask		:  1,	/* 0: enabled, 1: disabled */
		__reserved_2	: 15;

	__u32	__reserved_3	: 24,
		dest		:  8;
} __attribute__ ((packed));

struct IR_IO_APIC_route_entry {
	__u64	vector		: 8,
		zero		: 3,
		index2		: 1,
		delivery_status : 1,
		polarity	: 1,
		irr		: 1,
		trigger		: 1,
		mask		: 1,
		reserved	: 31,
		format		: 1,
		index		: 15;
} __attribute__ ((packed));

#define IOAPIC_AUTO			-1
#define IOAPIC_EDGE			0
#define IOAPIC_LEVEL			1

#define IOAPIC_MASKED			1
#define IOAPIC_UNMASKED			0

#define IOAPIC_POL_HIGH			0
#define IOAPIC_POL_LOW			1

#define IOAPIC_DEST_MODE_PHYSICAL	0
#define IOAPIC_DEST_MODE_LOGICAL	1

#define	IOAPIC_MAP_ALLOC		0x1
#define	IOAPIC_MAP_CHECK		0x2

/*
 * Some MP related
 */

#define MPC_APIC_USABLE		0x01
#define	MP_PROCESSOR		0
#define	MP_BUS			1
#define	MP_IOAPIC		2
#define	MP_INTSRC		3
#define	MP_LINTSRC		4

enum mp_irq_source_types {
	mp_INT = 0,
	mp_NMI = 1,
	mp_SMI = 2,
	mp_ExtINT = 3
};

struct mpc_intsrc {
	unsigned char type;
	unsigned char irqtype;
	unsigned short irqflag;
	unsigned char srcbus;
	unsigned char srcbusirq;
	unsigned char dstapic;
	unsigned char dstirq;
};

struct mp_ioapic_gsi {
	u32				gsi_base;
	u32				gsi_end;
};

struct mpc_ioapic {
	unsigned char			type;
	unsigned char			apicid;
	unsigned char			apicver;
	unsigned char			flags;
	unsigned int			apicaddr;
};

struct ioapic_domain_cfg {
	enum ioapic_domain_type		type;
	const struct irq_domain_ops	*ops;
};

extern const struct irq_domain_ops mp_ioapic_irqdomain_ops;

struct ioapic {
	/* # of IRQ routing registers */
	int				nr_registers;

	/*
	 * Saved state during suspend/resume,
	 * or while enabling intr-remap.
	 */
	struct IO_APIC_route_entry	*saved_registers;

	/* I/O APIC config */
	struct mpc_ioapic		mp_config;

	/* IO APIC gsi routing info */
	struct mp_ioapic_gsi		gsi_config;

	struct irq_domain		*irqdomain;
	struct ioapic_domain_cfg	irqdomain_cfg;

	struct resource			*iomem_res;
};

extern struct ioapic ioapics[MAX_IO_APICS];

extern unsigned long io_apic_irqs;

#define IO_APIC_IRQ(x) (((x) >= NR_IRQS_LEGACY) || ((1 << (x)) & io_apic_irqs))

#define MAX_MP_BUSSES		256
/* Each PCI slot may be a combo card with its own bus.  4 IRQ pins per slot. */
#define MAX_IRQ_SOURCES		(MAX_MP_BUSSES * 4)

/* # of MP IRQ source entries */
extern int mp_irq_entries;

extern DECLARE_BITMAP(mp_bus_not_pci, MAX_MP_BUSSES);

/* MP IRQ source entries */
extern struct mpc_intsrc mp_irqs[MAX_IRQ_SOURCES];

/*
 * # of IO-APICs and # of IRQ routing registers
 */
extern int nr_ioapics;

int mp_register_ioapic(int id, u32 address, u32 gsi_base, struct ioapic_domain_cfg *cfg);
int mp_find_ioapic(u32 gsi);
int mp_find_ioapic_pin(int ioapic, u32 gsi);
int mpc_ioapic_id(int ioapic);
void mp_save_irq(struct mpc_intsrc *m);

int IO_APIC_get_PCI_irq_vector(int bus, int slot, int pin);

void __init arch_ioapic_init(void);
void __init enable_IO_APIC(void);
void __init setup_IO_APIC(void);

#endif /* _ASM_X86_IO_APIC_H_ */

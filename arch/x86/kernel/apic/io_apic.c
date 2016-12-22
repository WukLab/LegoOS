/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/io.h>
#include <asm/apic.h>
#include <asm/i8259.h>
#include <asm/fixmap.h>
#include <asm/hw_irq.h>
#include <asm/io_apic.h>
#include <asm/irq_vectors.h>

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/bitmap.h>
#include <lego/resource.h>
#include <lego/spinlock.h>

#define	for_each_ioapic(idx)		\
	for ((idx) = 0; (idx) < nr_ioapics; (idx)++)
#define	for_each_ioapic_reverse(idx)	\
	for ((idx) = nr_ioapics - 1; (idx) >= 0; (idx)--)
#define	for_each_pin(idx, pin)		\
	for ((pin) = 0; (pin) < ioapics[(idx)].nr_registers; (pin)++)
#define	for_each_ioapic_pin(idx, pin)	\
	for_each_ioapic((idx))		\
		for_each_pin((idx), (pin))
#define for_each_irq_pin(entry, head) \
	list_for_each_entry(entry, &head, list)

static DEFINE_SPINLOCK(ioapic_lock);
static int ioapic_initialized;

/* The one past the highest gsi number used */
u32 gsi_top;

int nr_ioapics;

/* MP IRQ source entries */
struct mpc_intsrc mp_irqs[MAX_IRQ_SOURCES];

/* # of MP IRQ source entries */
int mp_irq_entries;

DECLARE_BITMAP(mp_bus_not_pci, MAX_MP_BUSSES);

struct irq_pin_list {
	struct list_head		list;
	int 				apic;
	int				pin;
};

struct mp_chip_data {
	struct list_head		irq_2_pin;
	struct IO_APIC_route_entry	entry;
	int				trigger;
	int				polarity;
	u32				count;
	bool				isa_irq;
};

struct mp_ioapic_gsi {
	u32				gsi_base;
	u32				gsi_end;
};

struct mpc_ioapic {
	unsigned char type;
	unsigned char apicid;
	unsigned char apicver;
	unsigned char flags;
	unsigned int apicaddr;
};

static struct ioapic {
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

	struct resource			*iomem_res;
} ioapics[MAX_IO_APICS];

static int find_free_ioapic_entry(void)
{
	int idx;

	for (idx = 0; idx < MAX_IO_APICS; idx++)
		if (ioapics[idx].nr_registers == 0)
			return idx;

	return MAX_IO_APICS;
}

int mpc_ioapic_id(int ioapic_idx)
{
	return ioapics[ioapic_idx].mp_config.apicid;
}

static inline struct mp_ioapic_gsi *mp_ioapic_gsi_routing(int ioapic_idx)
{
	return &ioapics[ioapic_idx].gsi_config;
}

#define mpc_ioapic_ver(ioapic_idx)	ioapics[ioapic_idx].mp_config.apicver

unsigned int mpc_ioapic_addr(int ioapic_idx)
{
	return ioapics[ioapic_idx].mp_config.apicaddr;
}

struct io_apic {
	unsigned int index;
	unsigned int unused[3];
	unsigned int data;
	unsigned int unused2[11];
	unsigned int eoi;
};

static inline struct io_apic __iomem *io_apic_base(int idx)
{
	return (void __iomem *) __fix_to_virt(FIX_IO_APIC_BASE_0 + idx)
		+ (mpc_ioapic_addr(idx) & ~PAGE_MASK);
}

static inline unsigned int io_apic_read(unsigned int apic, unsigned int reg)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);
	writel(reg, &io_apic->index);
	return readl(&io_apic->data);
}

static inline void io_apic_write(unsigned int apic, unsigned int reg,
			  unsigned int value)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);

	writel(reg, &io_apic->index);
	writel(value, &io_apic->data);
}

/* Will be called in mpparse/acpi/sfi codes for saving IRQ info */
void mp_save_irq(struct mpc_intsrc *m)
{
	int i;

	pr_debug("Int: type %d, pol %d, trig %d, bus %02x,"
		" IRQ %02x, APIC ID %x, APIC INT %02x\n",
		m->irqtype, m->irqflag & 3, (m->irqflag >> 2) & 3, m->srcbus,
		m->srcbusirq, m->dstapic, m->dstirq);

	for (i = 0; i < mp_irq_entries; i++) {
		if (!memcmp(&mp_irqs[i], m, sizeof(*m)))
			return;
	}

	memcpy(&mp_irqs[mp_irq_entries], m, sizeof(*m));
	if (++mp_irq_entries == MAX_IRQ_SOURCES)
		panic("Max # of irq sources exceeded!!\n");
}

static int bad_ioapic_register(int idx)
{
	union IO_APIC_reg_00 reg_00;
	union IO_APIC_reg_01 reg_01;
	union IO_APIC_reg_02 reg_02;

	reg_00.raw = io_apic_read(idx, 0);
	reg_01.raw = io_apic_read(idx, 1);
	reg_02.raw = io_apic_read(idx, 2);

	if (reg_00.raw == -1 && reg_01.raw == -1 && reg_02.raw == -1) {
		pr_warn("I/O APIC 0x%x registers return all ones, skipping!\n",
			mpc_ioapic_addr(idx));
		return 1;
	}

	return 0;
}

static u8 io_apic_unique_id(int idx, u8 id)
{
	union IO_APIC_reg_00 reg_00;
	DECLARE_BITMAP(used, 256);
	unsigned long flags;
	u8 new_id;
	int i;

	bitmap_zero(used, 256);
	for_each_ioapic(i)
		__set_bit(mpc_ioapic_id(i), used);

	/* Hand out the requested id if available */
	if (!test_bit(id, used))
		return id;

	/*
	 * Read the current id from the ioapic and keep it if
	 * available.
	 */
	spin_lock_irqsave(&ioapic_lock, flags);
	reg_00.raw = io_apic_read(idx, 0);
	spin_unlock_irqrestore(&ioapic_lock, flags);

	new_id = reg_00.bits.ID;
	if (!test_bit(new_id, used)) {
		pr_debug("IOAPIC[%d]: Using reg apic_id %d instead of %d\n",
			 idx, new_id, id);
		return new_id;
	}

	/*
	 * Get the next free id and write it to the ioapic.
	 */
	new_id = find_first_zero_bit(used, 256);
	reg_00.bits.ID = new_id;

	spin_lock_irqsave(&ioapic_lock, flags);
	io_apic_write(idx, 0, reg_00.raw);
	reg_00.raw = io_apic_read(idx, 0);
	spin_unlock_irqrestore(&ioapic_lock, flags);

	/* Sanity check */
	BUG_ON(reg_00.bits.ID != new_id);

	return new_id;
}

static int io_apic_get_version(int ioapic)
{
	union IO_APIC_reg_01	reg_01;
	unsigned long flags;

	spin_lock_irqsave(&ioapic_lock, flags);
	reg_01.raw = io_apic_read(ioapic, 1);
	spin_unlock_irqrestore(&ioapic_lock, flags);

	return reg_01.bits.version;
}

static int io_apic_get_redir_entries(int ioapic)
{
	union IO_APIC_reg_01	reg_01;
	unsigned long flags;

	spin_lock_irqsave(&ioapic_lock, flags);
	reg_01.raw = io_apic_read(ioapic, 1);
	spin_unlock_irqrestore(&ioapic_lock, flags);

	/* The register returns the maximum index redir index
	 * supported, which is one less than the total number of redir
	 * entries.
	 */
	return reg_01.bits.entries + 1;
}

int mp_find_ioapic(u32 gsi)
{
	int i;

	if (nr_ioapics == 0)
		return -1;

	/* Find the IOAPIC that manages this GSI. */
	for_each_ioapic(i) {
		struct mp_ioapic_gsi *gsi_cfg = mp_ioapic_gsi_routing(i);
		if (gsi >= gsi_cfg->gsi_base && gsi <= gsi_cfg->gsi_end)
			return i;
	}

	pr_err("ERROR: Unable to locate IOAPIC for GSI %d\n", gsi);
	return -1;
}

int mp_find_ioapic_pin(int ioapic, u32 gsi)
{
	struct mp_ioapic_gsi *gsi_cfg;

	if (WARN_ON(ioapic < 0))
		return -1;

	gsi_cfg = mp_ioapic_gsi_routing(ioapic);
	if (WARN_ON(gsi > gsi_cfg->gsi_end))
		return -1;

	return gsi - gsi_cfg->gsi_base;
}

static void alloc_ioapic_saved_registers(int idx)
{
	size_t size;

	if (ioapics[idx].saved_registers)
		return;

	size = sizeof(struct IO_APIC_route_entry) * ioapics[idx].nr_registers;
	ioapics[idx].saved_registers = kzalloc(size, GFP_KERNEL);
	if (!ioapics[idx].saved_registers)
		pr_err("IOAPIC %d: suspend/resume impossible!\n", idx);
}

static void free_ioapic_saved_registers(int idx)
{
	kfree(ioapics[idx].saved_registers);
	ioapics[idx].saved_registers = NULL;
}

/**
 * mp_register_ioapic - Register an IOAPIC device
 * @id:		hardware IOAPIC ID
 * @address:	physical address of IOAPIC register area
 * @gsi_base:	base of GSI associated with the IOAPIC
 * @cfg:	configuration information for the IOAPIC
 */
int mp_register_ioapic(int id, u32 address, u32 gsi_base)
{
	bool hotplug = !!ioapic_initialized;
	struct mp_ioapic_gsi *gsi_cfg;
	int idx, ioapic, entries;
	u32 gsi_end;

	if (!address) {
		pr_warn("Bogus (zero) I/O APIC address found, skipping!\n");
		return -EINVAL;
	}

	for_each_ioapic(ioapic)
		if (ioapics[ioapic].mp_config.apicaddr == address) {
			pr_warn("address 0x%x conflicts with IOAPIC%d\n",
				address, ioapic);
			return -EEXIST;
		}

	idx = find_free_ioapic_entry();
	if (idx >= MAX_IO_APICS) {
		pr_warn("Max # of I/O APICs (%d) exceeded (found %d), skipping\n",
			MAX_IO_APICS, idx);
		return -ENOSPC;
	}

	ioapics[idx].mp_config.type = MP_IOAPIC;
	ioapics[idx].mp_config.flags = MPC_APIC_USABLE;
	ioapics[idx].mp_config.apicaddr = address;

	set_fixmap_nocache(FIX_IO_APIC_BASE_0 + idx, address);
	if (bad_ioapic_register(idx)) {
		clear_fixmap(FIX_IO_APIC_BASE_0 + idx);
		return -ENODEV;
	}

	ioapics[idx].mp_config.apicid = io_apic_unique_id(idx, id);
	ioapics[idx].mp_config.apicver = io_apic_get_version(idx);

	/*
	 * Build basic GSI lookup table to facilitate gsi->io_apic lookups
	 * and to prevent reprogramming of IOAPIC pins (PCI GSIs).
	 */
	entries = io_apic_get_redir_entries(idx);
	gsi_end = gsi_base + entries - 1;
	for_each_ioapic(ioapic) {
		gsi_cfg = mp_ioapic_gsi_routing(ioapic);
		if ((gsi_base >= gsi_cfg->gsi_base &&
		     gsi_base <= gsi_cfg->gsi_end) ||
		    (gsi_end >= gsi_cfg->gsi_base &&
		     gsi_end <= gsi_cfg->gsi_end)) {
			pr_warn("GSI range [%u-%u] for new IOAPIC conflicts with GSI[%u-%u]\n",
				gsi_base, gsi_end,
				gsi_cfg->gsi_base, gsi_cfg->gsi_end);
			clear_fixmap(FIX_IO_APIC_BASE_0 + idx);
			return -ENOSPC;
		}
	}
	gsi_cfg = mp_ioapic_gsi_routing(idx);
	gsi_cfg->gsi_base = gsi_base;
	gsi_cfg->gsi_end = gsi_end;

	/*
	 * If mp_register_ioapic() is called during early boot stage when
	 * walking ACPI/SFI/DT tables, it's too early to create irqdomain,
	 * we are still using bootmem allocator. So delay it to setup_IO_APIC().
	 */
	if (hotplug)
		alloc_ioapic_saved_registers(idx);

	if (gsi_cfg->gsi_end >= gsi_top)
		gsi_top = gsi_cfg->gsi_end + 1;
	if (nr_ioapics <= idx)
		nr_ioapics = idx + 1;

	/* Set nr_registers to mark entry present */
	ioapics[idx].nr_registers = entries;

	pr_info("IOAPIC[%d]: apic_id %d, version %d, address 0x%x, GSI %d-%d\n",
		idx, mpc_ioapic_id(idx),
		mpc_ioapic_ver(idx), mpc_ioapic_addr(idx),
		gsi_cfg->gsi_base, gsi_cfg->gsi_end);

	return 0;
}

void __init arch_ioapic_init(void)
{
	int i;

	if (!nr_legacy_irqs())
		io_apic_irqs = ~0UL;

	for_each_ioapic(i)
		alloc_ioapic_saved_registers(i);
}

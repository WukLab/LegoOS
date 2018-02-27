/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Process ACPI tables, namely MADT and HPET,
 * to get hardware SMP configurations.
 */

#define pr_fmt(fmt) "ACPI: " fmt

#include <asm/asm.h>
#include <asm/apic.h>
#include <asm/i8259.h>
#include <asm/io_apic.h>
#include <asm/processor.h>
#include <asm/irq_vectors.h>

#include <lego/irq.h>
#include <lego/acpi.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/resource.h>
#include <lego/memblock.h>
#include <lego/early_ioremap.h>

int acpi_lapic;
int acpi_ioapic;
u64 acpi_lapic_addr = APIC_DEFAULT_PHYS_BASE;

int acpi_sci_override_gsi;

/*
 * The default interrupt routing model is PIC (8259).  This gets
 * overridden if IOAPICs are enumerated (below).
 */
enum acpi_irq_model_id acpi_irq_model = ACPI_IRQ_MODEL_PIC;

/*
 * ISA irqs by default are the first 16 gsis but can be
 * any gsi as specified by an interrupt source override.
 */
static u32 isa_irq_to_gsi[NR_IRQS_LEGACY] __read_mostly = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

#define	ACPI_INVALID_GSI		INT_MIN

int acpi_isa_irq_to_gsi(unsigned isa_irq, u32 *gsi)
{
	if (isa_irq < nr_legacy_irqs() &&
	    isa_irq_to_gsi[isa_irq] != ACPI_INVALID_GSI) {
		*gsi = isa_irq_to_gsi[isa_irq];
		return 0;
	}

	return -1;
}

/**
 * acpi_register_lapic - register a local apic and generates a logic cpu number
 * @id: local apic id to register
 * @acpiid: ACPI id to register
 * @enabled: this cpu is enabled or not
 *
 * Returns the logic cpu number which maps to the local apic
 */
static int acpi_register_lapic(int id, u32 acpiid, u8 enabled)
{
	int cpu;

	if (id >= MAX_LOCAL_APIC) {
		pr_err("Skipped apicid: %d\n", id);
		return -EINVAL;
	}

	cpu = apic_register_new_cpu(id, enabled);
	return cpu;
}

static int __init acpi_parse_madt(struct acpi_table_header *table)
{
	struct acpi_table_madt *madt = NULL;

	if (!cpu_has(X86_FEATURE_APIC))
		return -EINVAL;

	madt = (struct acpi_table_madt *)table;
	if (WARN_ON(!madt))
		return -ENODEV;

	if (madt->address) {
		/* Maybe overrided later by subtable */
		acpi_lapic_addr = (u64) madt->address;
		pr_info("Local APIC address %#x\n",
			madt->address);
	}

	return 0;
}

static int __init
acpi_parse_sapic(struct acpi_subtable_header *header, const unsigned long end)
{
	struct acpi_madt_local_sapic *processor = NULL;

	processor = (struct acpi_madt_local_sapic *)header;

	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	acpi_register_lapic((processor->id << 8) | processor->eid,	/* APIC ID */
			    processor->processor_id,			/* ACPI ID */
			    processor->lapic_flags & ACPI_MADT_ENABLED);

	return 0;
}

static int __init
acpi_parse_lapic(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_local_apic *processor = NULL;

	processor = (struct acpi_madt_local_apic *)header;

	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* Ignore invalid ID */
	if (processor->id == 0xff)
		return 0;

	/*
	 * We need to register disabled CPU as well to permit
	 * counting disabled CPUs. This allows us to size
	 * cpus_possible_map more accurately, to permit
	 * to not preallocating memory for all NR_CPUS
	 * when we use CPU hotplug.
	 */
	acpi_register_lapic(processor->id,			/* APIC ID */
			    processor->processor_id,		/* ACPI ID */
			    processor->lapic_flags & ACPI_MADT_ENABLED);

	return 0;
}

static int __init
acpi_parse_x2apic(struct acpi_subtable_header *header, const unsigned long end)
{
	struct acpi_madt_local_x2apic *processor = NULL;
	int apic_id;
	u8 enabled;

	processor = (struct acpi_madt_local_x2apic *)header;

	if (BAD_MADT_ENTRY(processor, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	apic_id = processor->local_apic_id;
	enabled = processor->lapic_flags & ACPI_MADT_ENABLED;
#ifdef CONFIG_X86_X2APIC
	/*
	 * We need to register disabled CPU as well to permit
	 * counting disabled CPUs. This allows us to size
	 * cpus_possible_map more accurately, to permit
	 * to not preallocating memory for all NR_CPUS
	 * when we use CPU hotplug.
	 */
	if (!apic->apic_id_valid(apic_id) && enabled)
		pr_warn("x2apic entry ignored\n");
	else
		acpi_register_lapic(apic_id, processor->uid, enabled);
#else
	pr_warn("x2apic entry ignored\n");
#endif

	return 0;
}

static int __init
acpi_parse_x2apic_nmi(struct acpi_subtable_header *header,
		      const unsigned long end)
{
	struct acpi_madt_local_x2apic_nmi *x2apic_nmi = NULL;

	x2apic_nmi = (struct acpi_madt_local_x2apic_nmi *)header;

	if (BAD_MADT_ENTRY(x2apic_nmi, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (x2apic_nmi->lint != 1)
		pr_warn("NMI not connected to LINT 1!\n");

	return 0;
}

static int __init
acpi_parse_lapic_nmi(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_local_apic_nmi *lapic_nmi = NULL;

	lapic_nmi = (struct acpi_madt_local_apic_nmi *)header;

	if (BAD_MADT_ENTRY(lapic_nmi, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (lapic_nmi->lint != 1)
		pr_warn("NMI not connected to LINT 1!\n");

	return 0;
}

static int __init
acpi_parse_ioapic(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_io_apic *ioapic = NULL;
	struct ioapic_domain_cfg cfg = {
		.type = IOAPIC_DOMAIN_DYNAMIC,
		.ops = &mp_ioapic_irqdomain_ops,
	};

	ioapic = (struct acpi_madt_io_apic *)header;

	if (BAD_MADT_ENTRY(ioapic, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* Statically assign IRQ numbers for IOAPICs hosting legacy IRQs */
	if (ioapic->global_irq_base < nr_legacy_irqs())
		cfg.type = IOAPIC_DOMAIN_LEGACY;

	/*
	 * Register this IO-APIC
	 * GSI: Global System Interrupt, a weird name used by ACPI only!
	 */
	mp_register_ioapic(ioapic->id, ioapic->address, ioapic->global_irq_base, &cfg);

	return 0;
}

/*
 * For legacy IRQ override
 * Typically, there are two overrides:
 *	- IRQ0
 *	- IRQ9
 */
#ifdef	CONFIG_X86_IO_APIC
#define MP_ISA_BUS		0
static void __init mp_config_acpi_legacy_irqs(void)
{
	int i;
	struct mpc_intsrc mp_irq;

	set_bit(MP_ISA_BUS, mp_bus_not_pci);
	pr_debug("Bus #%d is ISA\n", MP_ISA_BUS);

	/*
	 * Use the default configuration for the IRQs 0-15.  Unless
	 * overridden by (MADT) interrupt source override entries.
	 */
	for (i = 0; i < nr_legacy_irqs(); i++) {
		int ioapic, pin;
		unsigned int dstapic;
		int idx;
		u32 gsi;

		/* Locate the gsi that irq i maps to. */
		if (acpi_isa_irq_to_gsi(i, &gsi))
			continue;

		/*
		 * Locate the IOAPIC that manages the ISA IRQ.
		 */
		ioapic = mp_find_ioapic(gsi);
		if (ioapic < 0)
			continue;
		pin = mp_find_ioapic_pin(ioapic, gsi);
		dstapic = mpc_ioapic_id(ioapic);

		for (idx = 0; idx < mp_irq_entries; idx++) {
			struct mpc_intsrc *irq = mp_irqs + idx;

			/* Do we already have a mapping for this ISA IRQ? */
			if (irq->srcbus == MP_ISA_BUS && irq->srcbusirq == i)
				break;

			/* Do we already have a mapping for this IOAPIC pin */
			if (irq->dstapic == dstapic && irq->dstirq == pin)
				break;
		}

		if (idx != mp_irq_entries) {
			printk(KERN_DEBUG "ACPI: IRQ%d used by override.\n", i);
			continue;	/* IRQ already used */
		}

		mp_irq.type = MP_INTSRC;
		mp_irq.irqflag = 0;	/* Conforming */
		mp_irq.srcbus = MP_ISA_BUS;
		mp_irq.dstapic = dstapic;
		mp_irq.irqtype = mp_INT;
		mp_irq.srcbusirq = i;	/* Identity mapped */
		mp_irq.dstirq = pin;

		mp_save_irq(&mp_irq);
	}
}

static void __init mp_override_legacy_irq(u8 bus_irq, u8 polarity, u8 trigger,
					  u32 gsi)
{
	int ioapic;
	int pin;
	struct mpc_intsrc mp_irq;

	/*
	 * Convert 'gsi' to 'ioapic.pin'.
	 */
	ioapic = mp_find_ioapic(gsi);
	if (ioapic < 0)
		return;
	pin = mp_find_ioapic_pin(ioapic, gsi);

	/*
	 * TBD: This check is for faulty timer entries, where the override
	 *      erroneously sets the trigger to level, resulting in a HUGE
	 *      increase of timer interrupts!
	 */
	if ((bus_irq == 0) && (trigger == 3))
		trigger = 1;

	mp_irq.type = MP_INTSRC;
	mp_irq.irqtype = mp_INT;
	mp_irq.irqflag = (trigger << 2) | polarity;
	mp_irq.srcbus = MP_ISA_BUS;
	mp_irq.srcbusirq = bus_irq;			/* IRQ */
	mp_irq.dstapic = mpc_ioapic_id(ioapic);		/* APIC ID */
	mp_irq.dstirq = pin;				/* INTIN# */

	mp_save_irq(&mp_irq);

	/*
	 * BIG FAT NOTE:
	 *
	 * Reset default identity mapping if gsi is also an legacy IRQ,
	 * otherwise there will be more than one entry with the same GSI
	 * and acpi_isa_irq_to_gsi() may give wrong result.
	 *
	 * For example, if IRQ0 is overrides to GSI2, then GSI2 and IRQ2
	 * themselves are no longer used! You can check the IO-APIC interrupt
	 * redirection table for this info.
	 */
	if (gsi < nr_legacy_irqs() && isa_irq_to_gsi[gsi] == gsi)
		isa_irq_to_gsi[gsi] = ACPI_INVALID_GSI;
	isa_irq_to_gsi[bus_irq] = gsi;
}
#endif /* CONFIG_X86_IO_APIC */

static int __init
acpi_parse_nmi_src(struct acpi_subtable_header * header, const unsigned long end)
{
	struct acpi_madt_nmi_source *nmi_src = NULL;

	nmi_src = (struct acpi_madt_nmi_source *)header;

	if (BAD_MADT_ENTRY(nmi_src, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	return 0;
}

/*
 * Parse Interrupt Source Override for the ACPI SCI
 */
static void __init acpi_sci_ioapic_setup(u8 bus_irq, u16 polarity, u16 trigger, u32 gsi)
{
	if (trigger == 0)	/* compatible SCI trigger is level */
		trigger = 3;

	if (polarity == 0)	/* compatible SCI polarity is low */
		polarity = 3;

	mp_override_legacy_irq(bus_irq, polarity, trigger, gsi);

	/*
	 * TODO:
	 * Something about Houtplug?
	 */
	//acpi_penalize_sci_irq(bus_irq, trigger, polarity);

	/*
	 * stash over-ride to indicate we've been here
	 * and for later update of acpi_gbl_FADT
	 */
	acpi_sci_override_gsi = gsi;
	return;
}

static int __init
acpi_parse_int_src_ovr(struct acpi_subtable_header * header,
		       const unsigned long end)
{
	struct acpi_madt_interrupt_override *intsrc = NULL;

	intsrc = (struct acpi_madt_interrupt_override *)header;

	if (BAD_MADT_ENTRY(intsrc, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	if (intsrc->source_irq == acpi_gbl_FADT.sci_interrupt) {
		acpi_sci_ioapic_setup(intsrc->source_irq,
				      intsrc->inti_flags & ACPI_MADT_POLARITY_MASK,
				      (intsrc->inti_flags & ACPI_MADT_TRIGGER_MASK) >> 2,
				      intsrc->global_irq);
		return 0;
	}

	/* IRQ0 overrided by gsi2 */
	if (intsrc->source_irq == 0) {
		if ((intsrc->global_irq == 2)
			&& (intsrc->inti_flags & ACPI_MADT_POLARITY_MASK)) {
			intsrc->inti_flags &= ~ACPI_MADT_POLARITY_MASK;
			pr_info("BIOS IRQ0 pin2 override: forcing polarity to high active.\n");
		}
	}

	/* Override isa_irq_to_gsi[] */
	mp_override_legacy_irq(intsrc->source_irq,
				intsrc->inti_flags & ACPI_MADT_POLARITY_MASK,
				(intsrc->inti_flags & ACPI_MADT_TRIGGER_MASK) >> 2,
				intsrc->global_irq);

	return 0;
}

/*
 * Parse IOAPIC related entries in MADT
 * returns 0 on success, < 0 on error
 */
static int __init acpi_parse_madt_ioapic_entries(void)
{
	int count;

	/*
	 * Part I:
	 * Parse IO-APIC configurations:
	 */
	count = acpi_table_parse_madt(ACPI_MADT_TYPE_IO_APIC, acpi_parse_ioapic,
				      MAX_IO_APICS);
	if (!count) {
		pr_err("No IOAPIC entries present\n");
		return -ENODEV;
	} else if (count < 0) {
		pr_err("Error parsing IOAPIC entry\n");
		return count;
	}

	/*
	 * Part II:
	 * Parse possible IRQ override:
	 */
	count = acpi_table_parse_madt(ACPI_MADT_TYPE_INTERRUPT_OVERRIDE,
				      acpi_parse_int_src_ovr, NR_IRQS);
	if (count < 0) {
		pr_err("Error parsing interrupt source overrides entry\n");
		return count;
	}

	/*
	 * If BIOS did not supply an INT_SRC_OVR for the SCI
	 * pretend we got one so we can set the SCI flags:
	 */
	if (!acpi_sci_override_gsi)
		acpi_sci_ioapic_setup(acpi_gbl_FADT.sci_interrupt, 0, 0,
				      acpi_gbl_FADT.sci_interrupt);

	/* Fill in identity legacy mappings where no override */
	mp_config_acpi_legacy_irqs();

	/*
	 * Part III:
	 * Parse NMI SRC:
	 */
	count = acpi_table_parse_madt(ACPI_MADT_TYPE_NMI_SOURCE,
				      acpi_parse_nmi_src, NR_IRQS);
	if (count < 0) {
		pr_err("Error parsing NMI SRC entry\n");
		return count;
	}
	return 0;
}

static int __init acpi_parse_madt_lapic_entries(void)
{
	int ret, count = 0, x2count = 0;
	struct acpi_subtable_proc madt_proc[2];

	count = acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_SAPIC,
				      acpi_parse_sapic, MAX_LOCAL_APIC);

	/*
	 * Parse APIC
	 */

	if (!count) {
		memset(madt_proc, 0, sizeof(madt_proc));
		madt_proc[0].id = ACPI_MADT_TYPE_LOCAL_APIC;
		madt_proc[0].handler = acpi_parse_lapic;
		madt_proc[1].id = ACPI_MADT_TYPE_LOCAL_X2APIC;
		madt_proc[1].handler = acpi_parse_x2apic;
		ret = acpi_table_parse_entries_array(ACPI_SIG_MADT,
				sizeof(struct acpi_table_madt),
				madt_proc, ARRAY_SIZE(madt_proc), MAX_LOCAL_APIC);
		if (ret < 0) {
			pr_err("Error parsing LAPIC/X2APIC entries\n");
			return ret;
		}

		count = madt_proc[0].count;
		x2count = madt_proc[1].count;
	}

	if (!count && !x2count) {
		pr_err("No LAPIC entries present\n");
		return -ENODEV;
	} else if (count < 0 || x2count < 0) {
		pr_err("Error parsing LAPIC entry\n");
		return count;
	}

	x2count = acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_X2APIC_NMI,
					acpi_parse_x2apic_nmi, 0);
	count = acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_APIC_NMI,
				      acpi_parse_lapic_nmi, 0);
	if (count < 0 || x2count < 0) {
		pr_err("Error parsing LAPIC NMI entry\n");
		return count;
	}

	return 0;
}

static int __init
acpi_parse_lapic_addr_ovr(struct acpi_subtable_header * header,
			  const unsigned long end)
{
	struct acpi_madt_local_apic_override *lapic_addr_ovr = NULL;

	lapic_addr_ovr = (struct acpi_madt_local_apic_override *)header;

	if (BAD_MADT_ENTRY(lapic_addr_ovr, end))
		return -EINVAL;

	acpi_table_print_madt_entry(header);

	/* Override the default address */
	acpi_lapic_addr = lapic_addr_ovr->address;
	pr_info("Local APIC address overrided to %#llx\n", acpi_lapic_addr);

	return 0;
}

static int __init acpi_parse_madt_lapic_addr_ovr(void)
{
	int count;

	/*
	 * Note that the LAPIC address is obtained from the MADT (32-bit value)
	 * and (optionally) overridden by a LAPIC_ADDR_OVR entry (64-bit value).
	 */
	count = acpi_table_parse_madt(ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE,
				      acpi_parse_lapic_addr_ovr, 0);
	if (count < 0) {
		pr_err("Error parsing LAPIC address override entry\n");
		return count;
	}

	return count;
}

/**
 * acpi_boot_parse_madt
 *
 * Process the Multiple APIC Description Table,
 * find all possible APIC and IO-APIC settings.
 */
static void __init acpi_boot_parse_madt(void)
{
	int ret;

	ret = acpi_parse_table(ACPI_SIG_MADT, acpi_parse_madt);
	if (ret)
		return;

	/* Find possible override */
	acpi_parse_madt_lapic_addr_ovr();

	/* Now register the lapic base address */
	register_lapic_address(acpi_lapic_addr);

	ret = acpi_parse_madt_lapic_entries();
	if (!ret)
		acpi_lapic = 1;

	ret = acpi_parse_madt_ioapic_entries();
	if (!ret)
		acpi_ioapic = 1;

	/*
	 * ACPI supports both logical (e.g. Hyper-Threading)
	 * and physical processors, where MPS only supports physical.
	 */
	if (acpi_lapic && acpi_ioapic)
		pr_info("Using ACPI (MADT) for SMP configuration\n");
	else if (acpi_lapic)
		pr_info("Using ACPI for processor (LAPIC) configuration\n");
}

#ifdef CONFIG_HPET_TIMER
#include <asm/hpet.h>

static int __init acpi_parse_hpet(struct acpi_table_header *table)
{
	struct acpi_table_hpet *hpet_tbl = (struct acpi_table_hpet *)table;

	if (hpet_tbl->address.space_id != 0) {
		pr_err("HPET timers must be located in memory.\n");
		return -1;
	}

	hpet_address = hpet_tbl->address.address;
	hpet_blockid = hpet_tbl->sequence;

	/*
	 * Some broken BIOSes advertise HPET at 0x0. We really do not
	 * want to allocate a resource there.
	 */
	if (!hpet_address) {
		pr_warn("HPET id: %#x base: %#lx is invalid\n",
			hpet_tbl->id, hpet_address);
		return 0;
	}

#ifdef CONFIG_X86_64
	/*
	 * Some even more broken BIOSes advertise HPET at
	 * 0xfed0000000000000 instead of 0xfed00000. Fix it up and add
	 * some noise:
	 */
	if (hpet_address == 0xfed0000000000000UL) {
		pr_warn("HPET id: %#x base: 0xfed0000000000000 fixed up "
			"to 0xfed00000.\n", hpet_tbl->id);
		hpet_address >>= 32;
	}
#endif
	pr_info("HPET id: %#x base: %#lx\n", hpet_tbl->id, hpet_address);

	return 0;
}
#else
static inline void acpi_boot_parse_hpet(void) { };
#endif

static void __init acpi_boot_parse_hpet(void)
{
	acpi_parse_table(ACPI_SIG_HPET, acpi_parse_hpet);
}

int sbf_port __initdata = -1;

static int __init acpi_parse_sbf(struct acpi_table_header *table)
{
	struct acpi_table_boot *sb = (struct acpi_table_boot *)table;

	sbf_port = sb->cmos_index;	/* Save CMOS port */

	return 0;
}

static void __init acpi_boot_parse_sbf(void)
{
	acpi_parse_table(ACPI_SIG_BOOT, acpi_parse_sbf);
}

/*
 * Parse ACPI tables one-by-one
 * - MADT: Multiple APIC Description Table
 * - HPET: High Precision Event Timer
 */
void __init acpi_boot_parse_tables(void)
{
	acpi_boot_parse_sbf();

	acpi_boot_parse_madt();

	acpi_boot_parse_hpet();
}

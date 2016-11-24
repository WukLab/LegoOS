/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Parsing SRAT: Static Resource Affinity Table to
 * get ACPI reported NUMA setting.
 */

#include <asm/asm.h>
#include <asm/numa.h>
#include <asm/apic.h>
#include <asm/processor.h>

#include <lego/acpi.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/nodemask.h>

static unsigned char acpi_srat_revision __initdata;

static int __init
acpi_parse_srat_gicc_affinity(struct acpi_subtable_header *header,
			      const unsigned long end)
{
	struct acpi_srat_gicc_affinity *processor_affinity;

	processor_affinity = (struct acpi_srat_gicc_affinity *)header;
	if (!processor_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	return 0;
}

static int __init
acpi_parse_srat_x2apic_affinity(struct acpi_subtable_header *header,
				const unsigned long end)
{
	struct acpi_srat_x2apic_cpu_affinity *processor_affinity;

	processor_affinity = (struct acpi_srat_x2apic_cpu_affinity *)header;
	if (!processor_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	/* let architecture-dependent part to do it */
	//acpi_numa_x2apic_affinity_init(processor_affinity);

	return 0;
}

static int __init
acpi_parse_srat_cpu_affinity(struct acpi_subtable_header *header,
			     const unsigned long end)
{
	int pxm, node;
	int apicid;
	struct acpi_srat_cpu_affinity *p;

	p = (struct acpi_srat_cpu_affinity *)header;
	if (!p)
		return -EINVAL;

	if (p->header.length != sizeof(*p))
		return -EFAULT;

	if ((p->flags & ACPI_SRAT_CPU_ENABLED) == 0)
		return -ENODEV;

	pxm = p->proximity_domain_lo;
	if (acpi_srat_revision >= 2)
		pxm |= *((unsigned int*)p->proximity_domain_hi) << 8;

	node = acpi_map_pxm_to_node(pxm);
	if (node < 0) {
		pr_err("SRAT: Too many proximity domains %x\n", pxm);
		return -EFAULT;
	}

	apicid = p->apic_id;
	if (apicid >= MAX_LOCAL_APIC) {
		pr_err("SRAT: PXM %u -> APIC 0x%02x -> Node %u "
		       "skipped apicid that is too big\n", pxm, apicid, node);
		return -EFAULT;
	}

	set_apicid_to_node(apicid, node);
	node_set(node, numa_nodes_parsed);
	pr_info("SRAT: PXM %u -> APIC 0x%02x -> Node %u\n", pxm, apicid, node);

	return 0;
}

static int __init acpi_parse_srat(struct acpi_table_header *table)
{
	struct acpi_table_srat *srat;

	srat = (struct acpi_table_srat *)table;
	acpi_srat_revision = srat->header.revision;

	/* Real work done in acpi_table_parse_srat */
	return 0;
}

static int __init
acpi_parse_srat_memory_affinity(struct acpi_subtable_header * header,
				const unsigned long end)
{
	struct acpi_srat_mem_affinity *memory_affinity;

	memory_affinity = (struct acpi_srat_mem_affinity *)header;
	if (!memory_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	/* let architecture-dependent part to do it */
	//if (!acpi_numa_memory_affinity_init(memory_affinity))
	//	parsed_numa_memblks++;
	return 0;
}

void __init acpi_boot_numa_init(void)
{
	int ret, cnt;
	struct acpi_subtable_proc srat_proc[3];

	ret = acpi_parse_table(ACPI_SIG_SRAT, acpi_parse_srat);
	if (ret) {
		pr_info("SRAT not found, skip NUMA\n");
		return;
	}

	memset(srat_proc, 0, sizeof(srat_proc));
	srat_proc[0].id = ACPI_SRAT_TYPE_CPU_AFFINITY;
	srat_proc[0].handler = acpi_parse_srat_cpu_affinity;
	srat_proc[1].id = ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY;
	srat_proc[1].handler = acpi_parse_srat_x2apic_affinity;
	srat_proc[2].id = ACPI_SRAT_TYPE_GICC_AFFINITY;
	srat_proc[2].handler = acpi_parse_srat_gicc_affinity;

	acpi_table_parse_entries_array(ACPI_SIG_SRAT,
				sizeof(struct acpi_table_srat),
				srat_proc, ARRAY_SIZE(srat_proc), 0);

	cnt = acpi_table_parse_srat(ACPI_SRAT_TYPE_MEMORY_AFFINITY,
				    acpi_parse_srat_memory_affinity,
				    NR_NODE_MEMBLKS);

	/* SLIT: System Locality Information Table */
	//acpi_table_parse(ACPI_SIG_SLIT, acpi_parse_slit);
}

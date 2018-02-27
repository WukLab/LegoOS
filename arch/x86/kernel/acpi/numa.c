/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

#include <lego/pfn.h>
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

/* Proximity Domain -> x2APIC mapping */
static void __init
acpi_numa_x2apic_affinity_init(struct acpi_srat_x2apic_cpu_affinity *pa)
{
	int pxm, node;
	int apic_id;

	if (pa->header.length < sizeof(struct acpi_srat_x2apic_cpu_affinity)) {
		pr_err("SRAT: bad SRAT not used.\n");
		return;
	}
	if ((pa->flags & ACPI_SRAT_CPU_ENABLED) == 0)
		return;
	pxm = pa->proximity_domain;
	apic_id = pa->apic_id;
	if (!apic->apic_id_valid(apic_id)) {
		pr_info("SRAT: PXM %u -> X2APIC 0x%04x ignored\n",
			 pxm, apic_id);
		return;
	}
	node = acpi_map_pxm_to_node(pxm);
	if (node < 0) {
		pr_err("SRAT: Too many proximity domains %x\n", pxm);
		pr_err("SRAT: bad SRAT not used.\n");
		return;
	}

	if (apic_id >= MAX_LOCAL_APIC) {
		pr_info("SRAT: PXM %u -> APIC 0x%04x -> Node %u skipped apicid that is too big\n", pxm, apic_id, node);
		return;
	}
	set_apicid_to_node(apic_id, node);
	node_set(node, numa_nodes_parsed);
	pr_info("SRAT: PXM %u -> x2APIC 0x%04x -> Node %u\n",
	       pxm, apic_id, node);
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
	acpi_numa_x2apic_affinity_init(processor_affinity);

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

/*
 * Default callback for parsing of the Proximity Domain <-> Memory
 * Area mappings
 */
static int __init
acpi_numa_memory_affinity_init(struct acpi_srat_mem_affinity *ma)
{
	u64 start, end;
	int node, pxm;

	if (ma->header.length < sizeof(struct acpi_srat_mem_affinity)) {
		pr_err("SRAT: Unexpected header length: %d\n",
		       ma->header.length);
		goto out_err_bad_srat;
	}
	if ((ma->flags & ACPI_SRAT_MEM_ENABLED) == 0)
		goto out_err;

	start = ma->base_address;
	end = start + ma->length;
	pxm = ma->proximity_domain;
	if (acpi_srat_revision <= 1)
		pxm &= 0xff;

	node = acpi_map_pxm_to_node(pxm);
	if (node == NUMA_NO_NODE || node >= MAX_NUMNODES) {
		pr_err("SRAT: Too many proximity domains.\n");
		goto out_err_bad_srat;
	}

	if (numa_add_memblk(node, start, end) < 0) {
		pr_err("SRAT: Failed to add memblk to node %u [mem %#010Lx-%#010Lx]\n",
		       node, (unsigned long long) start,
		       (unsigned long long) end - 1);
		goto out_err_bad_srat;
	}

	node_set(node, numa_nodes_parsed);

	pr_info("SRAT: Node %u PXM %u [mem %#010Lx-%#010Lx]%s\n",
		node, pxm,
		(unsigned long long) start, (unsigned long long) end - 1,
		ma->flags & ACPI_SRAT_MEM_NON_VOLATILE ? " non-volatile" : "");

	return 0;

out_err_bad_srat:
	pr_err("SRAT: bad SRAT not used.\n");
out_err:
	return -EINVAL;
}

static int __initdata parsed_numa_memblks;

static int __init __used
acpi_parse_srat_memory_affinity(struct acpi_subtable_header * header,
				const unsigned long end)
{
	struct acpi_srat_mem_affinity *memory_affinity;

	memory_affinity = (struct acpi_srat_mem_affinity *)header;
	if (!memory_affinity)
		return -EINVAL;

	acpi_table_print_srat_entry(header);

	if (!acpi_numa_memory_affinity_init(memory_affinity))
		parsed_numa_memblks++;

	return 0;
}

/*
 * A lot of BIOS fill in 10 (= no distance) everywhere. This messes
 * up the NUMA heuristics which wants the local node to have a smaller
 * distance than the others.
 * Do some quick checks here and only use the SLIT if it passes.
 */
static int __init slit_valid(struct acpi_table_slit *slit)
{
	int i, j;
	int d = slit->locality_count;
	for (i = 0; i < d; i++) {
		for (j = 0; j < d; j++)  {
			u8 val = slit->entry[d*i + j];
			if (i == j) {
				if (val != LOCAL_DISTANCE)
					return 0;
			} else if (val <= LOCAL_DISTANCE)
				return 0;
		}
	}
	return 1;
}

/* SLIT: System Locality Information Table */
static int __init acpi_parse_slit(struct acpi_table_header *table)
{
	int i, j;
	struct acpi_table_slit *slit = (struct acpi_table_slit *)table;

	if (!slit_valid(slit)) {
		pr_info("SLIT table looks invalid. Not used.\n");
		return -EINVAL;
	}

	for (i = 0; i < slit->locality_count; i++) {
		const int from_node = pxm_to_node(i);

		if (from_node == NUMA_NO_NODE)
			continue;

		for (j = 0; j < slit->locality_count; j++) {
			const int to_node = pxm_to_node(j);

			if (to_node == NUMA_NO_NODE)
				continue;

			numa_set_distance(from_node, to_node,
				slit->entry[slit->locality_count * i + j]);
		}
	}

	return 0;
}

bool acpi_numa_disabled = false;

/*
 * Find possible NUMA configuration from ACPI tables
 * Mainly, we need to parse SRAT subtable and SLIT.
 */
void __init acpi_boot_numa_init(void)
{
	const char *reason;
	int cnt __maybe_unused;
	int ret;
	struct acpi_subtable_proc srat_proc[3];

	ret = acpi_parse_table(ACPI_SIG_SRAT, acpi_parse_srat);
	if (ret) {
		reason = "no SRAT table found";
		goto no_numa;
	}

	/*
	 * 1) CPU <--> Node Affinity
	 */
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

	/*
	 * 2) Node <--> Memory Affinity
	 */
	cnt = acpi_table_parse_srat(ACPI_SRAT_TYPE_MEMORY_AFFINITY,
				    acpi_parse_srat_memory_affinity,
				    NR_NODE_MEMBLKS);

	if (cnt < 0 || !parsed_numa_memblks) {
		reason = "fail to get Node <--> Memory affinity";
		goto no_numa;
	}

	/*
	 * 3) NUMA distance table
	 * SLIT: System Locality Information Table
	 */
	acpi_parse_table(ACPI_SIG_SLIT, acpi_parse_slit);

	return;

no_numa:
	acpi_numa_disabled = true;
	pr_info("SRAT: NUMA Disabled, because %s\n", reason);
}

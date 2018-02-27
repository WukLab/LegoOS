/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "ACPI: " fmt

#include <lego/mm.h>
#include <lego/bug.h>
#include <lego/numa.h>
#include <lego/acpi.h>
#include <lego/ctype.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/nodemask.h>

#define PXM_INVAL	(-1)

static nodemask_t nodes_found_map = { {
	[0 ... BITS_TO_LONGS(MAX_NUMNODES)-1] = 0UL
} };

/* maps to convert between proximity domain and logical node ID */
static int pxm_to_node_map[MAX_PXM_DOMAINS]
			= { [0 ... MAX_PXM_DOMAINS - 1] = NUMA_NO_NODE };
static int node_to_pxm_map[MAX_NUMNODES]
			= { [0 ... MAX_NUMNODES - 1] = PXM_INVAL };

int pxm_to_node(int pxm)
{
	if (pxm < 0)
		return NUMA_NO_NODE;
	return pxm_to_node_map[pxm];
}

int node_to_pxm(int node)
{
	if (node < 0)
		return PXM_INVAL;
	return node_to_pxm_map[node];
}

static void __acpi_map_pxm_to_node(int pxm, int node)
{
	if (pxm_to_node_map[pxm] == NUMA_NO_NODE || node < pxm_to_node_map[pxm])
		pxm_to_node_map[pxm] = node;
	if (node_to_pxm_map[node] == PXM_INVAL || pxm < node_to_pxm_map[node])
		node_to_pxm_map[node] = pxm;
}

int acpi_map_pxm_to_node(int pxm)
{
	int node;

	if (pxm < 0 || pxm >= MAX_PXM_DOMAINS)
		return NUMA_NO_NODE;

	node = pxm_to_node_map[pxm];

	if (node == NUMA_NO_NODE) {
		if (nodes_weight(nodes_found_map) >= MAX_NUMNODES)
			return NUMA_NO_NODE;
		node = first_unset_node(nodes_found_map);
		__acpi_map_pxm_to_node(pxm, node);
		node_set(node, nodes_found_map);
	}

	return node;
}

void __init acpi_table_print_srat_entry(struct acpi_subtable_header *header)
{
	switch (header->type) {
	case ACPI_SRAT_TYPE_CPU_AFFINITY:
		{
			struct acpi_srat_cpu_affinity *p =
			    (struct acpi_srat_cpu_affinity *)header;
			pr_debug("SRAT Processor (id[0x%02x] eid[0x%02x]) in proximity domain %d %s\n",
				 p->apic_id, p->local_sapic_eid,
				 p->proximity_domain_lo,
				 (p->flags & ACPI_SRAT_CPU_ENABLED) ?
				 "enabled" : "disabled");
		}
		break;

	case ACPI_SRAT_TYPE_MEMORY_AFFINITY:
		{
			struct acpi_srat_mem_affinity *p =
			    (struct acpi_srat_mem_affinity *)header;
			pr_debug("SRAT Memory (0x%lx length 0x%lx) in proximity domain %d %s%s%s\n",
				 (unsigned long)p->base_address,
				 (unsigned long)p->length,
				 p->proximity_domain,
				 (p->flags & ACPI_SRAT_MEM_ENABLED) ?
				 "enabled" : "disabled",
				 (p->flags & ACPI_SRAT_MEM_HOT_PLUGGABLE) ?
				 " hot-pluggable" : "",
				 (p->flags & ACPI_SRAT_MEM_NON_VOLATILE) ?
				 " non-volatile" : "");
		}
		break;

	case ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY:
		{
			struct acpi_srat_x2apic_cpu_affinity *p =
			    (struct acpi_srat_x2apic_cpu_affinity *)header;
			pr_debug("SRAT Processor (x2apicid[0x%08x]) in proximity domain %d %s\n",
				 p->apic_id,
				 p->proximity_domain,
				 (p->flags & ACPI_SRAT_CPU_ENABLED) ?
				 "enabled" : "disabled");
		}
		break;

	case ACPI_SRAT_TYPE_GICC_AFFINITY:
		{
			struct acpi_srat_gicc_affinity *p =
			    (struct acpi_srat_gicc_affinity *)header;
			pr_debug("SRAT Processor (acpi id[0x%04x]) in proximity domain %d %s\n",
				 p->acpi_processor_uid,
				 p->proximity_domain,
				 (p->flags & ACPI_SRAT_GICC_ENABLED) ?
				 "enabled" : "disabled");
		}
		break;

	default:
		pr_warn("Found unsupported SRAT entry (type = 0x%x)\n",
			header->type);
		break;
	}
}

/**
 * acpi_table_parse_srat
 *
 * Parse SRAT subtable
 */
int __init
acpi_table_parse_srat(enum acpi_srat_type id,
		      acpi_tbl_entry_handler handler, unsigned int max_entries)
{
	return acpi_table_parse_entries(ACPI_SIG_SRAT,
					    sizeof(struct acpi_table_srat), id,
					    handler, max_entries);
}

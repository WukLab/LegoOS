/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/init.h>
#include <lego/mm.h>
#include <lego/net.h>
#include <lego/kthread.h>
#include <lego/workqueue.h>
#include <lego/list.h>
#include <lego/string.h>
#include <lego/jiffies.h>
#include <lego/pci.h>
#include <lego/delay.h>
#include <lego/slab.h>
#include <lego/time.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <rdma/ib_verbs.h>

#include <uapi/fit.h>

#include "fit_internal.h"

/* Built based on node id */
struct fit_machine_info *lego_cluster[CONFIG_FIT_NR_NODES];

/*
 * NOTE:
 * This array specifies hostname of machines you want to use in Lego cluster.
 * Hostnames are listed by the order of FIT node ID. Any wrong configuration
 * lead to an early panic. Using hostname is more convenient that just using
 * raw numbers.
 */
static const char *lego_cluster_hostnames[CONFIG_FIT_NR_NODES] = {
	[0]	=	"node0",
	[1]	=	"node1",
};

static struct fit_machine_info WUKLAB_CLUSTER[] = {
	[0]	= {	.hostname =	"node0",	.lid =	42,	},
	[1]	= {	.hostname =	"node1",	.lid =	23,	},
	[2]	= {	.hostname =	"node2",	.lid =	8,	},
	[3]	= {	.hostname =	"node3",	.lid =	9,	},
};

/* Indicate machines that are used by lego */
static DECLARE_BITMAP(cluster_used_machines, 32);

/* Exposed array used by FIT code */
unsigned int global_lid[CONFIG_FIT_NR_NODES];
unsigned int first_qpn[CONFIG_FIT_NR_NODES];

unsigned int get_node_global_lid(unsigned int nid)
{
	BUG_ON(nid >= CONFIG_FIT_NR_NODES);
	return global_lid[nid];
}

unsigned int get_node_first_qpn(unsigned int nid)
{
	return CONFIG_FIT_FIRST_QPN;
}

/*
 * Fill the lego_cluster, global_lid, first_qpn array.
 * Return 0 on success, return 1 if duplicates
 */
static int assign_fit_machine(unsigned int nid, struct fit_machine_info *machine)
{
	unsigned int machine_index;

	machine_index = machine - WUKLAB_CLUSTER;
	if (test_and_set_bit(machine_index, cluster_used_machines))
		return 1;

	lego_cluster[nid] = machine;
	global_lid[nid] = lego_cluster[nid]->lid;
	first_qpn[nid] = get_node_first_qpn(nid);

	return 0;
}

static struct fit_machine_info *find_fit_machine(const char *hostname)
{
	struct fit_machine_info *machine;
	int i;

	/* Linear search for a small cluster */
	for (i = 0; i < ARRAY_SIZE(WUKLAB_CLUSTER); i++) {
		machine = &WUKLAB_CLUSTER[i];
		if (!strncmp(hostname, machine->hostname, FIT_HOSTNAME_MAX))
			return machine;
	}
	return NULL;
}

/*
 * Statically setting LIDs and QPNs now
 * since we don't have socket working
 */
void init_global_lid_qpn(void)
{
	int nid;
	bool bug = false;

#if defined(CONFIG_FIT_LOCAL_ID) && defined(CONFIG_FIT_NR_NODES)
	BUILD_BUG_ON(CONFIG_FIT_LOCAL_ID >= CONFIG_FIT_NR_NODES);
#else
	BUILD_BUG_ON(1);
#endif

	/*
	 * Build the machine list based on user provided
	 * hostnames, including global_lid array and first_qpn.
	 */
	for (nid = 0; nid < CONFIG_FIT_NR_NODES; nid++) {
		struct fit_machine_info *machine;
		const char *hostname = lego_cluster_hostnames[nid];

		if (!hostname) {
			pr_info("    Empty hostname on node %d\n", nid);
			bug = true;
			continue;
		}

		machine = find_fit_machine(hostname);
		if (!machine) {
			pr_info("    Wrong hostname %s on node %d\n",
				hostname, nid);
			bug = true;
			continue;
		}

		if (assign_fit_machine(nid, machine)) {
			pr_info("    Duplicated hostname %s on node %d\n",
				hostname, nid);
			bug = true;
		}
	}
	if (bug)
		panic("Please check your network config!");
}

void print_gloabl_lid(void)
{
	int nid;

	pr_info("***\n");
	pr_info("***  FIT_initial_timeout_s:   %d\n", CONFIG_FIT_INITIAL_SLEEP_TIMEOUT);
	pr_info("***  FIT_LOCAL_ID:            %d\n", CONFIG_FIT_LOCAL_ID);
	pr_info("***  FIT_FIRST_QPN:           %d\n", CONFIG_FIT_FIRST_QPN);
	pr_info("***  FIT_NR_QPS_PER_PAIR:     %d\n", CONFIG_FIT_NR_QPS_PER_PAIR);
	pr_info("***  FIT_MAX_SEND_WR:         %d\n", CONFIG_FIT_MAX_OUTSTANDING_SEND);
	pr_info("***\n");
	pr_info("***    NodeID    Hostname    LID    QPN\n");
	pr_info("***    -------------------------------------\n");
	for (nid = 0; nid < CONFIG_FIT_NR_NODES; nid++) {
		pr_info("***    %6d    %s    %3d    %3d",
			nid, lego_cluster[nid]->hostname,
			get_node_global_lid(nid),
			get_node_first_qpn(nid));

		if (nid == CONFIG_FIT_LOCAL_ID)
			printk(KERN_CONT " <---\n");
		else
			printk(KERN_CONT "\n");
	}
	pr_info("***\n");
}

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

/*
 * NOTE:
 * This array specifies hostname of machines you want to use in Lego cluster.
 * Hostnames are listed by the order of FIT node ID. Any wrong configuration
 * lead to an early panic.
 */
/* Built based on node id */
struct fit_machine_info *lego_cluster[CONFIG_FIT_NR_NODES];

#ifdef CONFIG_SAME_MACHINE_VMS
/*
 * multiple VMs on the same machine
 * only need to change lid below
 * NOTE: always start vm1 first, then vm2, etc.
 */
static const char *lego_cluster_hostnames[CONFIG_FIT_NR_NODES] = {
	[0]	= 	"vm1",
	[1]	= 	"vm2",
	[2]	= 	"vm3",
};

static struct fit_machine_info WUKLAB_CLUSTER[] = {
[0]	= {	.hostname =	"vm1",	.lid =	21,	.first_qpn =	72,	},
[1]	= {	.hostname =	"vm2",	.lid =	21,	.first_qpn =	72,	},
[2]	= {	.hostname =	"vm3",	.lid =	21,	.first_qpn =	72,	},
};
#else
static const char *lego_cluster_hostnames[CONFIG_FIT_NR_NODES] = {
	[0]	= 	"wuklab00",
	[1]	= 	"wuklab02",
	[2]	= 	"wuklab03",
	[3]	= 	"wuklab07",
};

static struct fit_machine_info WUKLAB_CLUSTER[] = {
[0]	= {	.hostname =	"wuklab00",	.lid =	2,	.first_qpn =	0,	},
[1]	= {	.hostname =	"wuklab01",	.lid =	6,	.first_qpn =	72,	},
[2]	= {	.hostname =	"wuklab02",	.lid =	8,	.first_qpn =	72,	},
[3]	= {	.hostname =	"wuklab03",	.lid =	9,	.first_qpn =	74,	},
[4]	= {	.hostname =	"wuklab04",	.lid =	7,	.first_qpn =	72,	},
[5]	= {	.hostname =	"wuklab05",	.lid =	3,	.first_qpn =	0,	},
[6]	= {	.hostname =	"wuklab06",	.lid =	5,	.first_qpn =	0,	},
[7]	= {	.hostname =	"wuklab07",	.lid =	4,	.first_qpn =	74,	},
[8]	= {	.hostname =	"wuklab08",	.lid =	10,	.first_qpn =	72,	},
[9]	= {	.hostname =	"wuklab09",	.lid =	12,	.first_qpn =	72,	},
[10]	= {	.hostname =	"wuklab10",	.lid =	14,	.first_qpn =	74,	},
[11]	= {	.hostname =	"wuklab11",	.lid =	11,	.first_qpn =	74,	},
[12]	= {	.hostname =	"wuklab12",	.lid =	13,	.first_qpn =	72,	},
[13]	= {	.hostname =	"wuklab13",	.lid =	15,	.first_qpn =	72,	},
[14]	= {	.hostname =	"wuklab14",	.lid =	16,	.first_qpn =	74,	},
[15]	= {	.hostname =	"wuklab15",	.lid =	17,	.first_qpn =	72,	},
[16]	= {	.hostname =	"wuklab16",	.lid =	20,	.first_qpn =	74,	},
[17]	= {	.hostname =	"wuklab17",	.lid =	21,	.first_qpn =	0,	},
[18]	= {	.hostname =	"wuklab18",	.lid =	19,	.first_qpn =	0,	},
[19]	= {	.hostname =	"wuklab19",	.lid =	18,	.first_qpn =	72,	},
};
#endif

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
	BUG_ON(nid >= CONFIG_FIT_NR_NODES);
#ifdef CONFIG_SAME_MACHINE_VMS
	return first_qpn[nid] + MAX_CONNECTION * nid;
#else
	return first_qpn[nid];
#endif
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

	/* Sanity Check */
	if (machine->first_qpn == 0) {
		pr_info("******\n");
		pr_info("******      WARNING: %s first_qpn not finalized, "
			"default to use 72\n", machine->hostname);
		pr_info("******\n");
		machine->first_qpn = 72;
	}

	lego_cluster[nid] = machine;
	global_lid[nid] = lego_cluster[nid]->lid;
	first_qpn[nid] = lego_cluster[nid]->first_qpn;

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

	pr_info("***  FIT_initial_timeout_s:   %d\n", CONFIG_FIT_INITIAL_SLEEP_TIMEOUT);
	pr_info("***  FIT_local_id:            %d\n", CONFIG_FIT_LOCAL_ID);
	pr_info("***\n");
	pr_info("***    NodeID    Hostname    LID    QPN\n");
	pr_info("***    -------------------------------------\n");
	for (nid = 0; nid < CONFIG_FIT_NR_NODES; nid++) {
		pr_info("***    %6d    %s    %3d    %3d",
			nid, lego_cluster[nid]->hostname,
			get_node_global_lid(nid),
			get_node_first_qpn(nid));

		if (nid == CONFIG_FIT_LOCAL_ID)
			pr_cont(" <---\n");
		else
			pr_cont("\n");
	}
	pr_info("***\n");
}

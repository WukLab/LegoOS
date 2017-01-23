#include "ns.h"
#include <inc/lib.h>

extern union Nsipc nsipcbuf;

#define debug 0

// Virtual address at which to receive page mappings containing client requests.
struct jif_pkt *sendReq = (struct jif_pkt *)(0x0ffff000 - PGSIZE);

void
output(envid_t ns_envid)
{
    binaryname = "ns_output";

    // LAB 6: Your code here:
    // 	- read a packet from the network server
    //	- send the packet to the device driver

	void* buf = NULL;
	size_t len = 0;
	//struct jif_pkt *sendReq;
	uint32_t req, whom;
	int perm, r;

	while (1) {
		perm = 0;

		cprintf("output env id %d \n", thisenv->env_id);

		req = ipc_recv((int32_t *) &whom, sendReq, &perm);
		while(thisenv->env_ipc_recving == 1)
			sys_yield();

		if (debug)
			cprintf("net packet send req %d from %08x [page %08x: %s]\n",
				req, whom, uvpt[PGNUM(sendReq)], sendReq);

		// All requests must contain an argument page
		if (!(perm & PTE_P)) {
			cprintf("Invalid request from %08x: no argument page\n",
				whom);
			continue; // just leave it hanging...
		}
		//if(debug)
		//	cprintf("output data %s",sendReq->jp_data);

		if(req == NSREQ_OUTPUT)
		{	
			while(sys_net_tx((void*)sendReq->jp_data, sendReq->jp_len) != 0)
			{
				sys_yield();
			}
		}else {
			cprintf("Invalid request code %d from %08x\n", req, whom);
			r = -E_INVAL;
		}
		
		if(debug)
			cprintf("Net Output: Sent packet to kernel %d to %x\n", r, whom);
		sys_page_unmap(0, sendReq);
		
    }
}


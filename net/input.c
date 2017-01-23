#include "ns.h"

extern union Nsipc nsipcbuf;

#define debug 0

void
input(envid_t ns_envid)
{
    binaryname = "ns_input";

    // LAB 6: Your code here:
    // 	- read a packet from the device driver
    //	- send it to the network server
    // Hint: When you IPC a page to the network server, it will be
    // reading from it for a while, so don't immediately receive
    // another packet in to the same physical page.

	int length = 0;
	int type = NSREQ_INPUT;
	int result = 0;
	//Allocate page for data transfer
	//cprintf("Addresses %x %x\n", &nsipcbuf.pkt, &nsipcbuf);


	while(1)
	{		

		if ((result = sys_page_alloc(0, &nsipcbuf.pkt, PTE_P|PTE_U|PTE_W)) < 0)
			panic("sys_page_alloc: %e", result);
		
		//read a packet from the device driver
        while((length = sys_net_rx(&nsipcbuf.pkt.jp_data)) <= 0)
	    { 
	    	sys_yield();
	    }
		nsipcbuf.pkt.jp_len = length;
		
		if (debug)
			cprintf("[%08x] nsipc %d %08x\n", thisenv->env_id, type, *(uint32_t *)&nsipcbuf);

		//send it to the network server
		ipc_send(ns_envid, type, &nsipcbuf.pkt, PTE_P | PTE_W | PTE_U);	

		//Let server process this
		sys_yield();

		//If allocating new page each time		
        sys_page_unmap(0, &nsipcbuf.pkt.jp_data);
	}

}

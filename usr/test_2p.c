#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <stdio.h>
#include <linux/unistd.h>
#include "includeme.h"

#include <lego/rpc/struct_common.h>
#include <lego/fit_ibapi.h>

#define TEST_MSG_LEN 20

int main(void)
{
	printf("nid: %d\n", get_local_nid());

	int my_nid = get_local_nid();

	//SENDER
	if (my_nid == 0) {

		void *msg;

		msg = mallaoc(sizeof(struct common_header) + TEST_MSG_LEN);

		struct common_header *hdr;

		hdr = to_common_header(msg);
		hdr->opcode = 123;
		hdr->src_nid = my_nid;

		void *payload;
		payload = to_payload(msg);
		strcpy(payload, "HELLO FROM NODE 0\n");



		ibapi_send(1, msg, sizeof(struct common_header) + TEST_MSG_LEN);
	}

	// RECEIVER
	else {

		prinft("HI I'm %d", my_nid);
	}
	
}

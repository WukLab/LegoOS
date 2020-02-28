#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <stdio.h>
#include <linux/unistd.h>
#include "includeme.h"

int main(void)
{
	printf("nid: %d\n", get_local_nid());

	int my_nid = get_local_nid();

	//SENDER
	if (my_nid == 0) {
		printf("HI I'm Sender %d", my_nid);
		recho(1);
	}

	// RECEIVER
	else {
		printf("HI I'm Receiver %d", my_nid);
	}
	
}

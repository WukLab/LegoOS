#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <stdio.h>
#include <linux/unistd.h>
#include "includeme.h"


#include <lego/fit_ibapi.h>


int main(void)
{
	printf("nid: %d\n", get_local_nid());

	// int my_nid = get_local_nid();

	// //SENDER
	// if (my_nid == 0) {

	// 	struct p2m_test_msg *msg;


	// 	msg = send_buf;
	// fill_common_header(msg, P2M_TEST_NOREPLY);
	// msg->send_len = send_len;
	// msg->reply_len = reply_len;

	// start_ns = sched_clock();
	// for (i = 0; i < NR_TESTS; i++) {
	// 	ibapi_send(dst_nid, msg, msg->send_len);
	// }

	// }

	// // RECEIVER
	// else {

	// }
	
}

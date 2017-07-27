#include "common.h"
#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/param.h>
#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static void send_read_request(void *data){
	struct m2s_read payload;
	payload.pid = 23;
	strcpy(payload.filename, "/root/yilun/testfile1");

	int ret;
	char retbuf[MAX_FILENAME_LENGTH];

	ret = net_send_reply_timeout(0, M2S_READ, &payload,
				sizeof(payload), &retbuf, sizeof(retbuf), false,
				DEF_MAX_TIMEOUT);
	
	
}

static int __init init_test(void) {


	struct task_struct *tsk;
	tsk = kthread_run(send_read_request, NULL, "stroage server kthread.[%d]", 1);
	if (IS_ERR(tsk)){
		printk("kthread create failed.\n\n");
		return 0;
	
	}
}

static void __exit stop_test(void) {
	printk(KERN_INFO "Bye, test send!\n");
}

module_init(init_test);
module_exit(stop_test);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yilun");

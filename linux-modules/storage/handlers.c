#include "storage.h"
#include "common.h"
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/param.h>
#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/mutex.h>
#include <linux/mm.h>

//need add buf later;
static int handle_read_request(request *rq, void *buf){
	int metadata_entry, user_entry;
	int ret;

	ret = grant_access(rq, &metadata_entry, &user_entry);
	if (ret != OP_SUCCESS){
		return ret;
	}
	struct file *filp;
	filp = local_file_open(rq);
	if (IS_ERR(filp)){
		return PTR_ERR(filp);
	}
	ret = local_file_read(filp, (const char __user *)buf, rq->len, &rq->offset);
	local_file_close(filp);
	yield_access(metadata_entry, user_entry);
	return ret;
}

static int handle_write_request(request *rq, void *buf){
	struct file *filp;
	int metadata_entry, user_entry;
	int ret;
	
	//the file exist but not grant to access
	ret = grant_access(rq, &metadata_entry, &user_entry);
	if (ret != OP_SUCCESS){
		return ret;
	}

	filp = local_file_open(rq);
	if (IS_ERR(filp)){
		return PTR_ERR(filp);
	}
	ret = local_file_write(filp, (const char __user *)buf, rq->len, &rq->offset);
	local_file_close(filp);
	yield_access(metadata_entry, user_entry);
	return ret;
}

int handle_fake_read(void *payload){
	struct m2s_read *rx;
	rx = (struct m2s_read *) payload;

	printk("received filename %s\n", rx->filename);
	return 1;
}

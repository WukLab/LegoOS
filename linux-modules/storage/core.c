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

#define MAX_RXBUF_SIZE PAGE_SIZE

// File metadata structure
struct metadata global_metadata[MAX_SIZE];
struct mutex metadata_lock;

static int init_metadata(void) {

	struct metadata fake_metadata[MAX_SIZE];

	int i, j;
	ssize_t ret;

	for (i=0; i<MAX_SIZE; i++) {
		for (j=0; j<MAX_USERS_ALLOWED; j++) {
			fake_metadata[i].users[j] = -1;
		}
	fake_metadata[i].noOfUsers = 0;
	fake_metadata[i].permission = 077;
	fake_metadata[i].used = 0;
	fake_metadata[i].owner = -1;
	strcpy(fake_metadata[i].fileName, "");
	}

	//aquire metadata lock
	mutex_lock(&metadata_lock);
	struct file *filp;

	//metadata not executable.
	filp = filp_open(FILE_METADATA, O_CREAT | O_WRONLY, 0644);

	if (IS_ERR(filp))
	{
		printk("init_metadata : Error opening metadata file.\n");
		//release lock
		mutex_unlock(&metadata_lock);
		return OP_FAILURE;
	}
	//char *buf = kmalloc(sizeof(struct metadata)*MAX_SIZE, GFP_KERNEL);
	//memcpy(buf, fake_metadata, sizeof(struct metadata)*MAX_SIZE);
	
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = filp->f_op->write(filp, (char *)fake_metadata, sizeof(struct metadata)*MAX_SIZE, &filp->f_pos);
	set_fs(old_fs);
	if (ret != sizeof(struct metadata)*MAX_SIZE){
		printk("init_metadata : ret [%lu], metadata [%lu] not match.\n", ret, sizeof(struct metadata)*MAX_SIZE);
		if (ret == -EFAULT){
			printk("init_metadata : -EFAULT.\n");		
		}
		filp_close(filp, NULL);
		//release_lock
		mutex_unlock(&metadata_lock);
		return OP_FAILURE;	
	}
	filp_close(filp, NULL);
	//release lock
	mutex_unlock(&metadata_lock);
	printk("init_metadata : Opened the metadata file successfully.\n");

	return OP_SUCCESS;
}

static void stroage_dispatch(void *msg){
	struct common_header *hdr;
	void *payload;

	hdr = to_common_header(msg);
	payload = to_payload(msg);

	switch(hdr->opcode){
		case M2S_READ:
			handle_fake_read(payload);
			break;
	}
	return;
}

static void storage_manager(void *data){
	int port = 0;
	void *msg;
	unsigned long desc;
	struct task_struct *tsk;
	int retlen;

	msg = kmalloc(MAX_RXBUF_SIZE, GFP_KERNEL);


	if (unlikely(!msg)){
		WARN_ON(1);
		return;
	}

	while(1){
		retlen = ibapi_receive_message(port, msg, MAX_RXBUF_SIZE, &desc);
		if (unlikely(retlen >= MAX_RXBUF_SIZE))
			panic("Fatal : retlen %d MAX_RETBUF_SIZE %lu", retlen, MAX_RXBUF_SIZE);

		tsk = kthread_run(stroage_dispatch, msg, "storage_dispatch");
		if (unlikely(IS_ERR(tsk))){
			WARN_ON(1);
			return;
		}
	}
	return;	
}

static int __init init_storage_server(void) {

	mutex_init(&metadata_lock);
	int i;
	struct file *filp;

	while (IS_ERR(filp = filp_open(FILE_METADATA, O_RDWR, 0))) {
		printk("init_storage_server : Calling init_metadata function.\n");
		if (init_metadata() == OP_FAILURE) {
			return OP_FAILURE;
    		}
	}

	//This is the only time calling get metadata
	get_metadata();
	//dump_metadata();

	struct task_struct *tsk;
	tsk = kthread_run(storage_manager, NULL, "stroage server kthread.[%d]", 1);
	if (IS_ERR(tsk)){
		printk("kthread create failed.\n\n");
		return OP_FAILURE;
	
	}

	//dump_metadata();
	return OP_SUCCESS;
}

static void __exit stop_storage_server(void) {
	printk(KERN_INFO "Bye, storage server!\n");
}

module_init(init_storage_server);
module_exit(stop_storage_server);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yilun");

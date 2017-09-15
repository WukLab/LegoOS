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

#define MAX_RXBUF_SIZE	\
	(5*BLK_SIZE+sizeof(__u32)+sizeof(struct m2s_read_write_payload))

// File metadata structure
struct metadata global_metadata[MAX_SIZE];
struct mutex metadata_lock;

struct info_struct {
	uintptr_t desc;
	char msg[MAX_RXBUF_SIZE];
};

static int init_metadata(void)
{
	struct metadata fake_metadata[MAX_SIZE];
	int i, j;
	ssize_t ret;
	struct file *filp;

	for (i=0; i<MAX_SIZE; i++) {
		for (j=0; j<MAX_USERS_ALLOWED; j++) {
			fake_metadata[i].users[j] = -1;
		}
		fake_metadata[i].noOfUsers = 0;
		fake_metadata[i].permission = 0777;
		fake_metadata[i].used = 0;
		fake_metadata[i].owner = -1;
		strcpy(fake_metadata[i].fileName, "");
	}

	//aquire metadata lock
	mutex_lock(&metadata_lock);

	//metadata not executable.
	filp = filp_open(FILE_METADATA, O_CREAT | O_WRONLY, 0644);

	if (IS_ERR(filp)) {
		printk("init_metadata : Error opening metadata file.\n");
		//release lock
		mutex_unlock(&metadata_lock);
		return OP_FAILURE;
	}
	
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = filp->f_op->write(filp, (char *)fake_metadata, sizeof(struct metadata)*MAX_SIZE, &filp->f_pos);
	set_fs(old_fs);
	if (ret != sizeof(struct metadata)*MAX_SIZE) {
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

static void storage_dispatch(void *msg, uintptr_t desc)
{
	__u32 *opcode;
	void *payload;

	opcode = msg;
	payload = msg + sizeof(*opcode);

#ifdef DEBUG_STORAGE
	pr_info("storage_dispatch : check pointer address : \n");
	pr_info("msg %lu\n", msg);
#endif

	switch (*opcode) {
	case M2S_READ:
		handle_read_request(payload, desc);
		break;
	case M2S_WRITE:
		handle_write_request(payload, desc);
		break;
	case P2S_OPEN:
		handle_open_request(payload, desc);
		break;
	}
	return;
}

static void storage_manager(void *data)
{
	int retlen;
	void *msg;
	uintptr_t desc;

	msg = kmalloc(MAX_RXBUF_SIZE, GFP_KERNEL);
	if (!msg) {
		WARN_ON(1);
		return;
	}

	while(1) {
		retlen = ibapi_receive_message(0, msg, MAX_RXBUF_SIZE, &desc);
		if (unlikely(retlen >= MAX_RXBUF_SIZE)) {
			WARN(1, "retlen=%d MAX_RETBUF_SIZE=%lu", retlen, MAX_RXBUF_SIZE);
			break;
		}

		storage_dispatch(msg, desc);
	}
	return;	
}

static int __init init_storage_server(void)
{
	int i;
	struct file *filp;
	struct task_struct *tsk;

	mutex_init(&metadata_lock);

	while (IS_ERR(filp = filp_open(FILE_METADATA, O_RDWR, 0))) {
		printk("init_storage_server : Calling init_metadata function.\n");
		if (init_metadata() == OP_FAILURE) {
			return -1;
    		}
	}

	//This is the only time calling get metadata
	get_metadata();

	tsk = kthread_run(storage_manager, NULL, "storage_server kthread");
	if (IS_ERR(tsk)){
		printk("kthread create failed.\n\n");
		return -1;
	
	}

	//dump_metadata();
	return 0;
}

static void __exit stop_storage_server(void) {
	printk(KERN_INFO "Bye, storage server!\n");
}

module_init(init_storage_server);
module_exit(stop_storage_server);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yilun");

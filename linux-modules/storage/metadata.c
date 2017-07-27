#include "storage.h"
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/param.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/kernel.h>
#include <linux/kthread.h>

/* get_metadata()
 * get the newest metadata from storage to memory
 */

int get_metadata(void){
	printk("get_metadata enter.\n\n");
	char metadata_buf[4096];
	ssize_t ret;
	struct file *metadata_filp;
	metadata_filp = filp_open(FILE_METADATA, O_RDONLY, 0);
	if (IS_ERR(metadata_filp)){
		printk("get_metadata : Error to open metadata file.\n");
		return OP_FAILURE;
	}

	loff_t pos = 0;
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = metadata_filp->f_op->read(metadata_filp, metadata_buf, sizeof(struct metadata)*MAX_SIZE, &pos);
	set_fs(old_fs);

	if (ret == -EFAULT || ret != sizeof(struct metadata)*MAX_SIZE){
		printk("get_metadata : Incorrect metadata file length [%lu].\n", ret);
		return OP_FAILURE;
	}
	
	memcpy(global_metadata, metadata_buf, sizeof(struct metadata)*MAX_SIZE);
	printk("get_metadata success.\n");
	return OP_SUCCESS;
}

/* update_metadata()
 * Update newest memory metadata to storage
 */

int update_metadata(void){
	ssize_t ret;

	//metadata_lock;
	mutex_lock(&metadata_lock);
	struct file *filp;
	filp = filp_open(FILE_METADATA, O_WRONLY, 0);
	if (IS_ERR(global_metadata) || IS_ERR(filp)){
		filp_close(filp, NULL);
		//release_lock;
		mutex_unlock(&metadata_lock);
		return OP_FAILURE;
	}
	loff_t pos = 0;
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = filp->f_op->write(filp, global_metadata, sizeof(struct metadata)*MAX_SIZE, &pos);
	set_fs(old_fs);
	if (ret == -EFAULT || ret != sizeof(struct metadata)*MAX_SIZE){
		filp_close(filp, NULL);
		//release_lock;
		mutex_unlock(&metadata_lock);
		return OP_FAILURE;	
	}
	filp_close(filp, NULL);
	//release _lock
	mutex_unlock(&metadata_lock);
	return OP_SUCCESS;
	
}

void dump_metadata(void){
	int i, j;
	for (i = 0; i < MAX_SIZE; i++){
		//Only dump filename and permission
		printk("********************************************************\n");
		printk("filename : %s.\n", global_metadata[i].fileName);

		/*print file user list */
		printk("file user list : ");
		for (j = 0; j < MAX_USERS_ALLOWED; j++){
			printk("%d   ", global_metadata[i].users[j]);
		}
		printk("\n");
		printk("file active users : %d\n", global_metadata[i].noOfUsers);
		printk("file permission : %d.\n", global_metadata[i].permission);
		printk("file used : %d\n", global_metadata[i].used);
		printk("file owner : %d\n", global_metadata[i].owner);
		printk("********************************************************\n");
	}

}


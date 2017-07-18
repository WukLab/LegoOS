/*****
Author  : Sumukh Hallymysore Ravindra
Date    : Mar 11, 2017
Purpose : Handle file requests from user space
 		  Abstraction for disaggregated storage device by modifications to the kernel
******/

#include "core.h"
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

// File metadata structure
struct metadata global_metadata[MAX_SIZE];

int nextAvailable = 0;

//pthread_mutex_t metadata_lock;
struct mutex metadata_lock;

/* get_metadata()
 * get the newest metadata from storage to memory
 */

static int get_metadata(void){
	printk("get_metadata enter.\n\n");
	char metadata_buf[4096];
	//metadata_buf = kmalloc(sizeof(struct metadata)*MAX_SIZE, GFP_KERNEL);
	//memcpy(metadata_buf, global_metadata, sizeof(struct metadata)*MAX_SIZE);
	ssize_t ret;
	struct file *metadata_filp;
	metadata_filp = filp_open(FILE_METADATA, O_RDONLY, 0);
	if (IS_ERR(metadata_filp)){
		printk("get_metadata : Error to open metadata file.\n");
		return OP_FAILURE;
	}

	printk("get_metadata : Before read\n");
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
	printk("get_metadata success.\n\n");
	return OP_SUCCESS;
}

/* update_metadata()
 * Update newest memory metadata to storage
 */

static int update_metadata(void){
	ssize_t ret;

	//metadata_lock;
	mutex_lock(&metadata_lock);
	//char *metadata_buf = kmalloc(sizeof(struct metadata)*MAX_SIZE, GFP_KERNEL);
	//memcpy(metadata_buf, global_metadata, sizeof(struct metadata)*MAX_SIZE);
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

static void dump_metadata(void){
	int i;
	for (i=0; i<MAX_SIZE; i++){
		//Only dump filename and permission
		printk("********************************************************\n");
		printk("filename : %s.\n", global_metadata[i].fileName);
		printk("file permission : %d.\n", global_metadata[i].permission);
		printk("********************************************************\n");
	}

}

static int firstTimeInit(void) {

	struct metadata fake_metadata[MAX_SIZE];

	int i, j;
	ssize_t ret;

	for (i=0; i<MAX_SIZE; i++) {
		for (j=0; j<MAX_USERS_ALLOWED; j++) {
			fake_metadata[i].users[j].userID = 0;
			fake_metadata[i].users[j].permission = 0;
		}
	fake_metadata[i].noOfUsers = 0;
	fake_metadata[i].permission = i;
	fake_metadata[i].fd = 0;
	strcpy(fake_metadata[i].fileName, "sfdsfsdfs");
	}

	mutex_init(&metadata_lock);
	//aquire metadata lock
	mutex_lock(&metadata_lock);
	struct file *filp;
	filp = filp_open(FILE_METADATA, O_CREAT | O_WRONLY, 0644);

	if (IS_ERR(filp))
	{
		printk("firstTimeInit : Error opening metadata file.\n");
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
		printk("firstTimeInit : ret [%lu], metadata [%lu] not match.\n", ret, sizeof(struct metadata)*MAX_SIZE);
		if (ret == -EFAULT){
			printk("firstTimeInit : -EFAULT.\n");		
		}
		filp_close(filp, NULL);
		//release_lock
		mutex_unlock(&metadata_lock);
		return OP_FAILURE;	
	}
	filp_close(filp, NULL);
	//release lock
	mutex_unlock(&metadata_lock);
	printk("firstTimeInit : Opened the metadata file successfully.\n");

	return OP_SUCCESS;
}

/* ------------------------------------------
 * fileOpen
 *
 * Opens the file whose details are present in the
 * request parameter. Depedning upon the flags,
 * fileOpen might create a new one if it is not present
 * or through an error back
 * fileOpen has more differences with others since when 
 * O_CREAT is set, global metadata needs to be updated.
 *
 * -----------------------------------------
*/
static struct file *fileOpen (request *rq, int *fd) {

	int present = 0;
	int i;
	struct file *filp;

	filp = filp_open(rq->fileName, rq->flags, 0);
	if(IS_ERR(filp)){
		printk("fileOpen : Cannot open required file [%s].\n", rq->fileName);
		return NULL;
	}

	if(rq->flags & O_CREAT){
		//need require metadata lock;
		printk("fileOpen : Create new file [%s] and update metadata structure.\n", rq->fileName);

		for (i=0; i < MAX_SIZE; i++) {
			if (strcmp(global_metadata[i].fileName, rq->fileName) == 0){
				present = 1;
				break;
			}
		}

		if (present == 0) {
			for (i=0; i < MAX_SIZE; i++) {	
				if (global_metadata[i].noOfUsers == 0) {
					strcpy(global_metadata[i].fileName, rq->fileName);
					global_metadata[i].users[0].userID = rq->userID;
					global_metadata[i].noOfUsers++;
					global_metadata[i].permission = rq->permission;
					global_metadata[i].fd = *fd;
					update_metadata();
					break;
				}
			}
		}
		// Release the lock
		//pthread_mutex_unlock(&metadata_lock);

		
	}
	printk("fileOpen : Open file [%s] success.\n", rq->fileName);
	return filp; 

}

/* ------------------------------------------
 * fileClose
 *
 * Closes the file whose file descriptor fd is provided.
 * Should also update the fileMetadata with the latest
 * offset obtained from lseek for the particular user
 *
 * -----------------------------------------
*/

static int fileClose(struct file *filp){
	if (IS_ERR(filp)){
		printk("fileClose : Error to close file.\n");
		return OP_FAILURE;
	}
	filp_close(filp, NULL);
	printk("fileClose : Close file success.\n");
	return OP_SUCCESS;
}

/* ------------------------------------------
 * fileWrite
 *
 * Writes the file from the offset provided or
 * from the offset maintained in the file metadata
 * structure. Returns back SUCCESS or FAILURE of the operation
 * -----------------------------------------
*/

static ssize_t fileWrite(struct file *file, const char __user *buf, ssize_t len, loff_t *pos){
	printk("fileWrite : Called\n");
	ssize_t ret;
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = file->f_op->write(file, buf, len, pos);
	set_fs(old_fs);
	return ret;
}

/* ------------------------------------------
 * fileRead
 *
 * Read the file from the provided offset or from the
 * offset maintained in the file metadata structure.
 * Returns back the number of bytes read from the file
 * -----------------------------------------
*/

static ssize_t fileRead(struct file *file, const char __user *buf, ssize_t len, loff_t *pos){
	printk("fileRead : Called\n");
	ssize_t ret;
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = file->f_op->read(file, buf, len, pos);
	set_fs(old_fs);
	return ret;
}

/* ------------------------------------------
 * grantAccess
 *
 * Grants access to all the users for the requested
 * file.
 * grantAccess one file for each call
 *
 * -----------------------------------------
*/
static int grantAccess (request *rq) {
	
	int i, j;
	
	struct metadata *current_filemetadata;
	current_filemetadata = global_metadata;
	
	if (IS_ERR(rq)) {
		return OP_FAILURE;
	}
	
	// Get file permissions for the user
	for (i=0; i<MAX_SIZE; i++) {
		
		//fileData = &fileMetadata[i];

		// Find the metadata of the requested file
		if (strcmp(current_filemetadata->fileName, rq->fileName) == 0) {

			printk("grantAccess: file found -> %s\n", current_filemetadata->fileName);
			
			// Limit reached or not enough space to include all the users
			if (current_filemetadata->noOfUsers >= MAX_USERS_ALLOWED) {
				return OP_FAILURE;
			}

			//j = fileData->noOfUsers;

			break;
		}
		current_filemetadata++;
	}

	if (i >= MAX_SIZE) {
		return OP_FAILURE;
	}

	printk("grantAccess: file chosen %s, %d\n", current_filemetadata->fileName, i);
	
	// Add all the users to the metaData for the respective file data
	/*for (i=0; i < noOfUsers; i++) {
		fileData->users[j].userID = user[i].userID;
		fileData->users[j++].permission = user[i].permission;
	}*/
	current_filemetadata->noOfUsers++;

	//fileData->noOfUsers += noOfUsers;

	printk("grantAccess: file users %s, %d\n", current_filemetadata->fileName, current_filemetadata->noOfUsers);

	return OP_SUCCESS;

}

static void testCase(void *data) {
	struct file *testfilp;
	request rq1;
	rq1.userID = 100;
	strcpy(rq1.fileName, "/home/yilun/my.txt");
	rq1.service = 1; // Read
	rq1.flags = O_RDONLY;
	rq1.permission = 0x1; 
	rq1.len = 50;
	rq1.offset = 0;
	int fd = 0;
	int i;
	loff_t pos = 0;
	for (i=0; i < 5; i++){
		
			testfilp = fileOpen(&rq1, &fd);
			fileWrite(testfilp, "Hello, this is only test.", 25, &pos);
			fileClose(testfilp);
		
	}
	return;
	
}


static int __init init_storage_server(void) {

	int i;
	struct file *filp;

	while (IS_ERR(filp = filp_open(FILE_METADATA, O_RDWR, 0))) {
		printk("init_storage_server : Calling firstTimeInit function.\n");
		if (firstTimeInit() == OP_FAILURE) {
			return OP_FAILURE;
    		}
	}

	//This is the only time calling get metadata
	get_metadata();
	dump_metadata();

	struct task_struct *tsk;
	tsk = kthread_run(testCase, NULL, "stroage server kthread.[%d]", 1);
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

/* ------------------------------------------
 * requestHandler
 *
 * handle the incoming request based on the service
 * required. Can be one of file read, file write or
 * access update services. This function calls the
 * appropriate function handler and updates the
 *
 * -----------------------------------------
*/





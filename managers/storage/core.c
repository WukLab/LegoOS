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
			fake_metadata[i].users[j] = -1;
		}
	fake_metadata[i].noOfUsers = 0;
	fake_metadata[i].permission = i;
	fake_metadata[i].used = 0;
	fake_metadata[i].owner = -1;
	strcpy(fake_metadata[i].fileName, "sfdsfsdfs");
	}

	mutex_init(&metadata_lock);
	//aquire metadata lock
	mutex_lock(&metadata_lock);
	struct file *filp;

	//metadata not executable.
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
static struct file *fileOpen (request *rq) {

	int exist = 0;
	int i;
	struct file *filp;

	filp = filp_open(rq->fileName, rq->flags, 0755);
	if(IS_ERR(filp)){
		printk("fileOpen : Cannot open required file [%s].\n", rq->fileName);
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
 * check_permission
 * 0 : not permitted
 * 1 : permitted
 * -1: error
 * -----------------------------------------
*/
static int  check_permission(request *rq, int owner, int permission){
	if (IS_ERR(rq))
		return -1;
	if (rq->uid == owner){
		if(rq->flags & O_RDONLY){
			return (permission >> 3) & READ_MASK;
		}
		if(rq->flags & O_WRONLY){
			return (permission >> 3) & WRITE_MASK;
		}
		if (rq->flags & O_RDWR){
			return ((permission >> 3) & READ_MASK) & ((permission >> 3) & WRITE_MASK);
		}
	}

	// if the user is not the owner.
	if(rq->flags & O_RDONLY){
		return permission & READ_MASK;
	}
	if(rq->flags & O_WRONLY){
		return permission & WRITE_MASK;
	}
	if (rq->flags & O_RDWR){
		return (permission & READ_MASK) & (permission & WRITE_MASK);
	}
	
	return -1;
}

/* ------------------------------------------
 * grant_access
 *
 * Grants access to all the users for the requested file.
 * grant_access one file for each call
 * grant_access should check permission for existing file.
 *
 * -----------------------------------------
*/
static int grant_access (request *rq, int *metadata_entry, int *user_entry) {
	
	int i, j;
	
	struct metadata *current_filemetadata;
	current_filemetadata = global_metadata;
	
	if (IS_ERR(rq)) {
		return OP_FAILURE;
	}
	
	for (i=0; i<MAX_SIZE; i++) {

		// Find the metadata of the requested file, file exist;
		if (strcmp(current_filemetadata->fileName, rq->fileName) == 0) {

			printk("grant_access: file found -> %s\n", current_filemetadata->fileName);

			// Find if the user is new;
			for (j = 0; j < MAX_USERS_ALLOWED; j++){
				if (rq->uid == current_filemetadata->users[j]){
					
					/* This is the case that user do not have the permission to access existing file */

					if (check_permission(rq, current_filemetadata->owner, current_filemetadata->permission) != 1){
						*metadata_entry = -1;
						*user_entry = -1;
						return OP_FAILURE;
					}

					/* This is the case that user has the permission */

					*metadata_entry = i;
					*user_entry = j;
					return OP_SUCCESS;
				}
			}

			/* Enter here means the request file exist, but the user request access 
			 * is not in the metadata user list.
			 * This is a more common case, first need to check if the file users
			 * list is full. And also check if the user has the permission to access
			 * required file
			 */

			if (current_filemetadata->noOfUsers >= MAX_USERS_ALLOWED
				   	|| (check_permission(rq, current_filemetadata->owner, current_filemetadata->permission)) != 1){
				*metadata_entry = -1;
				*user_entry = -1;
				return OP_FAILURE;
			}
			
			/* Enter here means request file exist, the user is not on metadata user list,
			 * but the user has permission to access file and file user list is not full,
			 * now try to find the entry
			 */

			for (j = 0; j < MAX_USERS_ALLOWED; j++){
				// find first not used user entry;
				if (current_filemetadata->users[j] == -1){
					current_filemetadata->users[j] = rq->uid;
					current_filemetadata->noOfUsers++;
					*metadata_entry = i;
					*user_entry = j;
					return OP_SUCCESS;
				}	
			}

		}
		current_filemetadata++;
	}

	/* Enter here means the file is not exist yet
	 * The only way that grant_access success is that O_CREAT
	 * set and metadata has an empty entry;
	 */

	if (rq->flags & O_CREAT){
		
		/* Try to find an entry of global_metadata */
		int i;
		for (i = 0; i < MAX_SIZE; i++){
			if (global_metadata[i].used == 0){

				//acquire metadata lock
				mutex_lock(&metadata_lock);
				if (global_metadata[i].used){
					/* This entry is occupied by other threads after detecting */
					mutex_unlock(&metadata_lock);
					break;
				}
				global_metadata[i].used = 1;
				global_metadata[i].users[0] = rq->uid;
				global_metadata[i].owner = rq->uid;
				global_metadata[i].permission = rq->permission;
				global_metadata[i].noOfUsers = 1;
				strcpy(global_metadata[i].fileName, rq->fileName);

				//release metadata lock
				mutex_unlock(&metadata_lock);
				update_metadata();
				*metadata_entry = i;
				*user_entry = 0;
				return OP_SUCCESS;
			}
		}
	}

	/* Enter here means O_CREAT is not set and file is not exist
	 * not grant access
	 */

	*metadata_entry = -1;
	*user_entry = -1;
	return OP_FAILURE;

}

/* decrease the noOfUsers and release the entry on metadata user list
 *
 */

static int yield_access(int metadata_entry, int user_entry){
	if (metadata_entry < 0 || metadata_entry >= MAX_SIZE
			|| user_entry < 0 || user_entry >= MAX_USERS_ALLOWED)
		return OP_FAILURE;

	mutex_lock(&metadata_lock);
	global_metadata[metadata_entry].noOfUsers--;
	global_metadata[metadata_entry].users[user_entry] = -1;
	mutex_unlock(&metadata_lock);
	update_metadata();

	return OP_SUCCESS;
}

//need add buf later;
static int handle_read_request(request *rq, void *buf){
	int metadata_entry, user_entry;
	if (grant_access(rq, &metadata_entry, &user_entry) == OP_FAILURE){
		return OP_FAILURE;
	}
	struct file *filp;
	filp = fileOpen(rq);
	if (IS_ERR(filp)){
		return OP_FAILURE;
	}
	fileRead(filp, (const char __user *)buf, rq->len, &rq->offset);
	fileClose(filp);
	yield_access(metadata_entry, user_entry);
	return OP_SUCCESS;
}

static int handle_write_request(request *rq, void *buf){
	struct file *filp;
	int metadata_entry, user_entry;
	
	//the file exist but not grant to access.
	if (grant_access(rq, &metadata_entry, &user_entry) == OP_FAILURE){
		return OP_FAILURE;
	}

	filp = fileOpen(rq);
	if (IS_ERR(filp)){
		return OP_FAILURE;
	}
	fileWrite(filp, (const char __user *)buf, rq->len, &rq->offset);
	fileClose(filp);
	yield_access(metadata_entry, user_entry);
	return OP_SUCCESS;
}

static void testCase(void *data) {
	struct file *testfilp;
	request rq1;
	rq1.uid = 100;
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
		
			testfilp = fileOpen(&rq1);
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





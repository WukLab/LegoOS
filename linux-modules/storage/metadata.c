/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

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

/* File metadata structure */
struct metadata global_metadata[MAX_SIZE];
DEFINE_MUTEX(metadata_lock);

static int __init_metadata(void)
{
	struct metadata fake_metadata[MAX_SIZE];
	int i, j;
	ssize_t ret;
	mm_segment_t old_fs;
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

int metadata_init(void)
{
	struct file *filp;

	if (IS_ERR(filp = filp_open(FILE_METADATA, O_RDWR, 0))) {
		printk("init_storage_server : Calling init_metadata function.\n");
		if (__init_metadata() == OP_FAILURE) {
			return -1;
    		}
	}
	get_metadata();
}

/* get_metadata()
 * get the newest metadata from storage to memory
 */

int get_metadata(void){
	char *metadata_buf;
	ssize_t ret;
	struct file *metadata_filp;
	loff_t pos = 0;
	mm_segment_t old_fs;
	size_t len_meta;
	
	printk("get_metadata enter.\n\n");
	metadata_filp = filp_open(FILE_METADATA, O_RDONLY, 0);
	if (IS_ERR(metadata_filp)){
		printk("get_metadata : Error to open metadata file.\n");
		return OP_FAILURE;
	}

	len_meta = sizeof(struct metadata) * MAX_SIZE;
	metadata_buf = kmalloc(len_meta, GFP_KERNEL);
	if (unlikely(!metadata_buf)) {
		return OP_FAILURE;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = metadata_filp->f_op->read(metadata_filp, metadata_buf, len_meta, &pos);
	set_fs(old_fs);

	if (ret == -EFAULT || ret != len_meta){
		printk("get_metadata : Incorrect metadata file length [%lu].\n", ret);
		return OP_FAILURE;
	}
	
	memcpy(global_metadata, metadata_buf, len_meta);
	printk("get_metadata success.\n");
	return OP_SUCCESS;
}

/* update_metadata()
 * Update newest memory metadata to storage
 */

int update_metadata(void){
	ssize_t ret;
	struct file *filp;
	loff_t pos = 0;
	mm_segment_t old_fs;
	size_t len_meta;

	len_meta = sizeof(struct metadata) * MAX_SIZE;
	//metadata_lock;
	mutex_lock(&metadata_lock);
	filp = filp_open(FILE_METADATA, O_WRONLY, 0);
	if (IS_ERR(global_metadata) || IS_ERR(filp)){
		filp_close(filp, NULL);
		//release_lock;
		mutex_unlock(&metadata_lock);
		return OP_FAILURE;
	}
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = filp->f_op->write(filp, (char *) global_metadata, len_meta, &pos);
	set_fs(old_fs);
	if (ret == -EFAULT || ret != len_meta){
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

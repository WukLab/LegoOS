#include "storage.h"
#include <linux/fs.h>
#include <linux/param.h>
#include <linux/dcache.h>
#include <linux/mutex.h>
#include <linux/mm.h>

/* ------------------------------------------
 * local_file_open
 *
 * Opens the file whose details are present in the
 * request parameter. Depedning upon the flags,
 * local_file_open might create a new one if it is not present
 * or through an error back
 * local_file_open has more differences with others since when 
 * O_CREAT is set, global metadata needs to be updated.
 *
 * -----------------------------------------
*/
struct file *local_file_open (request *rq) {

	struct file *filp;

	filp = filp_open(rq->fileName, rq->flags, 0755);
	if(IS_ERR(filp)){
		printk("local_file_open : Cannot open required file [%s].\n", rq->fileName);
	}

	//printk("local_file_open : Open file [%s] success.\n", rq->fileName);
	return filp; 

}

/* ------------------------------------------
 * local_file_close
 *
 * Closes the file whose file descriptor fd is provided.
 * Should also update the fileMetadata with the latest
 * offset obtained from lseek for the particular user
 *
 * -----------------------------------------
*/

int local_file_close(struct file *filp){
	int ret;
	ret = filp_close(filp, NULL);
	//printk("local_file_close : Close file success.\n");
	return ret;
}

/* ------------------------------------------
 * local_file_write
 *
 * Writes the file from the offset provided or
 * from the offset maintained in the file metadata
 * structure. Returns back SUCCESS or FAILURE of the operation
 * -----------------------------------------
*/

ssize_t local_file_write(struct file *file, const char __user *buf, ssize_t len, loff_t *pos){
	//printk("local_file_write : Called\n");
	ssize_t ret;
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = file->f_op->write(file, buf, len, pos);
	set_fs(old_fs);
	return ret;
}

/* ------------------------------------------
 * local_file_read
 *
 * Read the file from the provided offset or from the
 * offset maintained in the file metadata structure.
 * Returns back the number of bytes read from the file
 * -----------------------------------------
*/

ssize_t local_file_read(struct file *file, const char __user *buf, ssize_t len, loff_t *pos){
	//printk("local_file_read : Called\n");
	ssize_t ret;
	mm_segment_t old_fs;
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = file->f_op->read(file, buf, len, pos);
	set_fs(old_fs);
	return ret;
}

/*
 * local_fsync
 *
 * fsync the local file.
 */
int local_fsync(struct file *file){
	return vfs_fsync(file, 0);
}

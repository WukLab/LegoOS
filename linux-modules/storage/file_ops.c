#include "storage.h"
#include <linux/fs.h>
#include <linux/param.h>
#include <linux/dcache.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/securebits.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>

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

	filp = filp_open(rq->fileName, rq->flags | O_LARGEFILE, 0755);
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

ssize_t local_file_read(struct file *file, char __user *buf, ssize_t len, loff_t *pos){
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

/* local handler function for access and faccess */
int faccessat_root(const char __user * filename, int mode)
{
	const struct cred *old_cred;
	struct cred *override_cred;
	struct path path;
	struct inode *inode;
	int res;
	unsigned int lookup_flags = LOOKUP_FOLLOW;

	if (mode & ~S_IRWXO)	/* where's F_OK, X_OK, W_OK, R_OK? */
		return -EINVAL;

	override_cred = prepare_creds();
	if (!override_cred)
		return -ENOMEM;

	override_cred->fsuid = override_cred->uid;
	override_cred->fsgid = override_cred->gid;


	old_cred = override_creds(override_cred);
retry:
	//set_fs_pwd(current->fs, &current->fs->root);
	//res = user_path_at(AT_FDCWD, filename, lookup_flags, &path);
	res = kern_path(filename, lookup_flags, &path);
	if (res)
		goto out;

	inode = path.dentry->d_inode;

	if ((mode & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		/*
		 * MAY_EXEC on regular files is denied if the fs is mounted
		 * with the "noexec" flag.
		 */
		res = -EACCES;
		if (path.mnt->mnt_flags & MNT_NOEXEC)
			goto out_path_release;
	}

	res = inode_permission(inode, mode | MAY_ACCESS);
	/* SuS v2 requires we report a read only fs too */
	if (res || !(mode & S_IWOTH) || special_file(inode->i_mode))
		goto out_path_release;
	/*
	 * This is a rare case where using __mnt_is_readonly()
	 * is OK without a mnt_want/drop_write() pair.  Since
	 * no actual write to the fs is performed here, we do
	 * not need to telegraph to that to anyone.
	 *
	 * By doing this, we accept that this access is
	 * inherently racy and know that the fs may change
	 * state before we even see this result.
	 */
	if (__mnt_is_readonly(path.mnt))
		res = -EROFS;

out_path_release:
	path_put(&path);
	if (retry_estale(res, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	revert_creds(old_cred);
	put_cred(override_cred);
	return res;
}

int kernel_fs_stat(const char *name, struct kstat *stat, int flag)
{
	mm_segment_t old_fs;
	int err;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_fstatat(AT_FDCWD, name, stat, flag);
	set_fs(old_fs);
	return err;
}

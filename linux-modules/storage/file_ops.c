#include "storage.h"
#include "common.h"
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
#include <linux/security.h>

#ifdef STORAGE_BYPASS_PAGE_CACHE
#define ROUND_DOWN_PAGE(x)	(x & PAGE_MASK)
#define UP_ALIGN_PAGE(x)	(ROUND_DOWN_PAGE(x) + PAGE_SIZE)
#define IS_PAGE_ALIGNED(x)	(x % PAGE_SIZE)

static inline unsigned long chunk_size(size_t len, loff_t pos)
{
	loff_t end;
	unsigned long ret;
	end = pos + len;
	ret = ROUND_DOWN_PAGE(end) - ROUND_DOWN_PAGE(pos) + PAGE_SIZE;
	return ret;
}
#endif /* STORAGE_BYPASS_PAGE_CACHE */

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

#ifndef STORAGE_BYPASS_PAGE_CACHE
	filp = filp_open(rq->fileName, rq->flags | O_LARGEFILE, 0755);
#else
	filp = filp_open(rq->fileName, rq->flags | O_DIRECT | O_LARGEFILE, 0755);
#endif
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
ssize_t local_file_write(struct file *file, const char __user *buf,
			 ssize_t len, loff_t *pos)
{
	ssize_t ret;
	mm_segment_t old_fs;

#ifdef STORAGE_BYPASS_PAGE_CACHE
	loff_t aligned_pos, chkoff, end;
	size_t curr_i_size, chksize;

	BUG_ON(!file->f_inode);
	chksize = chunk_size(len, *pos);
	chkoff = (*pos) % PAGE_SIZE;
	curr_i_size = i_size_read(file->f_inode);
	aligned_pos = ROUND_DOWN_PAGE(*pos);
	end = (*pos) + len;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	if (unlikely(chkoff)) {
		loff_t out = aligned_pos;
		ret = file->f_op->read(file, ubuf, chksize, &out);
		if (unlikely(ret < 0)) {
			pr_warn("Fail to transfer out block before write.\n");
			return ret;
		}
	}

	copy_to_user(ubuf + chkoff, buf, len);
	ret = file->f_op->write(file, ubuf, chksize, &aligned_pos);

	if (unlikely(ret < 0)) {
		pr_warn("Fail to perform directIO write");
		return ret;
	}

	ret = len;
	if (unlikely(!IS_PAGE_ALIGNED(end) && end > curr_i_size))
		vfs_truncate(&file->f_path, end);
#else
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = file->f_op->write(file, buf, len, pos);
	set_fs(old_fs);
#endif
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

ssize_t local_file_read(struct file *file, char __user *buf, ssize_t len, loff_t *pos)
{
	ssize_t ret;
	mm_segment_t old_fs;

#ifdef STORAGE_BYPASS_PAGE_CACHE
	loff_t aligned_pos, chkoff, end;
	size_t curr_i_size, chksize;

	BUG_ON(!file->f_inode);
	chksize = chunk_size(len, *pos);
	chkoff = (*pos) % PAGE_SIZE;
	curr_i_size = i_size_read(file->f_inode);
	aligned_pos = ROUND_DOWN_PAGE(*pos);
	end = (*pos) + len;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	ret = file->f_op->read(file, ubuf, chksize, &aligned_pos);
	set_fs(old_fs);
	if (unlikely(ret + aligned_pos < end)) {
		ret = ret - chkoff;
	} else {
		ret = len;
	}
	copy_from_user(buf, ubuf + chkoff, ret);
#else
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = file->f_op->read(file, buf, len, pos);
	set_fs(old_fs);
#endif
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

/* port from linux /fs/namei.c, func: do_unlinkat
 * @ pathname: absolute path of directory to be created
 */
long do_unlink(const char *pathname)
{
	long error;
	struct dentry *dentry;
	struct inode *dir;
	struct path path;
	//struct inode *tmp;
	unsigned int lookup_flags = LOOKUP_FOLLOW;

	error = kern_path(pathname, lookup_flags, &path);
	if (error)
		return error;

	dentry = path.dentry;
	dir = dentry->d_parent->d_inode;

	mutex_lock(&dir->i_mutex);
	//error = vfs_unlink(dir, dentry, &tmp);
	error = vfs_unlink(dir, dentry);
	mutex_unlock(&dir->i_mutex);
	path_put(&path);

	return error;
}

/* port form linux fs/namei.c func : mkdirat
 * @pathname: absolute path of directory to be created
 */
long do_mkdir(const char *pathname, umode_t mode)
{
	struct dentry *dentry;
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;

retry:
	dentry = kern_path_create(AT_FDCWD, pathname, &path, lookup_flags);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (!IS_POSIXACL(path.dentry->d_inode))
		mode &= ~current_umask();
	error = security_path_mkdir(&path, dentry, mode);
	if (!error)
		error = vfs_mkdir(path.dentry->d_inode, dentry, mode);
	done_path_create(&path, dentry);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

/* @pathname: absolute path of directory to be removed
 */
long do_rmdir(const char *pathname)
{
	long error;
	struct dentry *dentry;
	struct inode *dir;
	struct path path;
	unsigned int lookup_flags = LOOKUP_DIRECTORY;

	error = kern_path(pathname, lookup_flags, &path);
	if (error)
		return error;

	dentry = path.dentry;
	dir = dentry->d_parent->d_inode;

	mutex_lock(&dir->i_mutex);
	error = vfs_rmdir(dir, dentry);
	mutex_unlock(&dir->i_mutex);
	path_put(&path);

	return error;
}

/*
 * port from linux fs/statfs.c, func: user_statfs
 * do_kstatfs: fill statfsbuf will statfs info
 * @pathname: any full filepath on given fs
 * @statfsbuf: kernel virtual address of a buffer to be filled
 * return value: 0 on sucess, -errno on fail
 */
long do_kstatfs(const char *pathname, struct lego_kstatfs *statfsbuf)
{
	long error;
	struct path path;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
	struct kstatfs *linux_kstatfs;

	/*
	 * We lego renamed this structure because the header file
	 * is shared between Lego kernel and linux module. To avoid
	 * redefition, we add lego_ prefix.
	 *
	 * But the size of these two must match!
	 */
	BUILD_BUG_ON(sizeof(struct lego_kstatfs) != sizeof(struct kstatfs));

	linux_kstatfs = (struct kstatfs *)statfsbuf;

retry:
	error = kern_path(pathname, lookup_flags, &path);
	if (!error) {
		error = vfs_statfs(&path, linux_kstatfs);
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return error;
}

/* callback struct/functions for readdir */
struct getdents_callback {
	struct dir_context ctx;
	struct linux_dirent * current_dir;
	struct linux_dirent * previous;
	int count;
	int error;
};

static int filldir(void * __buf, const char * name, int namlen, loff_t offset,
		   u64 ino, unsigned int d_type)
{
	struct linux_dirent * dirent; /* kernel dirent */
	struct getdents_callback * buf = (struct getdents_callback *) __buf;
	unsigned long d_ino;
	int reclen = ALIGN(offsetof(struct linux_dirent, d_name) + namlen + 2,
		sizeof(long));

	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->error = -EOVERFLOW;
		return -EOVERFLOW;
	}
	dirent = buf->previous;
	if (dirent) {
		dirent->d_off = offset;
	}
	dirent = buf->current_dir;
	dirent->d_ino = d_ino;
	dirent->d_reclen = reclen;
	memcpy(dirent->d_name, name, namlen);
	memset(dirent->d_name + namlen, '\0', 1);
	*((char *) dirent + reclen - 1) = d_type;

	buf->previous = dirent;
	dirent = (void *)dirent + reclen;
	buf->current_dir = dirent;
	buf->count -= reclen;
	return 0;
}

/*
 * port from linux fs/readdir.c
 * @pathname: full pathname of directory to be read
 * @dirent: kernel buffer to hold linux_dirent struct
 * @pos: offset of readdir
 * @count: max nrbytes allowed to be put into buffer
 * return value: nrbytes read on success, -errno on fail
 */
long do_getdents(const char *pathname, struct linux_dirent *dirent,
		loff_t *pos, unsigned int count)
{
	struct file * filp;
	struct linux_dirent * lastdirent;
	struct getdents_callback buf = {
		.ctx.actor = filldir,
		.count = count,
		.current_dir = dirent
	};
	int error;

	filp = filp_open(pathname, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR_OR_NULL(filp))
		return -EBADF;

	filp->f_pos = *pos;
	error = iterate_dir(filp, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		lastdirent->d_off = buf.ctx.pos;
		error = count - buf.count;
	}
	*pos = filp->f_pos;
	filp_close(filp, NULL);
	return error;
}

long do_readlink(const char *pathname, char *buf, int bufsiz)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_EMPTY;

	if (bufsiz <= 0)
		return -EINVAL;

retry:
	error = kern_path(pathname, lookup_flags, &path);
	if (!error) {
		struct inode *inode = path.dentry->d_inode;

		if (inode->i_op->readlink) {
			touch_atime(&path);
			error = inode->i_op->readlink(path.dentry,
							buf, bufsiz);
		} else {
			error = -EINVAL;
		}
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return error;
}

/*
 * do_link: create a hard link for newname that link to oldname
 * @oldname: full path name to be linked to
 * @newname: new created pathname that links to oldname.
 * @flags: normally it is 0. do_link allows two flags:
 *	- AT_EMPTY_PATH:	allow oldname to be empty
 *	- AT_SYMLINK_FOLLOW:	allow oldname to be symbolic link
 * return value: 0 on success, -errno on fail.
 */
static long do_link(const char *oldname, const char *newname, int flags)
{
	struct dentry *new_dentry;
	struct path old_path, new_path;
	int how = 0;
	long error;

	if ((flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) != 0)
		return -EINVAL;
	/*
	 * To use null names we require CAP_DAC_READ_SEARCH
	 * This ensures that not everyone will be able to create
	 * handlink using the passed filedescriptor.
	 */
	if (flags & AT_EMPTY_PATH) {
		if (!capable(CAP_DAC_READ_SEARCH))
			return -ENOENT;
		how = LOOKUP_EMPTY;
	}

	if (flags & AT_SYMLINK_FOLLOW)
		how |= LOOKUP_FOLLOW;
retry:
	error = kern_path(oldname, how, &old_path);
	if (error)
		return error;

	new_dentry = kern_path_create(AT_FDCWD, newname, &new_path,
					(how & LOOKUP_REVAL));
	error = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto out;

	error = -EXDEV;
	if (old_path.mnt != new_path.mnt)
		goto out_dput;

	error = vfs_link(old_path.dentry, new_path.dentry->d_inode, new_dentry);
	//error = vfs_link(old_path.dentry, new_path.dentry->d_inode, new_dentry, NULL);
out_dput:
	done_path_create(&new_path, new_dentry);
	if (retry_estale(error, how)) {
		how |= LOOKUP_REVAL;
		goto retry;
	}
out:
	path_put(&old_path);

	return error;
}

/*
 * do_rename: rename a old path to a new path
 * @oldname: full pathname of old file/dir
 * @newname: full pathname
 *
 * do_rename is logically transfered into three steps
 *	- unlink newname
 *	- link newname to oldname
 *	- unlink oldname
 * return value 0 on success, -errno on fail
 */
long do_rename(char *oldname, char *newname)
{
	long error;

	error = do_unlink(newname);
	if (error && (error != -ENOENT))
		goto out;
	error = do_link(oldname, newname, 0);
	if (error)
		goto out;
	error = do_unlink(oldname);

out:
	return error;
}

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

request constuct_request(int uid, char *fileName, fmode_t permission, ssize_t len, 
		loff_t offset, int flags){
	request rq;
	rq.uid = uid;
	strcpy(rq.fileName, fileName);
	rq.permission = permission;
	rq.len = len;
	rq.offset = offset;
	rq.flags = flags;
	return rq;
}

ssize_t handle_read_request(void *payload, uintptr_t desc)
{
	struct m2s_read_write_payload *m2s_rq;
	//int metadata_entry, user_entry;
	ssize_t ret;
	ssize_t *retval;
	char *readbuf;
	void *retbuf;
	int len_retbuf = 0;
	struct file *filp;
	request rq;

	m2s_rq = (struct m2s_read_write_payload *) payload;
	len_retbuf = m2s_rq->len + sizeof(ssize_t);
	rq = constuct_request(m2s_rq->uid, m2s_rq->filename, 0, m2s_rq->len, 
			m2s_rq->offset, m2s_rq->flags);

	if (unlikely(m2s_rq->len > 512*BLK_SIZE)) {
		pr_info("read request is too large, request [%lu].\n", m2s_rq->len);
		ret = -ENOMEM;
		goto err;
	}

	retbuf = kmalloc(len_retbuf, GFP_KERNEL);
	if (unlikely(!retbuf)) {
		pr_info("No memory for read retbuf, request [%lu].\n", m2s_rq->len);
		ret = -ENOMEM;
		goto err;
	}

	retval = (ssize_t *) retbuf;
	readbuf = (char *) (retbuf + sizeof(ssize_t));

#ifdef DEBUG_STORAGE
	pr_info("%s:() uid: %d, filename: %s, len: %lu, offset: %Lu, flags: %o\n",	\
			__func__, m2s_rq->uid, m2s_rq->filename, m2s_rq->len,
			m2s_rq->offset, m2s_rq->flags);
#endif /* DEBUG_STORAGE */

	/* *retval = grant_access(&rq, &metadata_entry, &user_entry);
	if (*retval){
		goto out_reply;
	} */ /*enable in future*/
	*retval = 0;

	filp = local_file_open(&rq);
	if (IS_ERR(filp)){
		*retval = PTR_ERR(filp);
		goto out_reply;
	}
	
	*retval = local_file_read(filp, (char __user *)readbuf, rq.len, &rq.offset);
	local_file_close(filp);
	//yield_access(metadata_entry, user_entry); //enable in future
	//pr_info("Content in readbuf is [%s]\n", readbuf);

out_reply:
	ret = *retval;
	ibapi_reply_message(retbuf, len_retbuf, desc);
	kfree(retbuf);
	return ret;

err:
	ibapi_reply_message(&ret, sizeof(ret), desc);
	return ret;
	
}

ssize_t handle_write_request(void *payload, uintptr_t desc)
{
	struct m2s_read_write_payload *m2s_wq;
	//int metadata_entry, user_entry;
	ssize_t retval;
	char *writebuf;
	struct file *filp;
	request rq;

	m2s_wq = (struct m2s_read_write_payload *) payload;
	rq = constuct_request(m2s_wq->uid, m2s_wq->filename, 0, m2s_wq->len, 
			m2s_wq->offset, m2s_wq->flags);

	writebuf = (char *) (payload + sizeof(struct m2s_read_write_payload));

#ifdef DEBUG_STORAGE
	pr_info("%s:() uid: %d, filename: %s, len: %lu, offset: %Lu, flags: %o\n",			\
			__func__, m2s_wq->uid, m2s_wq->filename, m2s_wq->len,
			m2s_wq->offset, m2s_wq->flags);
#endif
	/*retval = grant_access(&rq, &metadata_entry, &user_entry);
	if (retval){
		goto out_reply;
	}*/ //enable in future
	retval = 0;

	filp = local_file_open(&rq);
	if (IS_ERR(filp)){
		retval = PTR_ERR(filp);
		goto out_reply;
	}
	retval = local_file_write(filp, (const char __user *)writebuf, rq.len, &rq.offset);
	local_file_close(filp);
	//yield_access(metadata_entry, user_entry); //enable in future

out_reply:
	ibapi_reply_message(&retval, sizeof(retval), desc);
	return retval;
	
}

/* Open request from processor directly */
int handle_open_request(void *payload, uintptr_t desc)
{
	struct p2s_open_struct *m2s_op = payload;
	//int metadata_entry, user_entry;
	int ret;
	request rq;
	struct file *filp;

	rq = constuct_request(m2s_op->uid, m2s_op->filename, m2s_op->permission, 0, 0, m2s_op->flags);

#ifdef DEBUG_STORAGE
	pr_info("%s(): filename: %s, uid: %d, permission: %u, flags: %o",
			__func__, m2s_op->filename, m2s_op->uid, m2s_op->permission, m2s_op->flags);
#endif
	ret = 0;

	filp = local_file_open(&rq);
	if (IS_ERR(filp)){
		ret = PTR_ERR(filp);
		goto out_reply;
	}

	local_file_close(filp);

out_reply:
	ibapi_reply_message(&ret, sizeof(ret), desc);
	return ret;
}

int handle_stat_request(void *payload, uintptr_t desc)
{
	struct p2s_stat_struct *stat_rq = payload;
	struct kstat stat;
	void *ret_msg;
	int *retval_in_msg;
	struct kstat *stat_in_msg;
	int res;
	int ret_len = sizeof(int) + sizeof(struct kstat);
	
	ret_msg = kmalloc(ret_len, GFP_KERNEL);
	if (unlikely(!ret_msg)) {
		panic("NO MEM for allocating return message.\n");
	}
	retval_in_msg = ret_msg;
	stat_in_msg = ret_msg + sizeof(int);

	res = kernel_fs_stat(stat_rq->filename, &stat, stat_rq->flag);

	/* ib return msg format, retval + stat */
	*retval_in_msg = res;
	*stat_in_msg = stat;

	ibapi_reply_message(ret_msg, ret_len, desc);

	kfree(ret_msg);
	return res;
}

int handle_access_request(void *payload, uintptr_t desc)
{
	/* filepath + mode */
	struct p2s_access_struct *acc = payload;
	int ret;
	
	ret = faccessat_root(acc->filename, acc->mode);

	pr_info("%s %s %d, %d\n", __func__, acc->filename, acc->mode, ret);
	ibapi_reply_message(&ret, sizeof(int), desc);
	return ret;
}

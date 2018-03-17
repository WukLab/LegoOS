/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/files.h>
#include <lego/syscalls.h>
#include <lego/spinlock.h>
#include <lego/sched.h>
#include <processor/processor.h>
#include <processor/fs.h>

/* 2^5 pages pipe buffer */
#define PIPE_DEF_ORDER	5

#ifdef CONFIG_DEBUG_PIPE
#define pipe_debug(fmt, ...) 			\
	pr_debug("%s() "fmt"\n",			\
			__func__, __VA_ARGS__)
#else
static inline void pipe_debug(const char *fmt, ...) {  }
#endif /* CONFIG_DEBUG_PIPE */

/* default pipe size, 32 pages */
unsigned int pipe_def_size = 131072;

/*
 * We implement pipe by a 32-pages kernel memory ring buffer
 * pipe_info is the metadata to manage a pipe, readers/writers are counters
 * of active readers/writers processes, and would initialized as 1 while
 * sys_pipe() or sys_pipe2() is called to create a new pipe.
 *
 * fifo_open() would increment a counter (depends on the file is 
 * a pipe reader or writer), and filo_open() is called by copy_files(), which is 
 * a fork()'s rountine.
 *
 * head is the pointer for consumers to dequeue from ring buffer
 * tail is the pointer for producers to enqueue into ring buffer
 *
 * pipe_read() reads n bytes from ring buffer and advances pipe->head, and while buffer
 * has enough room (currently 4-pages), wakes up all waiters (including readers/writers)
 * in order to make consumers work. And pipe_read() sleeps on the ring buffer is completely
 * empty. (It means pipe_read() is not necessary to read same nrbytes as it required).
 *
 * pipe_write() writes n bytes into ring buffer and advances pipe->tail. It first checks if
 * there are still active readers, if not, pipe is broken and SIGPIPE needs to send to current
 * process. Unlike pipe_read(), pipe_write() would wait on ring buffer until it has more than
 * n bytes space. And it wakes up all waiters before each time it goes to sleep to make
 * consumers make more room on ring buffer.
 *
 * pipe buffer and pipe_info would free on pipe->readers = pipe->writers = 0; pipe_release
 * would decrease a readers or writers counter, which is called when file is closed.
 */

struct pipe_info {
	spinlock_t lock;
	wait_queue_head_t wait;
	unsigned int readers;
	unsigned int writers;
	void *head;		/* consumers pointer */
	void *tail;		/* producers pointer */
	void *buffer;
	int len;		/* nbytes in use */
};

struct pipe_info *alloc_pipe_info(void)
{
	void *buffer;
	struct pipe_info *pipe;

	buffer = (void *)__get_free_pages(GFP_KERNEL, PIPE_DEF_ORDER);
	if (unlikely(!buffer)) {
		return NULL;
	}

	pipe = kmalloc(sizeof(struct pipe_info), GFP_KERNEL);
	if (unlikely(!pipe)) {
		free_pages((unsigned long)buffer, PIPE_DEF_ORDER);	
		return NULL;
	}

	spin_lock_init(&pipe->lock);
	pipe->buffer = pipe->head = pipe->tail = buffer;
	pipe->readers = 1;
	pipe->writers = 1;
	pipe->len = 0;

	/* TODO: init wait_queue, ops */
	init_waitqueue_head(&pipe->wait);
	
	return pipe;
}

static inline void free_pipe_info(struct pipe_info *pipe)
{
	pipe_debug("CPU:%d, PID:%d",
		smp_processor_id(), current->pid);

	if (!pipe)
		return;
	if (pipe->buffer)
		free_pages((unsigned long)pipe->buffer, PIPE_DEF_ORDER);
	kfree(pipe);
}

static inline void pipe_lock(struct pipe_info *pipe)
{
	spin_lock(&pipe->lock);
}

static inline void pipe_unlock(struct pipe_info *pipe)
{
	spin_unlock(&pipe->lock);
}

/*
 * caller must hold pipe->lock
 */
static inline void pipe_wait(struct pipe_info *pipe)
{
	DEFINE_WAIT(wait);

	/* 
	 * We must relase the pipe lock before go into sleep 
	 */
	pipe_unlock(pipe);
	prepare_to_wait(&pipe->wait, &wait, TASK_INTERRUPTIBLE);
	schedule();
	finish_wait(&pipe->wait, &wait);
	pipe_lock(pipe);
}

static ssize_t
pipe_read(struct file *filp, char __user *buf,
	size_t count, loff_t *off)
{
	struct pipe_info *pipe = filp->private_data;
	ssize_t ret;
	int do_wakeup;

	if (unlikely(count == 0))
		return 0;
	
	if (unlikely(!pipe))
		return -EINVAL;

	do_wakeup = 0;
	ret = 0;
	pipe_lock(pipe);
	for (;;) {
		if (pipe->len) {
			/* buffer has items */
			ret = count;
			if (ret > pipe->len)
				ret = pipe->len;
			
			if (pipe->head + ret > pipe->buffer + pipe_def_size) {
				/* chunk into two copy */
				int nbytes1, nbytes2;
				nbytes1 = pipe->buffer + pipe_def_size - pipe->head;
				nbytes2 = ret - nbytes1;

				if (copy_to_user(buf, pipe->head, nbytes1)) {
					ret = -EFAULT;
					break;
				}
				
				if (copy_to_user(buf + nbytes1, pipe->buffer, nbytes2)) {
					ret = -EFAULT;
					break;
				}
				pipe->head = pipe->buffer + nbytes2;
				pipe->len -= ret;
			} else {
				if (copy_to_user(buf, pipe->head, ret))	{
					ret = -EFAULT;
					break;
				}
				pipe->head = pipe->head + ret;
				pipe->len -= ret;
			}
			/*
			 * I do_wakeup to wakeup writers when more than 4 page left
			 */
			if (pipe_def_size - pipe->len >= 4 * PAGE_SIZE)
				do_wakeup = 1;
			if (signal_pending(current)) {
				if (!ret)
					ret = -ERESTARTSYS;
				break;
			}

			break;			
		}
		/* 
		 * if buffer is already empty, wakeup writers before sleep
		 */
		wake_up_interruptible(&pipe->wait);
		pipe_debug("sleep, CPU:%d, PID:%d, nr_readers:%u, nr_writers:%u",
				smp_processor_id(), current->pid, pipe->readers, pipe->writers);
		pipe_wait(pipe);
		pipe_debug("woken up, CPU:%d, PID:%d, nr_readers:%u, nr_writers:%u",
				smp_processor_id(), current->pid, pipe->readers, pipe->writers);
	}
	pipe_unlock(pipe);

	if (do_wakeup)
		wake_up_interruptible(&pipe->wait);

	return ret;
}

static ssize_t
pipe_write(struct file *filp, const char __user *buf,
	size_t count, loff_t *off)
{
	struct pipe_info *pipe = filp->private_data;
	ssize_t ret;
	int do_wakeup;

	if (unlikely(count == 0))
		return 0;
	
	if (unlikely(!pipe))
		return -EINVAL;

	do_wakeup = 0;
	ret = 0;
	pipe_lock(pipe);

	/* send SIGPIPE if there is no more reader */
	if (!pipe->readers) {
		kill_pid_info(SIGPIPE, (struct siginfo *) 0, current->pid);
		ret = -EPIPE;
		goto out;
	}

	for (;;) {
		if (pipe->len + count <= pipe_def_size) {
			/* buffer is not full */
			ret = count;
			
			if (pipe->tail + ret > pipe->buffer + pipe_def_size) {
				/* chunk into two copy */
				int nbytes1, nbytes2;
				nbytes1 = pipe->buffer + pipe_def_size - pipe->tail;
				nbytes2 = ret - nbytes1;

				if (copy_from_user(pipe->tail, buf, nbytes1)) {
					ret = -EFAULT;
					break;
				}
				
				if (copy_to_user(pipe->buffer, buf + nbytes1, nbytes2)) {
					ret = -EFAULT;
					break;
				}
				pipe->tail = pipe->buffer + nbytes2;
				pipe->len += ret;
			} else {
				if (copy_to_user(pipe->tail, buf, ret))	{
					ret = -EFAULT;
					break;
				}
				pipe->tail = pipe->tail + ret;
				pipe->len += ret;
			}
			
			/* anyway wakeup readers if write success */
			do_wakeup = 1;
			if (signal_pending(current)) {
				if (!ret)
					ret = -ERESTARTSYS;
				break;
			}

			break;			
		}
		/* 
		 * if buffer is almost full, wakeup readers before sleep
		 */
		wake_up_interruptible(&pipe->wait);
		pipe_debug("sleep, CPU:%d, PID:%d, nr_readers:%u, nr_writers:%u",
				smp_processor_id(), current->pid, pipe->readers, pipe->writers);
		pipe_wait(pipe);
		pipe_debug("woken up, CPU:%d, PID:%d, nr_readers:%u, nr_writers:%u",
				smp_processor_id(), current->pid, pipe->readers, pipe->writers);
	}
out:
	pipe_unlock(pipe);
	if (do_wakeup)
		wake_up_interruptible(&pipe->wait);

	return ret;
}

/*
 * fifo_open is called when get_file is called
 */
static int fifo_open(struct file *f)
{
	struct pipe_info *pipe = f->private_data;

	BUG_ON(!pipe);
	pipe_lock(pipe);
	if (f->f_mode & FMODE_READ)
		pipe->readers++;
	if (f->f_mode & FMODE_WRITE)
		pipe->writers++;
	
	if (pipe->readers == 1 || pipe->writers == 1)
		wake_up_interruptible(&pipe->wait);

	pipe_debug("CPU:%d, PID:%d, nr_readers:%u, nr_writers:%u",
		smp_processor_id(), current->pid, pipe->readers, pipe->writers);
	pipe_unlock(pipe);
	return 0;
}

static int pipe_release(struct file *filp)
{
	struct pipe_info *pipe = filp->private_data;

	/* if any reference, pipe_info should not be empty*/
	BUG_ON(!pipe);
	pipe_lock(pipe);
	if (filp->f_mode & FMODE_READ)
		pipe->readers--;
	if (filp->f_mode & FMODE_WRITE)
		pipe->writers--;
	
	if (pipe->readers || pipe->writers)
		wake_up_interruptible(&pipe->wait);
	
	pipe_debug("CPU:%d, PID:%d, nr_readers:%u, nr_writers:%u",
		smp_processor_id(), current->pid, pipe->readers, pipe->writers);
	pipe_unlock(pipe);

	if (!pipe->readers && !pipe->writers)
		free_pipe_info(pipe);
	return 0;
}

const struct file_operations pipefifo_fops = {
	.open = fifo_open,
	.read = pipe_read,
	.write = pipe_write,
	.release = pipe_release,
};

/*
 * callers must guarantee flides[0], fildes[1] are valid address
 */
static int do_pipe_create(int *flides, int flags)
{
	struct file *filps[2];
	struct files_struct *files = current->files;
	int error = 0;
	int fds[2];
	struct pipe_info *pipe;

	pipe = alloc_pipe_info();
	if (unlikely(!pipe)) {
		error = -ENOMEM;
		goto out;
	}

	fds[0] = alloc_fd(files, "PIPER");
	if (unlikely(fds[0] < 0)) {
		error = fds[0];
		free_pipe_info(pipe);
		goto out;
	}

	fds[1] = alloc_fd(files, "PIPEW");
	if (unlikely(fds[1] < 0)) {
		error = fds[1];
		free_pipe_info(pipe);
		free_fd(files, fds[0]);
		goto out;
	}

	/* initialize */
	filps[0] = fdget(fds[0]);
	filps[1] = fdget(fds[1]);

	filps[0]->private_data = pipe;
	filps[0]->f_flags = O_RDONLY | (flags & O_NONBLOCK);
	filps[0]->f_mode = FMODE_READ;
	filps[0]->f_op = &pipefifo_fops;

	filps[1]->private_data = pipe;
	filps[1]->f_flags = O_WRONLY | (flags & O_NONBLOCK);
	filps[1]->f_mode = FMODE_WRITE;
	filps[1]->f_op = &pipefifo_fops;

	flides[0] = fds[0];
	flides[1] = fds[1];

	put_file(filps[0]);
	put_file(filps[1]);

out:
	if (likely(!error)) {
		pipe_debug("CPU:%d, PID:%d, flides[0]:%d, flides[1]:%d",
			smp_processor_id(), current->pid, flides[0], flides[1]);
	} else {
		pipe_debug("CPU:%d, PID:%d, -errno:%d",
			smp_processor_id(), current->pid, error);
	}	
	return error;	
}

SYSCALL_DEFINE2(pipe2, int __user *, flides, int, flags)
{
	long ret;
	int fds[2];

	syscall_enter("flags: %#x\n", flags);
	ret = do_pipe_create(fds, flags);
	if (!ret) {
		if (copy_to_user(flides, fds, sizeof(fds)))
			ret = -EFAULT;
	}

	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE1(pipe, int __user *, flides)
{
	return sys_pipe2(flides, 0);
}

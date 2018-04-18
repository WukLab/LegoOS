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
#include <lego/files.h>
#include <processor/processor.h>
#include <processor/pcache.h>
#include <processor/fs.h>

#ifdef CONFIG_DEBUG_PIPE
#define pipe_debug(fmt, ...)					\
	pr_debug("CPU%d PID%d-%s %s() "fmt"\n",			\
		smp_processor_id(), current->pid, current->comm,\
		__func__, __VA_ARGS__)
#else
#define pipe_debug(fmt, ...)	do { } while (0)
#endif

#define PIPE_MAX_ORDER	(8)
#define PIPE_MAX_SIZE	((1 << PIPE_MAX_ORDER) * PAGE_SIZE)

/*
 * We implement pipe by a 32-pages kernel memory ring buffer
 * pipe_info is the metadata to manage a pipe, readers/writers are counters
 * of active readers/writers processes, and would initialized as 1 while
 * sys_pipe() or sys_pipe2() is called to create a new pipe.
 *
 * pipe_open() would increment a counter (depends on the file is
 * a pipe reader or writer), and filo_open() is called by copy_files(), which is
 * a fork()'s rountine.
 *
 * HEAD is the pointer for consumers to dequeue from ring buffer
 * TAIL is the pointer for producers to enqueue into ring buffer
 *
 * pipe_read() reads n bytes from ring buffer and advances pipe->HEAD, and while buffer
 * has enough room (currently 4-pages), wakes up all waiters (including readers/writers)
 * in order to make consumers work. And pipe_read() sleeps on the ring buffer is completely
 * empty. (It means pipe_read() is not necessary to read same nrbytes as it required).
 *
 * pipe_write() writes n bytes into ring buffer and advances pipe->TAIL. It first checks if
 * there are still active readers, if not, pipe is broken and SIGPIPE needs to send to current
 * process. Unlike pipe_read(), pipe_write() would wait on ring buffer until it has more than
 * n bytes space. And it wakes up all waiters before each time it goes to sleep to make
 * consumers make more room on ring buffer.
 *
 * pipe buffer and pipe_info would free on pipe->readers = pipe->writers = 0; pipe_release
 * would decrease a readers or writers counter, which is called when file is closed.
 */

struct pipe_info {
	spinlock_t		lock;
	wait_queue_head_t	wait;
	unsigned int		readers;
	unsigned int		writers;
	unsigned long		HEAD;		/* consumers pointer */
	unsigned long		TAIL;		/* producers pointer */
	unsigned long		buffer;
	unsigned long		END;
	int			len;		/* nbytes in use */

	/*
	 * How many references are there to this structure?
	 * Basically, means how many filp->private_data are there.
	 */
	atomic_t		_ref;
} ____cacheline_aligned;

static inline void get_pipe(struct pipe_info *p)
{
	BUG_ON(atomic_read(&p->_ref) <= 0);
	atomic_inc(&p->_ref);
}

static inline void __put_pipe(struct pipe_info *pipe)
{
	pipe_debug("pipe: %p buffer: %#lx", pipe, pipe->buffer);

	BUG_ON(!pipe);
	BUG_ON(!pipe->buffer);

	kfree((void *)pipe->buffer);
	pipe->buffer = 0;
	kfree(pipe);
}

static inline void put_pipe(struct pipe_info *p)
{
	if (atomic_dec_and_test(&p->_ref))
		__put_pipe(p);
}

struct pipe_info *alloc_pipe_info(void)
{
	void *buffer;
	struct pipe_info *pipe;

	buffer = kzalloc(PIPE_MAX_SIZE, GFP_KERNEL);
	if (!buffer)
		return NULL;

	pipe = kzalloc(sizeof(*pipe), GFP_KERNEL);
	if (!pipe) {
		kfree(buffer);
		return NULL;
	}

	pipe->buffer = pipe->HEAD = pipe->TAIL = (unsigned long)buffer;
	pipe->END = pipe->buffer + PIPE_MAX_SIZE;
	pipe->readers = 1;
	pipe->writers = 1;
	pipe->len = 0;
	init_waitqueue_head(&pipe->wait);
	spin_lock_init(&pipe->lock);
	atomic_set(&pipe->_ref, 1);

	pipe_debug("pipe: %p  buffer: %#lx", pipe, pipe->buffer);
	return pipe;
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

static ssize_t pipe_read(struct file *filp, char __user *user_buf,
			 size_t count, loff_t *off)
{
	ssize_t ret = 0;
	int do_wakeup = 0;
	struct pipe_info *pipe = filp->private_data;

	BUG_ON(!pipe);

	if (!count)
		return 0;

	pipe_lock(pipe);
	for (;;) {
		if (pipe->len) {
			ret = count;

			/* Limit to the maximum we have now */
			if (count > pipe->len)
				count = pipe->len;

			if (pipe->HEAD + count > pipe->END) {
				unsigned long rear, front;

				rear = pipe->END - pipe->HEAD;
				front = count - rear;
				BUG_ON(front > count);

				if (rear) {

					pipe_debug("buffer: [%#lx-%#lx] HEAD: %#lx rear: %#lx",
						pipe->buffer, pipe->END, pipe->HEAD, rear);
					if (copy_to_user(user_buf, (void *)pipe->HEAD, rear)) {
						ret = -EFAULT;
						break;
					}
				}

				pipe_debug("buffer: [%#lx-%#lx] front: %#lx",
					pipe->buffer, pipe->END, front);
				if (copy_to_user(user_buf + rear, (void *)pipe->buffer, front)) {
					ret = -EFAULT;
					break;
				}

				pipe->HEAD = pipe->buffer + front;
				pipe->len -= count;
			} else {
				pipe_debug("buffer: [%#lx-%#lx] HEAD: %#lx count: %#lx",
					pipe->buffer, pipe->END, pipe->HEAD, count);
				if (copy_to_user(user_buf, (void *)pipe->HEAD, count)) {
					ret = -EFAULT;
					break;
				}
				pipe->HEAD += count;
				pipe->len -= count;
			}

			/*
			 * I do_wakeup to wakeup writers when more than 4 page left
			 */
			if (PIPE_MAX_SIZE - pipe->len >= 4 * PAGE_SIZE)
				do_wakeup = 1;

			if (signal_pending(current)) {
				if (!ret)
					ret = -ERESTARTSYS;
				break;
			}

			break;
		}

		if (!pipe->writers)
			break;

		/*
		 * if buffer is already empty, wakeup writers before sleep
		 */
		wake_up_interruptible(&pipe->wait);
		pipe_debug("sleep fd: %d nr_readers:%u, nr_writers:%u",
				filp->fd,
				pipe->readers, pipe->writers);
		pipe_wait(pipe);
		pipe_debug("woken up fd: %d nr_readers:%u, nr_writers:%u",
				filp->fd,
				pipe->readers, pipe->writers);
	}
	pipe_unlock(pipe);

	if (do_wakeup)
		wake_up_interruptible(&pipe->wait);

	return ret;
}

static ssize_t pipe_write(struct file *filp, const char __user *user_buf,
			  size_t count, loff_t *off)
{
	ssize_t ret = 0;
	int do_wakeup = 0;
	struct pipe_info *pipe = filp->private_data;

	BUG_ON(!pipe);

	if (!count)
		return 0;

	/* Send SIGPIPE if there is no more reader */
	if (!pipe->readers) {
		kill_pid_info(SIGPIPE, (struct siginfo *) 0, current->pid);
		ret = -EPIPE;
		goto out;
	}

	pipe_lock(pipe);
	for (;;) {
		if (pipe->len + count <= PIPE_MAX_SIZE) {
			ret = count;

			/*
			 *
			 *   |------------------------------|
			 *   |           |---------|        |
			 *   ^  (front)  ^  (len)  ^ (rear) ^
			 *   ^           ^         ^        ^
			 * Buffer       HEAD       TAIL     END
			 *              Reader     Writer
			 *
			 * TAIL points to the first writable byte.
			 * HEAD points to the first readable byte
			 * END points to (Buffer + PIPE_MAX_SIZE)
			 */
			if (pipe->TAIL + count > pipe->END) {
				unsigned long rear, front;

				/*
				 * Rear is not enough to hold the new buf
				 * Divide it into two copy_from_user: rear, front.
				 */
				rear = pipe->END - pipe->TAIL;
				front = count - rear;
				BUG_ON(front > count);

				/* Rear if it is not zero */
				if (rear) {
					pipe_debug("buffer: [%#lx-%#lx] TAIL: %#lx rear: %#lx",
						pipe->buffer, pipe->END, pipe->TAIL, rear);
					if (copy_from_user((void *)pipe->TAIL, user_buf, rear)) {
						ret = -EFAULT;
						break;
					}
				}

				/* Front */
				pipe_debug("buffer: [%#lx-%#lx] TAIL: %#lx front: %#lx",
					pipe->buffer, pipe->END, pipe->TAIL, front);
				if (copy_from_user((void *)pipe->buffer, user_buf + rear, front)) {
					ret = -EFAULT;
					break;
				}

				pipe->TAIL = pipe->buffer + front;
				pipe->len += count;
			} else {
				pipe_debug("buffer: [%#lx-%#lx] TAIL: %#lx count: %#lx",
					pipe->buffer, pipe->END, pipe->TAIL, count);
				if (copy_from_user((void *)pipe->TAIL, user_buf, count)) {
					ret = -EFAULT;
					break;
				}
				pipe->TAIL += count;
				pipe->len += count;
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
		pipe_debug("sleep fd: %d nr_readers:%u, nr_writers:%u",
				filp->fd,
				pipe->readers, pipe->writers);
		pipe_wait(pipe);
		pipe_debug("woken up fd: %d nr_readers:%u, nr_writers:%u",
				filp->fd,
				pipe->readers, pipe->writers);
	}
	pipe_unlock(pipe);

out:
	if (do_wakeup)
		wake_up_interruptible(&pipe->wait);
	return ret;
}

/*
 * Callback for fork(), when file table is duplicated.
 */
static int pipe_open(struct file *f)
{
	struct pipe_info *pipe = f->private_data;

	BUG_ON(!pipe);

	pipe_lock(pipe);
	if (f->f_mode & FMODE_READ) {
		pipe->readers++;
		get_pipe(pipe);
	} else if (f->f_mode & FMODE_WRITE) {
		pipe->writers++;
		get_pipe(pipe);
	} else
		BUG();
	if (pipe->readers == 1 || pipe->writers == 1)
		wake_up_interruptible(&pipe->wait);

	pipe_debug("pipe: %p _ref: %d fd: %d nr_readers:%u, nr_writers:%u",
		pipe, atomic_read(&pipe->_ref), f->fd, pipe->readers, pipe->writers);

	pipe_unlock(pipe);
	return 0;
}

static int pipe_release(struct file *filp)
{
	struct pipe_info *pipe = filp->private_data;

	BUG_ON(!pipe);

	pipe_lock(pipe);
	if ((filp->f_mode & FMODE_READ) && (pipe->readers > 0))
		pipe->readers--;

	if ((filp->f_mode & FMODE_WRITE) && (pipe->writers > 0))
		pipe->writers--;

	if (pipe->readers || pipe->writers)
		wake_up_interruptible(&pipe->wait);

	pipe_debug("pipe: %p _ref: %d fd:%d, nr_readers:%u, nr_writers:%u",
		pipe, atomic_read(&pipe->_ref), filp->fd, pipe->readers, pipe->writers);

	pipe_unlock(pipe);

	/* May lead to a eventual free */
	put_pipe(pipe);
	return 0;
}

const struct file_operations pipefifo_fops = {
	.llseek		= no_llseek,
	.open		= pipe_open,
	.read		= pipe_read,
	.write		= pipe_write,
	.release	= pipe_release,
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

	if (flags & ~(O_CLOEXEC | O_NONBLOCK | O_DIRECT))
		return -EINVAL;

	pipe = alloc_pipe_info();
	if (!pipe) {
		error = -ENOMEM;
		goto out;
	}

	fds[0] = alloc_fd(files, "PIPER");
	if (fds[0] < 0) {
		error = fds[0];
		put_pipe(pipe);
		goto out;
	}

	fds[1] = alloc_fd(files, "PIPEW");
	if (fds[1] < 0) {
		error = fds[1];
		put_pipe(pipe);
		free_fd(files, fds[0]);
		goto out;
	}

	if (flags & O_CLOEXEC) {
		__set_close_on_exec(fds[0], files);
		__set_close_on_exec(fds[1], files);
	} else {
		__clear_close_on_exec(fds[0], files);
		__clear_close_on_exec(fds[1], files);
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

	/*
	 * alloc_pipe_info init the _ref as 1
	 * Since we set two private_data above, we need to grab one more.
	 */
	get_pipe(pipe);
out:
	pipe_debug("ret: %d flides[0]:%d, flides[1]:%d pipe: %p _ref: %d",
		error, flides[0], flides[1], pipe, atomic_read(&pipe->_ref));
	return error;
}

SYSCALL_DEFINE2(pipe2, int __user *, flides, int, flags)
{
	long ret;
	int fds[2];

	ret = do_pipe_create(fds, flags);
	if (!ret) {
		if (copy_to_user(flides, fds, sizeof(fds)))
			ret = -EFAULT;
	}
	return ret;
}

SYSCALL_DEFINE1(pipe, int __user *, flides)
{
	return sys_pipe2(flides, 0);
}

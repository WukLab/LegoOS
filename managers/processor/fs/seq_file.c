/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/seq_file.h>
#include <lego/spinlock.h>

static void seq_set_overflow(struct seq_file *m)
{
	m->count = m->size;
}

static void *seq_buf_alloc(unsigned long size)
{
	void *buf;
	gfp_t gfp = GFP_KERNEL;

	buf = kmalloc(size, gfp);
	return buf;
}

/**
 *	seq_open -	initialize sequential file
 *	@file: file we initialize
 *	@op: method table describing the sequence
 *
 *	seq_open() sets @file, associating it with a sequence described
 *	by @op.  @op->start() sets the iterator up and returns the first
 *	element of sequence. @op->stop() shuts it down.  @op->next()
 *	returns the next element of sequence.  @op->show() prints element
 *	into the buffer.  In case of error ->start() and ->next() return
 *	ERR_PTR(error).  In the end of sequence they return %NULL. ->show()
 *	returns 0 in case of success and negative number in case of error.
 *	Returning SEQ_SKIP means "discard this element and move on".
 *	Note: seq_open() will allocate a struct seq_file and store its
 *	pointer in @file->private_data. This pointer should not be modified.
 */
int seq_open(struct file *file, const struct seq_operations *op)
{
	struct seq_file *p;

	WARN_ON(file->private_data);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	file->private_data = p;

	spin_lock_init(&p->lock);
	p->op = op;

	/*
	 * No refcounting: the lifetime of 'p' is constrained
	 * to the lifetime of the file.
	 */
	p->file = file;

	/*
	 * seq_files support lseek() and pread().  They do not implement
	 * write() at all, but we clear FMODE_PWRITE here for historical
	 * reasons.
	 *
	 * If a client of seq_files a) implements file.write() and b) wishes to
	 * support pwrite() then that client will need to implement its own
	 * file.open() which calls seq_open() and then sets FMODE_PWRITE.
	 */
	file->f_mode &= ~FMODE_PWRITE;

	return 0;
}

static void *single_start(struct seq_file *p, loff_t *pos)
{
	return NULL + (*pos == 0);
}

static void *single_next(struct seq_file *p, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void single_stop(struct seq_file *p, void *v)
{
}

int single_open(struct file *file, int (*show)(struct seq_file *, void *),
		void *data)
{
	struct seq_operations *op = kmalloc(sizeof(*op), GFP_KERNEL);
	int res = -ENOMEM;

	if (op) {
		op->start = single_start;
		op->next = single_next;
		op->stop = single_stop;
		op->show = show;
		res = seq_open(file, op);
		if (!res)
			((struct seq_file *)file->private_data)->private = data;
		else
			kfree(op);
	}
	return res;
}

int single_open_size(struct file *file, int (*show)(struct seq_file *, void *),
		void *data, size_t size)
{
	char *buf = seq_buf_alloc(size);
	int ret;
	if (!buf)
		return -ENOMEM;
	ret = single_open(file, show, data);
	if (ret) {
		kfree(buf);
		return ret;
	}
	((struct seq_file *)file->private_data)->buf = buf;
	((struct seq_file *)file->private_data)->size = size;
	return 0;
}

static int traverse(struct seq_file *m, loff_t offset)
{
	loff_t pos = 0, index;
	int error = 0;
	void *p;

	index = 0;
	m->count = m->from = 0;
	if (!offset) {
		m->index = index;
		return 0;
	}
	if (!m->buf) {
		m->buf = seq_buf_alloc(m->size = PAGE_SIZE);
		if (!m->buf)
			return -ENOMEM;
	}
	p = m->op->start(m, &index);
	while (p) {
		error = PTR_ERR(p);
		if (IS_ERR(p))
			break;
		error = m->op->show(m, p);
		if (error < 0)
			break;
		if (unlikely(error)) {
			error = 0;
			m->count = 0;
		}
		if (seq_has_overflowed(m))
			goto Eoverflow;
		if (pos + m->count > offset) {
			m->from = offset - pos;
			m->count -= m->from;
			m->index = index;
			break;
		}
		pos += m->count;
		m->count = 0;
		if (pos == offset) {
			index++;
			m->index = index;
			break;
		}
		p = m->op->next(m, p, &index);
	}
	m->op->stop(m, p);
	m->index = index;
	return error;

Eoverflow:
	m->op->stop(m, p);
	kfree(m->buf);
	m->count = 0;
	m->buf = seq_buf_alloc(m->size <<= 1);
	return !m->buf ? -ENOMEM : -EAGAIN;
}

#ifdef CONFIG_DEBUG_PROC_SYS
static void debug_proc_sys(void __user *to, const char *from, unsigned long n)
{
	pr_info("seq_file: dest_uva: %p, nr_chars: %lu\n"
		"  string: [%s]\n", to, n, from);
}
#else
static inline void
debug_proc_sys(void __user *to, const char *from, unsigned long n) { }
#endif

/**
 *	seq_read -	->read() method for sequential files.
 *	@file: the file to read from
 *	@buf: the buffer to read to
 *	@size: the maximum number of bytes to read
 *	@ppos: the current position in the file
 *
 *	Ready-made ->f_op->read()
 */
ssize_t seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	size_t copied = 0;
	loff_t pos;
	size_t n;
	void *p;
	int err = 0;

	spin_lock(&m->lock);

	/* Don't assume *ppos is where we left it */
	if (unlikely(*ppos != m->read_pos)) {
		while ((err = traverse(m, *ppos)) == -EAGAIN)
			;
		if (err) {
			/* With prejudice... */
			m->read_pos = 0;
			m->index = 0;
			m->count = 0;
			goto Done;
		} else {
			m->read_pos = *ppos;
		}
	}

	/* grab buffer if we didn't have one */
	if (!m->buf) {
		m->buf = seq_buf_alloc(m->size = PAGE_SIZE);
		if (!m->buf)
			goto Enomem;
	}

	/* if not empty - flush it first */
	if (m->count) {
		n = min(m->count, size);
		err = copy_to_user(buf, m->buf + m->from, n);
		if (err)
			goto Efault;
		debug_proc_sys(buf, m->buf + m->from, n);
		m->count -= n;
		m->from += n;
		size -= n;
		buf += n;
		copied += n;
		if (!m->count) {
			m->from = 0;
			m->index++;
		}
		if (!size)
			goto Done;
	}
	/* we need at least one record in buffer */
	pos = m->index;
	p = m->op->start(m, &pos);
	while (1) {
		err = PTR_ERR(p);
		if (!p || IS_ERR(p))
			break;
		err = m->op->show(m, p);
		if (err < 0)
			break;
		if (unlikely(err))
			m->count = 0;
		if (unlikely(!m->count)) {
			p = m->op->next(m, p, &pos);
			m->index = pos;
			continue;
		}
		if (m->count < m->size)
			goto Fill;
		m->op->stop(m, p);
		kfree(m->buf);
		m->count = 0;
		m->buf = seq_buf_alloc(m->size <<= 1);
		if (!m->buf)
			goto Enomem;
		pos = m->index;
		p = m->op->start(m, &pos);
	}
	m->op->stop(m, p);
	m->count = 0;
	goto Done;
Fill:
	/* they want more? let's try to get some more */
	while (m->count < size) {
		size_t offs = m->count;
		loff_t next = pos;
		p = m->op->next(m, p, &next);
		if (!p || IS_ERR(p)) {
			err = PTR_ERR(p);
			break;
		}
		err = m->op->show(m, p);
		if (seq_has_overflowed(m) || err) {
			m->count = offs;
			if (likely(err <= 0))
				break;
		}
		pos = next;
	}
	m->op->stop(m, p);
	n = min(m->count, size);
	err = copy_to_user(buf, m->buf, n);
	if (err)
		goto Efault;
	debug_proc_sys(buf, m->buf, n);
	copied += n;
	m->count -= n;
	if (m->count)
		m->from = n;
	else
		pos++;
	m->index = pos;
Done:
	if (!copied)
		copied = err;
	else {
		*ppos += copied;
		m->read_pos += copied;
	}
	spin_unlock(&m->lock);
	return copied;

Enomem:
	err = -ENOMEM;
	goto Done;
Efault:
	err = -EFAULT;
	goto Done;
}

/**
 *	seq_lseek -	->llseek() method for sequential files.
 *	@file: the file in question
 *	@offset: new position
 *	@whence: 0 for absolute, 1 for relative position
 *
 *	Ready-made ->f_op->llseek()
 */
loff_t seq_lseek(struct file *file, loff_t offset, int whence)
{
	struct seq_file *m = file->private_data;
	loff_t retval = -EINVAL;

	spin_lock(&m->lock);
	switch (whence) {
	case SEEK_CUR:
		offset += file->f_pos;
	case SEEK_SET:
		if (offset < 0)
			break;
		retval = offset;
		if (offset != m->read_pos) {
			while ((retval = traverse(m, offset)) == -EAGAIN)
				;
			if (retval) {
				/* with extreme prejudice... */
				file->f_pos = 0;
				m->read_pos = 0;
				m->index = 0;
				m->count = 0;
			} else {
				m->read_pos = offset;
				retval = file->f_pos = offset;
			}
		} else {
			file->f_pos = offset;
		}
	}
	spin_unlock(&m->lock);
	return retval;
}

/**
 *	seq_release -	free the structures associated with sequential file.
 *	@file: file in question
 *	@inode: its inode
 *
 *	Frees the structures associated with sequential file; can be used
 *	as ->f_op->release() if you don't have private data to destroy.
 */
int seq_release(struct file *file)
{
	struct seq_file *m = file->private_data;
	kfree(m->buf);
	kfree(m);
	return 0;
}

int single_release(struct file *file)
{
	const struct seq_operations *op = ((struct seq_file *)file->private_data)->op;
	int res = seq_release(file);
	kfree(op);
	return res;
}

void seq_vprintf(struct seq_file *m, const char *f, va_list args)
{
	int len;

	if (m->count < m->size) {
		len = vsnprintf(m->buf + m->count, m->size - m->count, f, args);
		if (m->count + len < m->size) {
			m->count += len;
			return;
		}
	}
	seq_set_overflow(m);
}

void seq_printf(struct seq_file *m, const char *f, ...)
{
	va_list args;

	va_start(args, f);
	seq_vprintf(m, f, args);
	va_end(args);
}

void seq_putc(struct seq_file *m, char c)
{
	if (m->count >= m->size)
		return;

	m->buf[m->count++] = c;
}

void seq_puts(struct seq_file *m, const char *s)
{
	int len = strlen(s);

	if (m->count + len >= m->size) {
		seq_set_overflow(m);
		return;
	}
	memcpy(m->buf + m->count, s, len);
	m->count += len;
}

/*
 * A helper routine for putting decimal numbers without rich format of printf().
 * only 'unsigned long long' is supported.
 * This routine will put strlen(delimiter) + number into seq_file.
 * This routine is very quick when you show lots of numbers.
 * In usual cases, it will be better to use seq_printf(). It's easier to read.
 */
void seq_put_decimal_ull(struct seq_file *m, const char *delimiter,
			 unsigned long long num)
{
	int len;

	if (m->count + 2 >= m->size) /* we'll write 2 bytes at least */
		goto overflow;

	len = strlen(delimiter);
	if (m->count + len >= m->size)
		goto overflow;

	memcpy(m->buf + m->count, delimiter, len);
	m->count += len;

	if (m->count + 1 >= m->size)
		goto overflow;

	if (num < 10) {
		m->buf[m->count++] = num + '0';
		return;
	}

	len = num_to_str(m->buf + m->count, m->size - m->count, num);
	if (!len)
		goto overflow;

	m->count += len;
	return;

overflow:
	seq_set_overflow(m);
}

void seq_put_decimal_ll(struct seq_file *m, const char *delimiter, long long num)
{
	int len;

	if (m->count + 3 >= m->size) /* we'll write 2 bytes at least */
		goto overflow;

	len = strlen(delimiter);
	if (m->count + len >= m->size)
		goto overflow;

	memcpy(m->buf + m->count, delimiter, len);
	m->count += len;

	if (m->count + 2 >= m->size)
		goto overflow;

	if (num < 0) {
		m->buf[m->count++] = '-';
		num = -num;
	}

	if (num < 10) {
		m->buf[m->count++] = num + '0';
		return;
	}

	len = num_to_str(m->buf + m->count, m->size - m->count, num);
	if (!len)
		goto overflow;

	m->count += len;
	return;

overflow:
	seq_set_overflow(m);
}

/**
 * seq_write - write arbitrary data to buffer
 * @seq: seq_file identifying the buffer to which data should be written
 * @data: data address
 * @len: number of bytes
 *
 * Return 0 on success, non-zero otherwise.
 */
int seq_write(struct seq_file *seq, const void *data, size_t len)
{
	if (seq->count + len < seq->size) {
		memcpy(seq->buf + seq->count, data, len);
		seq->count += len;
		return 0;
	}
	seq_set_overflow(seq);
	return -1;
}

/**
 * seq_pad - write padding spaces to buffer
 * @m: seq_file identifying the buffer to which data should be written
 * @c: the byte to append after padding if non-zero
 */
void seq_pad(struct seq_file *m, char c)
{
	int size = m->pad_until - m->count;
	if (size > 0)
		seq_printf(m, "%*s", size, "");
	if (c)
		seq_putc(m, c);
}

/* A complete analogue of print_hex_dump() */
void seq_hex_dump(struct seq_file *m, const char *prefix_str, int prefix_type,
		  int rowsize, int groupsize, const void *buf, size_t len,
		  bool ascii)
{
	const u8 *ptr = buf;
	int i, linelen, remaining = len;
	char *buffer;
	size_t size;
	int ret;

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len && !seq_has_overflowed(m); i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		switch (prefix_type) {
		case DUMP_PREFIX_ADDRESS:
			seq_printf(m, "%s%p: ", prefix_str, ptr + i);
			break;
		case DUMP_PREFIX_OFFSET:
			seq_printf(m, "%s%.8x: ", prefix_str, i);
			break;
		default:
			seq_printf(m, "%s", prefix_str);
			break;
		}

		size = seq_get_buf(m, &buffer);
		ret = hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
					 buffer, size, ascii);
		seq_commit(m, ret < size ? ret : -1);

		seq_putc(m, '\n');
	}
}

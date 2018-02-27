/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SEQ_FILE_H_
#define _LEGO_SEQ_FILE_H_

#include <lego/files.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>

struct seq_operations;

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	u64 version;
	spinlock_t lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};

/**
 * seq_has_overflowed - check if the buffer has overflowed
 * @m: the seq_file handle
 *
 * seq_files have a buffer which may overflow. When this happens a larger
 * buffer is reallocated and all the data will be printed again.
 * The overflow state is true when m->count == m->size.
 *
 * Returns true if the buffer received more than it can hold.
 */
static inline bool seq_has_overflowed(struct seq_file *m)
{
	return m->count == m->size;
}

/**
 * seq_get_buf - get buffer to write arbitrary data to
 * @m: the seq_file handle
 * @bufp: the beginning of the buffer is stored here
 *
 * Return the number of bytes available in the buffer, or zero if
 * there's no space.
 */
static inline size_t seq_get_buf(struct seq_file *m, char **bufp)
{
	BUG_ON(m->count > m->size);
	if (m->count < m->size)
		*bufp = m->buf + m->count;
	else
		*bufp = NULL;

	return m->size - m->count;
}

/**
 * seq_commit - commit data to the buffer
 * @m: the seq_file handle
 * @num: the number of bytes to commit
 *
 * Commit @num bytes of data written to a buffer previously acquired
 * by seq_buf_get.  To signal an error condition, or that the data
 * didn't fit in the available space, pass a negative @num value.
 */
static inline void seq_commit(struct seq_file *m, int num)
{
	if (num < 0) {
		m->count = m->size;
	} else {
		BUG_ON(m->count + num > m->size);
		m->count += num;
	}
}

/**
 * seq_setwidth - set padding width
 * @m: the seq_file handle
 * @size: the max number of bytes to pad.
 *
 * Call seq_setwidth() for setting max width, then call seq_printf() etc. and
 * finally call seq_pad() to pad the remaining bytes.
 */
static inline void seq_setwidth(struct seq_file *m, size_t size)
{
	m->pad_until = m->count + size;
}

int seq_open(struct file *file, const struct seq_operations *op);
int single_open(struct file *file, int (*show)(struct seq_file *, void *),
		void *data);
int single_open_size(struct file *file, int (*show)(struct seq_file *, void *),
		void *data, size_t size);

ssize_t seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
loff_t seq_lseek(struct file *file, loff_t offset, int whence);
int seq_release(struct file *file);
int single_release(struct file *file);

void seq_vprintf(struct seq_file *m, const char *f, va_list args);
void seq_printf(struct seq_file *m, const char *f, ...);
void seq_putc(struct seq_file *m, char c);
void seq_puts(struct seq_file *m, const char *s);
void seq_put_decimal_ull(struct seq_file *m, const char *delimiter,
			 unsigned long long num);
void seq_put_decimal_ll(struct seq_file *m, const char *delimiter, long long num);
int seq_write(struct seq_file *seq, const void *data, size_t len);
void seq_pad(struct seq_file *m, char c);
void seq_hex_dump(struct seq_file *m, const char *prefix_str, int prefix_type,
		  int rowsize, int groupsize, const void *buf, size_t len,
		  bool ascii);

#endif /* _LEGO_SEQ_FILE_H_ */

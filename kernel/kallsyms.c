/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/types.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/sections.h>
#include <lego/kallsyms.h>

/*
 * These will be re-linked against their real values
 * during the second link stage.
 */
extern const unsigned long kallsyms_addresses[] __weak;
extern const int kallsyms_offsets[] __weak;
extern const u8 kallsyms_names[] __weak;

/*
 * Tell the compiler that the count isn't in the small data section if the arch
 * has one (eg: FRV).
 */
extern const unsigned long kallsyms_num_syms
__attribute__((weak, section(".rodata")));

extern const unsigned long kallsyms_relative_base
__attribute__((weak, section(".rodata")));

extern const u8 kallsyms_token_table[] __weak;
extern const u16 kallsyms_token_index[] __weak;

extern const unsigned long kallsyms_markers[] __weak;

static inline int is_kernel_inittext(unsigned long addr)
{
	if (addr >= (unsigned long)__sinittext &&
	    addr <= (unsigned long)__einittext)
		return 1;
	return 0;
}

static inline int is_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)__stext &&
	    addr <= (unsigned long)__etext)
		return 1;
	return 0;
}

static inline int is_ksym_addr(unsigned long addr)
{
	return is_kernel_inittext(addr) || is_kernel_text(addr);
}

static unsigned long get_symbol_pos(unsigned long addr,
				    unsigned long *symbolsize,
				    unsigned long *offset)
{
	return 0;
}

/*
 * Find the offset on the compressed stream given and index in the
 * kallsyms array.
 */
static unsigned int get_symbol_offset(unsigned long pos)
{
	const u8 *name;
	int i;

	/*
	 * Use the closest marker we have. We have markers every 256 positions,
	 * so that should be close enough.
	 */
	name = &kallsyms_names[kallsyms_markers[pos >> 8]];

	/*
	 * Sequentially scan all the symbols up to the point we're searching
	 * for. Every symbol is stored in a [<len>][<len> bytes of data] format,
	 * so we just need to add the len to the current pointer for every
	 * symbol we wish to skip.
	 */
	for (i = 0; i < (pos & 0xFF); i++)
		name = name + (*name) + 1;

	return name - kallsyms_names;
}

/*
 * Expand a compressed symbol data into the resulting uncompressed string,
 * if uncompressed string is too long (>= maxlen), it will be truncated,
 * given the offset to where the symbol is in the compressed stream.
 */
static unsigned int kallsyms_expand_symbol(unsigned int off,
					   char *result, size_t maxlen)
{
	int len, skipped_first = 0;
	const u8 *tptr, *data;

	/* Get the compressed symbol length from the first symbol byte. */
	data = &kallsyms_names[off];
	len = *data;
	data++;

	/*
	 * Update the offset to return the offset for the next symbol on
	 * the compressed stream.
	 */
	off += len + 1;

	/*
	 * For every byte on the compressed symbol data, copy the table
	 * entry for that byte.
	 */
	while (len) {
		tptr = &kallsyms_token_table[kallsyms_token_index[*data]];
		data++;
		len--;

		while (*tptr) {
			if (skipped_first) {
				if (maxlen <= 1)
					goto tail;
				*result = *tptr;
				result++;
				maxlen--;
			} else
				skipped_first = 1;
			tptr++;
		}
	}

tail:
	if (maxlen)
		*result = '\0';

	/* Return to offset to the next symbol. */
	return off;
}

const char *kallsyms_lookup(unsigned long addr,
			    unsigned long *symbolsize,
			    unsigned long *offset, char *namebuf)
{
	namebuf[KSYM_NAME_LEN - 1] = 0;
	namebuf[0] = 0;

	if (is_ksym_addr(addr)) {
		unsigned long pos;

		pos = get_symbol_pos(addr, symbolsize, offset);
		/* Grab name */
		kallsyms_expand_symbol(get_symbol_offset(pos),
				       namebuf, KSYM_NAME_LEN);
		return namebuf;
	}
	return NULL;
}

/* Look up a kernel symbol and return it in a text buffer. */
static int __sprint_symbol(char *buffer, unsigned long address,
			   int symbol_offset, int add_offset)
{
	const char *name;
	unsigned long offset, size;
	int len;

	address += symbol_offset;
	name = kallsyms_lookup(address, &size, &offset, buffer);
	if (!name)
		return sprintf(buffer, "0x%lx", address - symbol_offset);

	if (name != buffer)
		strcpy(buffer, name);
	len = strlen(buffer);
	offset -= symbol_offset;

	if (add_offset)
		len += sprintf(buffer + len, "+%#lx/%#lx", offset, size);

	return len;
}

/**
 * sprint_symbol - Look up a kernel symbol and return it in a text buffer
 * @buffer: buffer to be stored
 * @address: address to lookup
 *
 * This function looks up a kernel symbol with @address and stores its name,
 * offset, size and module name to @buffer if possible. If no symbol was found,
 * just saves its @address as is.
 *
 * This function returns the number of bytes stored in @buffer.
 */
int sprint_symbol(char *buffer, unsigned long address)
{
	return __sprint_symbol(buffer, address, 0, 1);
}

/**
 * sprint_symbol_no_offset - Look up a kernel symbol and return it in a text buffer
 * @buffer: buffer to be stored
 * @address: address to lookup
 *
 * This function looks up a kernel symbol with @address and stores its name
 * and module name to @buffer if possible. If no symbol was found, just saves
 * its @address as is.
 *
 * This function returns the number of bytes stored in @buffer.
 */
int sprint_symbol_no_offset(char *buffer, unsigned long address)
{
	return __sprint_symbol(buffer, address, 0, 0);
}

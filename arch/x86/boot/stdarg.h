/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Variable Argument Manipulation API
 */

#ifndef _BOOT_STDARG_H_
#define _BOOT_STDARG_H_

#include <lego/stddef.h>

#define __STACK_ALIGN		sizeof(long)
#define __va_rounded_size(TYPE) \
	(((sizeof(TYPE) + __STACK_ALIGN - 1) / __STACK_ALIGN) * __STACK_ALIGN)

typedef char *va_list;

#define va_arg(AP, TYPE)				\
	({						\
		TYPE __ret;				\
		__ret = *((TYPE *)(AP));		\
		(AP) += __va_rounded_size(TYPE);	\
		__ret;					\
	})

#define va_start(AP, LAST)	(AP) = ((va_list)&(LAST) + __va_rounded_size(LAST))
#define va_end(AP)		(AP) = NULL
#define va_copy(DEST, SRC)	(DEST) = (SRC)

#endif /* _BOOT_STDARG_H_ */

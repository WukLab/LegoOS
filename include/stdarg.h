/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * Variable argument lists
 */

#ifndef _DISOS_STDARG_H_
#define _DISOS_STDARG_H_

#define __STACK_ALIGN		sizeof(long)
#define __va_rounded_size(TYPE) \
	(((sizeof(TYPE) + __STACK_ALIGN - 1) / __STACK_ALIGN) * __STACK_ALIGN)

/*
 * Variable Argument Manipulation API
 */
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

#endif /* _DISOS_STDARG_H_ */

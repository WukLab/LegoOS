/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TYPECHECK_H_
#define _LEGO_TYPECHECK_H_

/*
 * Check at compile time that something is of a particular type.
 * Compiler will give you a warning.
 */
#define typecheck(type, x)		\
({					\
	type __dummy;			\
	typeof(x) __dummy2;		\
	(void)(&__dummy == & __dummy2);	\
	1;				\
})

/*
 * Check at compile time that 'function' is a certain type, or is a pointer
 * to that type (needs to use typedef for the function type.)
 */
#define typecheck_fn(type,function)	\
({					\
	typeof(type) __tmp = function;	\
	(void)__tmp;			\
})

#endif /* _LEGO_TYPECHECK_H_ */

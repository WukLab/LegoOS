/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * Macros for dealing with constants.
 */

#ifndef _LEGO_CONST_H_
#define _LEGO_CONST_H_

/*
 * Some constant macros are used in both assembler and
 * C code. Therefore we cannot annotate them always with
 * 'UL' and other type specifiers unilaterally. We use
 * the following macros to deal with this.
 *
 * Similarly, _AT() will cast an expression with a type in C, but
 * leave it unchanged in asm.
 */

#ifdef __ASSEMBLY__
#define _AC(X,Y)	X
#define _AT(T,X)	X
#else
#define __AC(X,Y)	(X##Y)
#define _AC(X,Y)	__AC(X,Y)
#define _AT(T,X)	((T)(X))
#endif

#define _BITUL(x)	(_AC(1,UL) << (x))
#define _BITULL(x)	(_AC(1,ULL) << (x))

#endif /* _LEGO_CONST_H_ */

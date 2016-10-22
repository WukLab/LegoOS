/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */

#ifndef _DISOS_STDDEF_H_
#define _DISOS_STDDEF_H_

#include <disos/compiler.h>

#undef  NULL
#define NULL ((void *)0)

enum {
	false	= 0,
	true	= 1
};

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER)	__compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)
#endif

/**
 * offsetofend(TYPE, MEMBER)
 *
 * @TYPE: The type of the structure
 * @MEMBER: The member within the structure to get the end offset of
 */
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof(((TYPE *)0)->MEMBER))

#endif /* _DISOS_STDDEF_H_ */

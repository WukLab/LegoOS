/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */

#ifndef _DISOS_COMPILER_H_
#define _DISOS_COMPILER_H_

#ifndef __GNUC__
#error Please use GCC
#endif

#define GCC_VERSION	(__GNUC__ * 10000	\
			+ __GNUC_MINOR__ * 100	\
			+ __GNUC_PATCHLEVEL__)

#endif /* _DISOS_COMPILER_H_ */

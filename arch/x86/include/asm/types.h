/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_TYPES_H_
#define _ASM_X86_TYPES_H_

#ifdef CONFIG_X86_64
#define __BITS_PER_LONG         64
#else
#define __BITS_PER_LONG         32
#endif

#define __BITS_PER_LONG_LONG    64

#ifndef __ASSEMBLY__

/*
 * 64 bit architectures use "unsigned long" size_t.
 * 32 bit architectures use "unsigned int" size_t,
 */
#ifdef CONFIG_X86_64
typedef unsigned long		size_t;
typedef long			ssize_t;
#else
typedef unsigned int		size_t;
typedef int			ssize_t;
#endif

typedef signed char		s8;
typedef unsigned char		u8;

typedef signed short		s16;
typedef unsigned short		u16;

typedef signed int		s32;
typedef unsigned int		u32;

typedef signed long long	s64;
typedef unsigned long long	u64;

typedef signed char		__s8;
typedef unsigned char		__u8;

typedef signed short		__s16;
typedef unsigned short		__u16;

typedef signed int		__s32;
typedef unsigned int		__u32;

typedef signed long long	__s64;
typedef unsigned long long	__u64;

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_TYPES_H_ */

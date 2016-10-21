/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
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

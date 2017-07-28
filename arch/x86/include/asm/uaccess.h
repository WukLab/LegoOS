/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * User-space memory access functions
 *
 * BIT FAT NOTE:
 * All code here can ONLY be used in processor component code.
 * Because memory component does not have user-program running.
 *
 * Memory component has its own set of functions to manipulate
 * user virtual memory pages, in managers/memory/include/vm.h
 */

#ifndef _ASM_X86_UACCESS_H_
#define _ASM_X86_UACCESS_H_

#include <lego/kernel.h>
#include <lego/extable.h>
#include <lego/compiler.h>
#include <asm/current.h>

#define VERIFY_READ	0
#define VERIFY_WRITE	1

/*
 * The fs value determines whether argument validity checking should be
 * performed or not.  If get_fs() == USER_DS, checking is performed, with
 * get_fs() == KERNEL_DS, checking is bypassed.
 *
 * For historical reasons, these macros are grossly misnamed.
 */

#define MAKE_MM_SEG(s)	((mm_segment_t) { (s) })

#define KERNEL_DS	MAKE_MM_SEG(-1UL)
#define USER_DS 	MAKE_MM_SEG(TASK_SIZE_MAX)

#define get_ds()	(KERNEL_DS)
#define get_fs()	(current->thread.addr_limit)
#define set_fs(x)	(current->thread.addr_limit = (x))

#define segment_eq(a, b)	((a).seg == (b).seg)

#define user_addr_max()		(current->thread.addr_limit.seg)
#define __addr_ok(addr) \
	((unsigned long __force)(addr) < user_addr_max())

/*
 * Test whether a block of memory is a valid user space address.
 * Returns 0 if the range is valid, nonzero otherwise.
 */
static inline bool
__chk_range_not_ok(unsigned long addr, unsigned long size, unsigned long limit)
{
	/*
	 * If we have used "sizeof()" for the size,
	 * we know it won't overflow the limit (but
	 * it might overflow the 'addr', so it's
	 * important to subtract the size from the
	 * limit, not add it to the address).
	 */
	if (__builtin_constant_p(size))
		return unlikely(addr > limit - size);

	/* Arbitrary sizes? Be careful about overflow */
	addr += size;
	if (unlikely(addr < size))
		return true;
	return unlikely(addr > limit);
}

#define __range_not_ok(addr, size, limit)				\
({									\
	__chk_user_ptr(addr);						\
	__chk_range_not_ok((unsigned long __force)(addr), size, limit); \
})

/**
 * access_ok: - Checks if a user space pointer is valid
 * @type: Type of access: %VERIFY_READ or %VERIFY_WRITE.  Note that
 *        %VERIFY_WRITE is a superset of %VERIFY_READ - if it is safe
 *        to write to a block, it is always safe to read from it.
 * @addr: User space pointer to start of block to check
 * @size: Size of block to check
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * Checks if a pointer to a block of memory in user space is valid.
 *
 * Returns true (nonzero) if the memory block may be valid, false (zero)
 * if it is definitely invalid.
 *
 * Note that, depending on architecture, this function probably just
 * checks that the pointer is in the user space range - after calling
 * this function, memory access functions may still return -EFAULT.
 */
#define access_ok(type, addr, size) \
	likely(!__range_not_ok(addr, size, user_addr_max()))


#ifdef CONFIG_HARDENED_USERCOPY
void __check_object_size(const void *ptr, unsigned long n, bool to_user);
static __always_inline void check_object_size(const void *ptr, unsigned long n,
					      bool to_user)
{
	if (!__builtin_constant_p(n))
		__check_object_size(ptr, n, to_user);
}
#else
static inline void check_object_size(const void *ptr, unsigned long n,
				     bool to_user)
{ }
#endif

/* Handles exceptions in both to and from, but doesn't do access_ok */
__must_check unsigned long
copy_user_enhanced_fast_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_unrolled(void *to, const void *from, unsigned len);

static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned len)
{
/*
 * FIXME:
 * Originally, there are three versions of usercopy.
 * All in lib/uaccess.S. We are just using the fastest verion
 * because 1) our E5-v3 supports, 2) we don't have alternatives
 */
	return copy_user_enhanced_fast_string(to, from , len);
}

/* FIXME: this hack is definitely wrong -AK */
struct __large_struct { unsigned long buf[100]; };
#define __m(x) (*(struct __large_struct __user *)(x))

#define __get_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
	asm volatile("\n"						\
		     "1:	mov"itype" %2,%"rtype"1\n"		\
		     "2:\n"						\
		     ".section .fixup,\"ax\"\n"				\
		     "3:	mov %3,%0\n"				\
		     "	xor"itype" %"rtype"1,%"rtype"1\n"		\
		     "	jmp 2b\n"					\
		     ".previous\n"					\
		     _ASM_EXTABLE(1b, 3b)				\
		     : "=r" (err), ltype(x)				\
		     : "m" (__m(addr)), "i" (errret), "0" (err))

/*
 * Tell gcc we read from memory instead of writing: this is because
 * we do not write to any memory gcc knows about, so there are no
 * aliasing issues.
 */
#define __put_user_asm(x, addr, err, itype, rtype, ltype, errret)	\
	asm volatile("\n"						\
		     "1:	mov"itype" %"rtype"1,%2\n"		\
		     "2:\n"						\
		     ".section .fixup,\"ax\"\n"				\
		     "3:	mov %3,%0\n"				\
		     "	jmp 2b\n"					\
		     ".previous\n"					\
		     _ASM_EXTABLE(1b, 3b)				\
		     : "=r"(err)					\
		     : ltype(x), "m" (__m(addr)), "i" (errret), "0" (err))

static __always_inline __must_check
int __copy_from_user(void *dst, const void * __user src, unsigned size)
{
	int ret = 0;

	check_object_size(dst, size, false);
	if (!__builtin_constant_p(size))
		return copy_user_generic(dst, (__force void *)src, size);
	switch (size) {
	case 1:
		__get_user_asm(*(u8 *)dst, (u8 __user *)src,
			      ret, "b", "b", "=q", 1);
		return ret;
	case 2:
		__get_user_asm(*(u16 *)dst, (u16 __user *)src,
			      ret, "w", "w", "=r", 2);
		return ret;
	case 4:
		__get_user_asm(*(u32 *)dst, (u32 __user *)src,
			      ret, "l", "k", "=r", 4);
		return ret;
	case 8:
		__get_user_asm(*(u64 *)dst, (u64 __user *)src,
			      ret, "q", "", "=r", 8);
		return ret;
	case 10:
		__get_user_asm(*(u64 *)dst, (u64 __user *)src,
			       ret, "q", "", "=r", 10);
		if (likely(!ret))
			__get_user_asm(*(u16 *)(8 + (char *)dst),
				       (u16 __user *)(8 + (char __user *)src),
				       ret, "w", "w", "=r", 2);
		return ret;
	case 16:
		__get_user_asm(*(u64 *)dst, (u64 __user *)src,
			       ret, "q", "", "=r", 16);
		if (likely(!ret))
			__get_user_asm(*(u64 *)(8 + (char *)dst),
				       (u64 __user *)(8 + (char __user *)src),
				       ret, "q", "", "=r", 8);
		return ret;
	default:
		return copy_user_generic(dst, (__force void *)src, size);
	}
}

static __always_inline __must_check
int __copy_to_user(void __user *dst, const void *src, unsigned size)
{
	int ret = 0;

	check_object_size(src, size, true);
	if (!__builtin_constant_p(size))
		return copy_user_generic((__force void *)dst, src, size);
	switch (size) {
	case 1:
		__put_user_asm(*(u8 *)src, (u8 __user *)dst,
			      ret, "b", "b", "iq", 1);
		return ret;
	case 2:
		__put_user_asm(*(u16 *)src, (u16 __user *)dst,
			      ret, "w", "w", "ir", 2);
		return ret;
	case 4:
		__put_user_asm(*(u32 *)src, (u32 __user *)dst,
			      ret, "l", "k", "ir", 4);
		return ret;
	case 8:
		__put_user_asm(*(u64 *)src, (u64 __user *)dst,
			      ret, "q", "", "er", 8);
		return ret;
	case 10:
		__put_user_asm(*(u64 *)src, (u64 __user *)dst,
			       ret, "q", "", "er", 10);
		if (likely(!ret)) {
			asm("":::"memory");
			__put_user_asm(4[(u16 *)src], 4 + (u16 __user *)dst,
				       ret, "w", "w", "ir", 2);
		}
		return ret;
	case 16:
		__put_user_asm(*(u64 *)src, (u64 __user *)dst,
			       ret, "q", "", "er", 16);
		if (likely(!ret)) {
			asm("":::"memory");
			__put_user_asm(1[(u64 *)src], 1 + (u64 __user *)dst,
				       ret, "q", "", "er", 8);
		}
		return ret;
	default:
		return copy_user_generic((__force void *)dst, src, size);
	}
}

static __always_inline __must_check
int __copy_in_user(void __user *dst, const void __user *src, unsigned size)
{
	int ret = 0;

	if (!__builtin_constant_p(size))
		return copy_user_generic((__force void *)dst,
					 (__force void *)src, size);
	switch (size) {
	case 1: {
		u8 tmp;
		__get_user_asm(tmp, (u8 __user *)src,
			       ret, "b", "b", "=q", 1);
		if (likely(!ret))
			__put_user_asm(tmp, (u8 __user *)dst,
				       ret, "b", "b", "iq", 1);
		return ret;
	}
	case 2: {
		u16 tmp;
		__get_user_asm(tmp, (u16 __user *)src,
			       ret, "w", "w", "=r", 2);
		if (likely(!ret))
			__put_user_asm(tmp, (u16 __user *)dst,
				       ret, "w", "w", "ir", 2);
		return ret;
	}

	case 4: {
		u32 tmp;
		__get_user_asm(tmp, (u32 __user *)src,
			       ret, "l", "k", "=r", 4);
		if (likely(!ret))
			__put_user_asm(tmp, (u32 __user *)dst,
				       ret, "l", "k", "ir", 4);
		return ret;
	}
	case 8: {
		u64 tmp;
		__get_user_asm(tmp, (u64 __user *)src,
			       ret, "q", "", "=r", 8);
		if (likely(!ret))
			__put_user_asm(tmp, (u64 __user *)dst,
				       ret, "q", "", "er", 8);
		return ret;
	}
	default:
		return copy_user_generic((__force void *)dst,
					 (__force void *)src, size);
	}
}

/*
 * This is a type: either unsigned long, if the argument fits into
 * that type, or otherwise unsigned long long.
 */
#define __inttype(x) \
__typeof__(__builtin_choose_expr(sizeof(x) > sizeof(0UL), 0ULL, 0UL))

/*
 * These are the main single-value transfer routines.  They automatically
 * use the right size if we just have the right pointer type.
 *
 * This gets kind of ugly. We want to return _two_ values in "get_user()"
 * and yet we don't want to do any pointers, because that is too much
 * of a performance impact. Thus we have a few rather ugly macros here,
 * and hide all the ugliness from the user.
 *
 * The "__xxx" versions of the user access functions are versions that
 * do not verify the address space, that must have been done previously
 * with a separate "access_ok()" call (this is used when we do multiple
 * accesses to the same area of user memory).
 */

extern int __get_user_1(void);
extern int __get_user_2(void);
extern int __get_user_4(void);
extern int __get_user_8(void);
extern int __get_user_bad(void);

/**
 * get_user: - Get a simple variable from user space.
 * @x:   Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */
/*
 * Careful: we have to cast the result to the type of the pointer
 * for sign reasons.
 *
 * The use of _ASM_DX as the register specifier is a bit of a
 * simplification, as gcc only cares about it as the starting point
 * and not size: for a 64-bit value it will use %ecx:%edx on 32 bits
 * (%ecx being the next register in gcc's x86 register sequence), and
 * %rdx on 64 bits.
 *
 * Clang/LLVM cares about the size of the register, but still wants
 * the base register for something that ends up being a pair.
 */
#define get_user(x, ptr)						\
({									\
	int __ret_gu;							\
	register __inttype(*(ptr)) __val_gu asm("%"_ASM_DX);		\
	register void *__sp asm(_ASM_SP);				\
	asm volatile("call __get_user_%P4"				\
		     : "=a" (__ret_gu), "=r" (__val_gu), "+r" (__sp)	\
		     : "0" (ptr), "i" (sizeof(*(ptr))));		\
	(x) = (__force __typeof__(*(ptr))) __val_gu;			\
	__builtin_expect(__ret_gu, 0);					\
})

extern void __put_user_bad(void);

/*
 * Strange magic calling convention: pointer in %ecx,
 * value in %eax(:%edx), return value in %eax. clobbers %rbx
 */
extern void __put_user_1(void);
extern void __put_user_2(void);
extern void __put_user_4(void);
extern void __put_user_8(void);

#define __put_user_x(size, x, ptr, __ret_pu)			\
	asm volatile("call __put_user_" #size : "=a" (__ret_pu)	\
		     : "0" ((typeof(*(ptr)))(x)), "c" (ptr) : "ebx")

/**
 * put_user: - Write a simple value into user space.
 * @x:   Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Returns zero on success, or -EFAULT on error.
 */
#define put_user(x, ptr)					\
({								\
	int __ret_pu;						\
	__typeof__(*(ptr)) __pu_val;				\
	__chk_user_ptr(ptr);					\
	__pu_val = x;						\
	switch (sizeof(*(ptr))) {				\
	case 1:							\
		__put_user_x(1, __pu_val, ptr, __ret_pu);	\
		break;						\
	case 2:							\
		__put_user_x(2, __pu_val, ptr, __ret_pu);	\
		break;						\
	case 4:							\
		__put_user_x(4, __pu_val, ptr, __ret_pu);	\
		break;						\
	case 8:							\
		__put_user_x(8, __pu_val, ptr, __ret_pu);	\
		break;						\
	default:						\
		__put_user_x(X, __pu_val, ptr, __ret_pu);	\
		break;						\
	}							\
	__builtin_expect(__ret_pu, 0);				\
})

unsigned long __must_check _copy_from_user(void *to, const void __user *from,
					   unsigned n);
unsigned long __must_check _copy_to_user(void __user *to, const void *from,
					 unsigned n);

extern void __compiletime_error("usercopy buffer size is too small")
__bad_copy_user(void);

static inline void copy_user_overflow(int size, unsigned long count)
{
	WARN(1, "Buffer overflow detected (%d < %lu)!\n", size, count);
}

static __always_inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	int sz = __compiletime_object_size(to);

	if (likely(sz < 0 || sz >= n)) {
		check_object_size(to, n, false);
		n = _copy_from_user(to, from, n);
	} else if (!__builtin_constant_p(n))
		copy_user_overflow(sz, n);
	else
		__bad_copy_user();

	return n;
}

static __always_inline unsigned long __must_check
copy_to_user(void __user *to, const void *from, unsigned long n)
{
	int sz = __compiletime_object_size(from);

	if (likely(sz < 0 || sz >= n)) {
		check_object_size(from, n, true);
		n = _copy_to_user(to, from, n);
	} else if (!__builtin_constant_p(n))
		copy_user_overflow(sz, n);
	else
		__bad_copy_user();

	return n;
}

unsigned long
copy_user_handle_tail(char *to, char *from, unsigned len);

__must_check long strncpy_from_user(char *dst, const char __user *src, long count);
__must_check long strlen_user(const char __user *str);
__must_check long strnlen_user(const char __user *str, long n);

#define __put_user_size(x, ptr, size, retval, errret)			\
do {									\
	retval = 0;							\
	__chk_user_ptr(ptr);						\
	switch (size) {							\
	case 1:								\
		__put_user_asm(x, ptr, retval, "b", "b", "iq", errret);	\
		break;							\
	case 2:								\
		__put_user_asm(x, ptr, retval, "w", "w", "ir", errret);	\
		break;							\
	case 4:								\
		__put_user_asm(x, ptr, retval, "l", "k", "ir", errret);	\
		break;							\
	case 8:								\
		__put_user_asm(x, ptr, retval, "q", "", "er", errret);	\
		break;							\
	default:							\
		__put_user_bad();					\
	}								\
} while (0)

#define __get_user_size(x, ptr, size, retval, errret)			\
do {									\
	retval = 0;							\
	__chk_user_ptr(ptr);						\
	switch (size) {							\
	case 1:								\
		__get_user_asm(x, ptr, retval, "b", "b", "=q", errret);	\
		break;							\
	case 2:								\
		__get_user_asm(x, ptr, retval, "w", "w", "=r", errret);	\
		break;							\
	case 4:								\
		__get_user_asm(x, ptr, retval, "l", "k", "=r", errret);	\
		break;							\
	case 8:								\
		__get_user_asm(x, ptr, retval, "q", "", "=r", errret);	\
		break;							\
	default:							\
		(x) = __get_user_bad();					\
	}								\
} while (0)

#define __get_user_nocheck(x, ptr, size)				\
({									\
	int __gu_err;							\
	__inttype(*(ptr)) __gu_val;					\
	__get_user_size(__gu_val, (ptr), (size), __gu_err, -EFAULT);	\
	(x) = (__force __typeof__(*(ptr)))__gu_val;			\
	__builtin_expect(__gu_err, 0);					\
})

#define __put_user_nocheck(x, ptr, size)			\
({								\
	int __pu_err;						\
	__put_user_size((x), (ptr), (size), __pu_err, -EFAULT);	\
	__builtin_expect(__pu_err, 0);				\
})

/**
 * __get_user: - Get a simple variable from user space, with less checking.
 * @x:   Variable to store result.
 * @ptr: Source address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple variable from user space to kernel
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and the result of
 * dereferencing @ptr must be assignable to @x without a cast.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 * On error, the variable @x is set to zero.
 */

#define __get_user(x, ptr)						\
	__get_user_nocheck((x), (ptr), sizeof(*(ptr)))

/**
 * __put_user: - Write a simple value into user space, with less checking.
 * @x:   Value to copy to user space.
 * @ptr: Destination address, in user space.
 *
 * Context: User context only. This function may sleep if pagefaults are
 *          enabled.
 *
 * This macro copies a single simple value from kernel space to user
 * space.  It supports simple types like char and int, but not larger
 * data types like structures or arrays.
 *
 * @ptr must have pointer-to-simple-variable type, and @x must be assignable
 * to the result of dereferencing @ptr.
 *
 * Caller must check the pointer with access_ok() before calling this
 * function.
 *
 * Returns zero on success, or -EFAULT on error.
 */

#define __put_user(x, ptr)						\
	__put_user_nocheck((__typeof__(*(ptr)))(x), (ptr), sizeof(*(ptr)))

#define unsafe_put_user(x, ptr, err_label)					\
do {										\
	int __pu_err;								\
	__put_user_size((x), (ptr), sizeof(*(ptr)), __pu_err, -EFAULT);		\
	if (unlikely(__pu_err)) goto err_label;					\
} while (0)

#define unsafe_get_user(x, ptr, err_label)					\
do {										\
	int __gu_err;								\
	unsigned long __gu_val;							\
	__get_user_size(__gu_val, (ptr), sizeof(*(ptr)), __gu_err, -EFAULT);	\
	(x) = (__typeof__(*(ptr)))__gu_val;					\
	if (unlikely(__gu_err)) goto err_label;					\
} while (0)

#define __get_user_asm_ex(x, addr, itype, rtype, ltype)			\
	asm volatile("1:	mov"itype" %1,%"rtype"0\n"		\
		     "2:\n"						\
		     ".section .fixup,\"ax\"\n"				\
                     "3:xor"itype" %"rtype"0,%"rtype"0\n"		\
		     "  jmp 2b\n"					\
		     ".previous\n"					\
		     _ASM_EXTABLE_EX(1b, 3b)				\
		     : ltype(x) : "m" (__m(addr)))

/*
 * This doesn't do __uaccess_begin/end - the exception handling
 * around it must do that.
 */
#define __get_user_size_ex(x, ptr, size)				\
do {									\
	__chk_user_ptr(ptr);						\
	switch (size) {							\
	case 1:								\
		__get_user_asm_ex(x, ptr, "b", "b", "=q");		\
		break;							\
	case 2:								\
		__get_user_asm_ex(x, ptr, "w", "w", "=r");		\
		break;							\
	case 4:								\
		__get_user_asm_ex(x, ptr, "l", "k", "=r");		\
		break;							\
	case 8:								\
		__get_user_asm_ex(x, ptr, "q", "",  "=r");		\
		break;							\
	default:							\
		(x) = __get_user_bad();					\
	}								\
} while (0)

#define __put_user_asm_ex(x, addr, itype, rtype, ltype)			\
	asm volatile("1:	mov"itype" %"rtype"0,%1\n"		\
		     "2:\n"						\
		     _ASM_EXTABLE_EX(1b, 2b)				\
		     : : ltype(x), "m" (__m(addr)))

/*
 * This doesn't do __uaccess_begin/end - the exception handling
 * around it must do that.
 */
#define __put_user_size_ex(x, ptr, size)				\
do {									\
	__chk_user_ptr(ptr);						\
	switch (size) {							\
	case 1:								\
		__put_user_asm_ex(x, ptr, "b", "b", "iq");		\
		break;							\
	case 2:								\
		__put_user_asm_ex(x, ptr, "w", "w", "ir");		\
		break;							\
	case 4:								\
		__put_user_asm_ex(x, ptr, "l", "k", "ir");		\
		break;							\
	case 8:								\
		__put_user_asm_ex(x, ptr, "q", "",  "er");		\
		break;							\
	default:							\
		__put_user_bad();					\
	}								\
} while (0)

/*
 * uaccess_try and catch
 */
#define uaccess_try	do {						\
	current->thread.uaccess_err = 0;				\
	barrier();

#define uaccess_catch(err)						\
	(err) |= (current->thread.uaccess_err ? -EFAULT : 0);		\
} while (0)

/*
 * {get|put}_user_try and catch
 *
 * get_user_try {
 *	get_user_ex(...);
 * } get_user_catch(err)
 */
#define get_user_try		uaccess_try
#define get_user_catch(err)	uaccess_catch(err)

#define get_user_ex(x, ptr)	do {					\
	unsigned long __gue_val;					\
	__get_user_size_ex((__gue_val), (ptr), (sizeof(*(ptr))));	\
	(x) = (__force __typeof__(*(ptr)))__gue_val;			\
} while (0)

#define put_user_try		uaccess_try
#define put_user_catch(err)	uaccess_catch(err)

#define put_user_ex(x, ptr)						\
	__put_user_size_ex((__typeof__(*(ptr)))(x), (ptr), sizeof(*(ptr)))

unsigned long __must_check clear_user(void __user *mem, unsigned long len);
unsigned long __must_check __clear_user(void __user *mem, unsigned long len);

#endif /* _ASM_X86_UACCESS_H_ */

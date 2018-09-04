/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_COMPILER_H_
#define _LEGO_COMPILER_H_

#include <asm/cache.h>
#include <lego/types.h>
#include <lego/linkage.h>

#ifndef __GNUC__
# error Please use GCC
#endif

#ifdef __CHECKER__
# define __user		__attribute__((noderef, address_space(1)))
# define __kernel	__attribute__((address_space(0)))
# define __safe		__attribute__((safe))
# define __force	__attribute__((force))
# define __nocast	__attribute__((nocast))
# define __iomem	__attribute__((noderef, address_space(2)))
# define __must_hold(x)	__attribute__((context(x,1,1)))
# define __acquires(x)	__attribute__((context(x,0,1)))
# define __releases(x)	__attribute__((context(x,1,0)))
# define __acquire(x)	__context__(x,1)
# define __release(x)	__context__(x,-1)
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
#else
# define __user
# define __kernel
# define __safe
# define __force
# define __nocast
# define __iomem
# define __chk_user_ptr(x) (void)0
# define __chk_io_ptr(x) (void)0
# define __builtin_warning(x, y...) (1)
# define __must_hold(x)
# define __acquires(x)
# define __releases(x)
# define __acquire(x) (void)0
# define __release(x) (void)0
# define __cond_lock(x,c) (c)
# define __percpu
#endif

#define GCC_VERSION				\
(						\
	__GNUC__		* 10000	+	\
	__GNUC_MINOR__		* 100	+	\
	__GNUC_PATCHLEVEL__			\
)

/*
 * Barrier for Compiler.
 * Prevent GCC from reordering memory accesses.
 */
#define barrier()		asm volatile("": : :"memory")

/*
 * Sections.
 * Work with your ld script.
 */
#define __section(S)		__attribute__((__section__(#S)))
#define __init			__section(.init.text)
#define __initdata		__section(.init.data)
#define __read_mostly		__section(.data..read_mostly)
#define __init_task_data	__section(.data..init_task)
#define __lockfunc		__section(.spinlock.text)

/*
 * ____cacheline_aligned just make the marked data cache line aligned
 * __cacheline_aligned will also put the data into a specific section
 */
#define ____cacheline_aligned					\
	__attribute__((__aligned__(L1_CACHE_BYTES)))

#define __cacheline_aligned					\
	__attribute__((__aligned__(L1_CACHE_BYTES),		\
	__section__(".data..cacheline_aligned")))

#define __cacheline_aligned_in_smp	__cacheline_aligned

#ifdef CONFIG_SMP
#define ____cacheline_aligned_in_smp	____cacheline_aligned
#else
#define ____cacheline_aligned_in_smp
#endif

/*
 * When used with Link Time Optimization, gcc can optimize away C functions or
 * variables which are referenced only from assembly code.  __visible tells the
 * optimizer that something else uses this function or variable, thus preventing
 * this.
 */
#define __visible		__attribute__((externally_visible))

#define __user
#define __kernel
#define __force
#define __iomem
#define __rcu

/*
 * Generic GCC Function and Variable attribute.
 * Please consult GCC manual for more details.
 */
#define __weak			__attribute__((__weak__))
#define __pure			__attribute__((__pure__))
#define __packed		__attribute__((__packed__))
#define __noreturn		__attribute__((__noreturn__))
#define __unused		__attribute__((__unused__))
#define __maybe_unused		__attribute__((__unused__))
#define __always_unused		__attribute__((__unused__))
#define __attribute_const	__attribute__((__const__))
#define __aligned(x)            __attribute__((aligned(x)))
#define __scanf(a, b)		__attribute__((format(scanf, a, b)))
#define __printf(a, b)		__attribute__((format(printf, a, b)))
#define __alias(symbol)		__attribute__((alias(#symbol)))
#define __attribute_const__	__attribute__((__const__))

#define __same_type(a, b)	__builtin_types_compatible_p(typeof(a), typeof(b))
#define __constant(exp)		__builtin_constant_p(exp)
#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

/*
 * Rather then using noinline to prevent stack consumption, use
 * noinline_for_stack instead.  For documentation reasons.
 */
#define __noinline		__attribute__((__noinline__))
#define noinline		__attribute__((__noinline__))
#define __noinline_for_stack	__noinline

#define __always_inline		inline __attribute__((always_inline))

#if GCC_VERSION < 30300
# define __used			__attribute__((__unused__))
#else
# define __used			__attribute__((__used__))
#endif

#if GCC_VERSION >= 30400
# define __must_check		__attribute__((warn_unused_result))
# define __malloc		__attribute__((__malloc__))
#else
# define __must_check
# define __malloc
#endif

#if GCC_VERSION >= 40000

#if GCC_VERSION >= 40100 && GCC_VERSION < 40600
# define __compiletime_object_size(obj) __builtin_object_size(obj, 0)
#else
# define __compiletime_object_size(obj) -1
#endif

/*
 * Tell gcc if a function is cold. The compiler will assume any path
 * directly leading to the call is unlikely.
 */
#if GCC_VERSION >= 40300
# define __cold				__attribute__((__cold__))
# define __compiletime_warning(message)	__attribute__((warning(message)))
# define __compiletime_error(message)	__attribute__((error(message)))
#else
# define __cold
# define __compiletime_warning(message)
# define __compiletime_error(message)
#endif

/*
 * Mark a position in code as unreachable.  This can be used to
 * suppress control flow warnings after asm blocks that transfer
 * control elsewhere.
 */
#if GCC_VERSION >= 40500
# define unreachable()		__builtin_unreachable()
#else
# define unreachable()		do { } while(1)
#endif

/*
 * When used with Link Time Optimization, gcc can optimize away C functions or
 * variables which are referenced only from assembly code.  __visible tells the
 * optimizer that something else uses this function or variable, thus preventing
 * this.
 */
#if GCC_VERSION >= 40600
# define __visible	__attribute__((externally_visible))
#else
# define __visible
#endif

/*
 * GCC 'asm goto' miscompiles certain code sequences:
 * http://gcc.gnu.org/bugzilla/show_bug.cgi?id=58670
 * (asm goto is automatically volatile - the naming reflects this.)
 */
#define asm_volatile_goto(x...)		\
	do {				\
		asm goto(x);		\
		asm ("");		\
	} while (0)

#define __compiler_offsetof(a, b)	__builtin_offsetof(a, b)

#if GCC_VERSION >= 40400
#define __HAVE_BUILTIN_BSWAP32__
#define __HAVE_BUILTIN_BSWAP64__
#endif
#if GCC_VERSION >= 40800
#define __HAVE_BUILTIN_BSWAP16__
#endif

#endif	/* GCC_VERSION >= 40000 */

#if GCC_VERSION >= 40900 && !defined(__CHECKER__)
/*
 * __assume_aligned(n, k): Tell the optimizer that the returned
 * pointer can be assumed to be k modulo n. The second argument is
 * optional (default 0), so we use a variadic macro to make the
 * shorthand.
 *
 * Beware: Do not apply this to functions which may return
 * ERR_PTRs. Also, it is probably unwise to apply it to functions
 * returning extra information in the low bits (but in that case the
 * compiler should see some alignment anyway, when the return value is
 * massaged by 'flags = ptr & 3; ptr &= ~3;').
 */
#define __assume_aligned(a, ...) __attribute__((__assume_aligned__(a, ## __VA_ARGS__)))
#else
#define __assume_aligned(a, ...)
#endif

/*
 * Prevent the compiler from merging or refetching reads or writes. The
 * compiler is also forbidden from reordering successive instances of
 * READ_ONCE, WRITE_ONCE and ACCESS_ONCE (see below), but only when the
 * compiler is aware of some particular ordering.  One way to make the
 * compiler aware of ordering is to put the two invocations of READ_ONCE,
 * WRITE_ONCE or ACCESS_ONCE() in different C statements.
 *
 * In contrast to ACCESS_ONCE these two macros will also work on aggregate
 * data types like structs or unions. If the size of the accessed data
 * type exceeds the word size of the machine (e.g., 32 bits or 64 bits)
 * READ_ONCE() and WRITE_ONCE()  will fall back to memcpy and print a
 * compile-time warning.
 *
 * Their two major use cases are: (1) Mediating communication between
 * process-level code and irq/NMI handlers, all running on the same CPU,
 * and (2) Ensuring that the compiler does not  fold, spindle, or otherwise
 * mutilate accesses that either do not require ordering or that interact
 * with an explicit memory barrier or atomic instruction that provides the
 * required ordering.
 *
 * If possible use READ_ONCE()/WRITE_ONCE() instead.
 */

#ifndef __ASSEMBLY__

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8 *)res = *(volatile __u8 *)p; break;
	case 2: *(__u16 *)res = *(volatile __u16 *)p; break;
	case 4: *(__u32 *)res = *(volatile __u32 *)p; break;
	case 8: *(__u64 *)res = *(volatile __u64 *)p; break;
	default:
		barrier();
		__builtin_memcpy((void *)res, (const void *)p, size);
		barrier();
	}
}

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile __u8 *)p = *(__u8 *)res; break;
	case 2: *(volatile __u16 *)p = *(__u16 *)res; break;
	case 4: *(volatile __u32 *)p = *(__u32 *)res; break;
	case 8: *(volatile __u64 *)p = *(__u64 *)res; break;
	default:
		barrier();
		__builtin_memcpy((void *)p, (const void *)res, size);
		barrier();
	}
}

#define READ_ONCE(x)						\
({								\
	union {							\
		typeof(x) __val;				\
		char __c[1];					\
	} __u;							\
	__read_once_size(&(x), __u.__c, sizeof(x));		\
	__u.__val;						\
})

#define WRITE_ONCE(x, val)					\
({								\
	union {							\
		typeof(x) __val;				\
		char __c[1];					\
	} __u = { .__val = (val) };				\
	__write_once_size(&(x), __u.__c, sizeof(x));		\
	__u.__val;						\
})

#define ACCESS_ONCE(x)						\
({								\
	__maybe_unused typeof(x) __var = (__force typeof(x)) 0;	\
	*(volatile typeof(x) *)&(x);				\
})

#endif /* __ASSEMBLY__ */

#define __compiletime_error_fallback(condition)			\
	do {							\
		((void)sizeof(char[1 - 2 * condition]));	\
	} while (0)

#define __compiletime_assert(condition, msg, prefix, suffix)	\
	do {							\
		bool __cond = !(condition);			\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (__cond)					\
			prefix ## suffix();			\
		__compiletime_error_fallback(__cond);		\
	} while (0)

#define _compiletime_assert(condition, msg, prefix, suffix)	\
	__compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg)			\
	_compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)

/* Is this type a native word size -- useful for atomic operations */
#ifndef __native_word
# define __native_word(t) (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
#endif

#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")

/*
 * A trick to suppress uninitialized variable warning without generating any
 * code
 */
#define uninitialized_var(x) x = x

#ifndef __attribute_const__
# define __attribute_const__    /* unimplemented */
#endif

/*
 * This macro obfuscates arithmetic on a variable address so that gcc
 * shouldn't recognize the original var, and make assumptions about it.
 *
 * This is needed because the C standard makes it undefined to do
 * pointer arithmetic on "objects" outside their boundaries and the
 * gcc optimizers assume this is the case. In particular they
 * assume such arithmetic does not wrap.
 *
 * A miscompilation has been observed because of this on PPC.
 * To work around it we hide the relationship of the pointer and the object
 * using this macro.
 *
 * Versions of the ppc64 compiler before 4.1 had a bug where use of
 * RELOC_HIDE could trash r30. The bug can be worked around by changing
 * the inline assembly constraint from =g to =r, in this particular
 * case either is valid.
 */
#define RELOC_HIDE(ptr, off)						\
({									\
	unsigned long __ptr;						\
	__asm__ ("" : "=r"(__ptr) : "0"(ptr));				\
	(typeof(ptr)) (__ptr + (off));					\
})

/*
 * Some barriers for x86:
 */

#define smp_store_release(p, v)						\
do {									\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#ifdef CONFIG_SMP
#define smp_store_mb(var, value)	do { (void)xchg(&var, value); } while (0)
#else
#define smp_store_mb(var, value)	do { WRITE_ONCE(var, value); barrier(); } while (0)
#endif

/**
 * lockless_dereference() - safely load a pointer for later dereference
 * @p: The pointer to load
 *
 * Similar to rcu_dereference(), but for situations where the pointed-to
 * object's lifetime is managed by something other than RCU.  That
 * "something other" might be reference counting or simple immortality.
 */
#define lockless_dereference(p) \
({ \
	typeof(p) _________p1 = READ_ONCE(p); \
	(_________p1); \
})

#endif /* _LEGO_COMPILER_H_ */

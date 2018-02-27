/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PERCPU_H_
#define _LEGO_PERCPU_H_

#include <lego/cpumask.h>
#include <lego/compiler.h>

#include <asm/percpu.h>

/*
 * Percpu allocator can serve percpu allocations before slab is
 * initialized which allows slab to depend on the percpu allocator.
 * The following two parameters decide how much resource to
 * preallocate for this.  Keep PERCPU_DYNAMIC_RESERVE equal to or
 * larger than PERCPU_DYNAMIC_EARLY_SIZE.
 */
#define PERCPU_DYNAMIC_EARLY_SLOTS	128
#define PERCPU_DYNAMIC_EARLY_SIZE	(12 << 10)

#ifdef CONFIG_SMP

/*
 * per_cpu_offset() is the offset that has to be added to a
 * percpu variable to get to the instance for a certain processor.
 */
extern unsigned long __per_cpu_offset[NR_CPUS];
#define per_cpu_offset(x) (__per_cpu_offset[x])

/*
 * Determine the offset for the currently active processor.
 * An arch may define __my_cpu_offset to provide a more effective
 * means of obtaining the offset to the per cpu variables of the
 * current processor.
 */
#ifndef __my_cpu_offset
#define __my_cpu_offset	per_cpu_offset(raw_smp_processor_id())
#endif
#define my_cpu_offset __my_cpu_offset

#ifdef CONFIG_HAVE_SETUP_PER_CPU_AREA
extern void setup_per_cpu_areas(void);
#endif

#endif	/* SMP */

#ifdef CONFIG_SMP
#define PER_CPU_BASE_SECTION ".data..percpu"
#else
#define PER_CPU_BASE_SECTION ".data"
#endif

#define raw_cpu_generic_read(pcp)					\
({									\
	*raw_cpu_ptr(&(pcp));						\
})

#define raw_cpu_generic_to_op(pcp, val, op)				\
do {									\
	*raw_cpu_ptr(&(pcp)) op val;					\
} while (0)

#define raw_cpu_generic_add_return(pcp, val)				\
({									\
	typeof(&(pcp)) __p = raw_cpu_ptr(&(pcp));			\
									\
	*__p += val;							\
	*__p;								\
})

#define raw_cpu_generic_xchg(pcp, nval)					\
({									\
	typeof(&(pcp)) __p = raw_cpu_ptr(&(pcp));			\
	typeof(pcp) __ret;						\
	__ret = *__p;							\
	*__p = nval;							\
	__ret;								\
})

#define raw_cpu_generic_cmpxchg(pcp, oval, nval)			\
({									\
	typeof(&(pcp)) __p = raw_cpu_ptr(&(pcp));			\
	typeof(pcp) __ret;						\
	__ret = *__p;							\
	if (__ret == (oval))						\
		*__p = nval;						\
	__ret;								\
})

#define raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
({									\
	typeof(&(pcp1)) __p1 = raw_cpu_ptr(&(pcp1));			\
	typeof(&(pcp2)) __p2 = raw_cpu_ptr(&(pcp2));			\
	int __ret = 0;							\
	if (*__p1 == (oval1) && *__p2  == (oval2)) {			\
		*__p1 = nval1;						\
		*__p2 = nval2;						\
		__ret = 1;						\
	}								\
	(__ret);							\
})

#define this_cpu_generic_read(pcp)					\
({									\
	typeof(pcp) __ret;						\
	preempt_disable_notrace();					\
	__ret = raw_cpu_generic_read(pcp);				\
	preempt_enable_notrace();					\
	__ret;								\
})

#define this_cpu_generic_to_op(pcp, val, op)				\
do {									\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	raw_cpu_generic_to_op(pcp, val, op);				\
	raw_local_irq_restore(__flags);					\
} while (0)


#define this_cpu_generic_add_return(pcp, val)				\
({									\
	typeof(pcp) __ret;						\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_add_return(pcp, val);			\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})

#define this_cpu_generic_xchg(pcp, nval)				\
({									\
	typeof(pcp) __ret;						\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_xchg(pcp, nval);			\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})

#define this_cpu_generic_cmpxchg(pcp, oval, nval)			\
({									\
	typeof(pcp) __ret;						\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_cmpxchg(pcp, oval, nval);		\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})

#define this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)	\
({									\
	int __ret;							\
	unsigned long __flags;						\
	raw_local_irq_save(__flags);					\
	__ret = raw_cpu_generic_cmpxchg_double(pcp1, pcp2,		\
			oval1, oval2, nval1, nval2);			\
	raw_local_irq_restore(__flags);					\
	__ret;								\
})

#ifndef raw_cpu_read_1
#define raw_cpu_read_1(pcp)		raw_cpu_generic_read(pcp)
#endif
#ifndef raw_cpu_read_2
#define raw_cpu_read_2(pcp)		raw_cpu_generic_read(pcp)
#endif
#ifndef raw_cpu_read_4
#define raw_cpu_read_4(pcp)		raw_cpu_generic_read(pcp)
#endif
#ifndef raw_cpu_read_8
#define raw_cpu_read_8(pcp)		raw_cpu_generic_read(pcp)
#endif

#ifndef raw_cpu_write_1
#define raw_cpu_write_1(pcp, val)	raw_cpu_generic_to_op(pcp, val, =)
#endif
#ifndef raw_cpu_write_2
#define raw_cpu_write_2(pcp, val)	raw_cpu_generic_to_op(pcp, val, =)
#endif
#ifndef raw_cpu_write_4
#define raw_cpu_write_4(pcp, val)	raw_cpu_generic_to_op(pcp, val, =)
#endif
#ifndef raw_cpu_write_8
#define raw_cpu_write_8(pcp, val)	raw_cpu_generic_to_op(pcp, val, =)
#endif

#ifndef raw_cpu_add_1
#define raw_cpu_add_1(pcp, val)		raw_cpu_generic_to_op(pcp, val, +=)
#endif
#ifndef raw_cpu_add_2
#define raw_cpu_add_2(pcp, val)		raw_cpu_generic_to_op(pcp, val, +=)
#endif
#ifndef raw_cpu_add_4
#define raw_cpu_add_4(pcp, val)		raw_cpu_generic_to_op(pcp, val, +=)
#endif
#ifndef raw_cpu_add_8
#define raw_cpu_add_8(pcp, val)		raw_cpu_generic_to_op(pcp, val, +=)
#endif

#ifndef raw_cpu_and_1
#define raw_cpu_and_1(pcp, val)		raw_cpu_generic_to_op(pcp, val, &=)
#endif
#ifndef raw_cpu_and_2
#define raw_cpu_and_2(pcp, val)		raw_cpu_generic_to_op(pcp, val, &=)
#endif
#ifndef raw_cpu_and_4
#define raw_cpu_and_4(pcp, val)		raw_cpu_generic_to_op(pcp, val, &=)
#endif
#ifndef raw_cpu_and_8
#define raw_cpu_and_8(pcp, val)		raw_cpu_generic_to_op(pcp, val, &=)
#endif

#ifndef raw_cpu_or_1
#define raw_cpu_or_1(pcp, val)		raw_cpu_generic_to_op(pcp, val, |=)
#endif
#ifndef raw_cpu_or_2
#define raw_cpu_or_2(pcp, val)		raw_cpu_generic_to_op(pcp, val, |=)
#endif
#ifndef raw_cpu_or_4
#define raw_cpu_or_4(pcp, val)		raw_cpu_generic_to_op(pcp, val, |=)
#endif
#ifndef raw_cpu_or_8
#define raw_cpu_or_8(pcp, val)		raw_cpu_generic_to_op(pcp, val, |=)
#endif

#ifndef raw_cpu_add_return_1
#define raw_cpu_add_return_1(pcp, val)	raw_cpu_generic_add_return(pcp, val)
#endif
#ifndef raw_cpu_add_return_2
#define raw_cpu_add_return_2(pcp, val)	raw_cpu_generic_add_return(pcp, val)
#endif
#ifndef raw_cpu_add_return_4
#define raw_cpu_add_return_4(pcp, val)	raw_cpu_generic_add_return(pcp, val)
#endif
#ifndef raw_cpu_add_return_8
#define raw_cpu_add_return_8(pcp, val)	raw_cpu_generic_add_return(pcp, val)
#endif

#ifndef raw_cpu_xchg_1
#define raw_cpu_xchg_1(pcp, nval)	raw_cpu_generic_xchg(pcp, nval)
#endif
#ifndef raw_cpu_xchg_2
#define raw_cpu_xchg_2(pcp, nval)	raw_cpu_generic_xchg(pcp, nval)
#endif
#ifndef raw_cpu_xchg_4
#define raw_cpu_xchg_4(pcp, nval)	raw_cpu_generic_xchg(pcp, nval)
#endif
#ifndef raw_cpu_xchg_8
#define raw_cpu_xchg_8(pcp, nval)	raw_cpu_generic_xchg(pcp, nval)
#endif

#ifndef raw_cpu_cmpxchg_1
#define raw_cpu_cmpxchg_1(pcp, oval, nval) \
	raw_cpu_generic_cmpxchg(pcp, oval, nval)
#endif
#ifndef raw_cpu_cmpxchg_2
#define raw_cpu_cmpxchg_2(pcp, oval, nval) \
	raw_cpu_generic_cmpxchg(pcp, oval, nval)
#endif
#ifndef raw_cpu_cmpxchg_4
#define raw_cpu_cmpxchg_4(pcp, oval, nval) \
	raw_cpu_generic_cmpxchg(pcp, oval, nval)
#endif
#ifndef raw_cpu_cmpxchg_8
#define raw_cpu_cmpxchg_8(pcp, oval, nval) \
	raw_cpu_generic_cmpxchg(pcp, oval, nval)
#endif

#ifndef raw_cpu_cmpxchg_double_1
#define raw_cpu_cmpxchg_double_1(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#endif
#ifndef raw_cpu_cmpxchg_double_2
#define raw_cpu_cmpxchg_double_2(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#endif
#ifndef raw_cpu_cmpxchg_double_4
#define raw_cpu_cmpxchg_double_4(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#endif
#ifndef raw_cpu_cmpxchg_double_8
#define raw_cpu_cmpxchg_double_8(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	raw_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#endif

#ifndef this_cpu_read_1
#define this_cpu_read_1(pcp)		this_cpu_generic_read(pcp)
#endif
#ifndef this_cpu_read_2
#define this_cpu_read_2(pcp)		this_cpu_generic_read(pcp)
#endif
#ifndef this_cpu_read_4
#define this_cpu_read_4(pcp)		this_cpu_generic_read(pcp)
#endif
#ifndef this_cpu_read_8
#define this_cpu_read_8(pcp)		this_cpu_generic_read(pcp)
#endif

#ifndef this_cpu_write_1
#define this_cpu_write_1(pcp, val)	this_cpu_generic_to_op(pcp, val, =)
#endif
#ifndef this_cpu_write_2
#define this_cpu_write_2(pcp, val)	this_cpu_generic_to_op(pcp, val, =)
#endif
#ifndef this_cpu_write_4
#define this_cpu_write_4(pcp, val)	this_cpu_generic_to_op(pcp, val, =)
#endif
#ifndef this_cpu_write_8
#define this_cpu_write_8(pcp, val)	this_cpu_generic_to_op(pcp, val, =)
#endif

#ifndef this_cpu_add_1
#define this_cpu_add_1(pcp, val)	this_cpu_generic_to_op(pcp, val, +=)
#endif
#ifndef this_cpu_add_2
#define this_cpu_add_2(pcp, val)	this_cpu_generic_to_op(pcp, val, +=)
#endif
#ifndef this_cpu_add_4
#define this_cpu_add_4(pcp, val)	this_cpu_generic_to_op(pcp, val, +=)
#endif
#ifndef this_cpu_add_8
#define this_cpu_add_8(pcp, val)	this_cpu_generic_to_op(pcp, val, +=)
#endif

#ifndef this_cpu_and_1
#define this_cpu_and_1(pcp, val)	this_cpu_generic_to_op(pcp, val, &=)
#endif
#ifndef this_cpu_and_2
#define this_cpu_and_2(pcp, val)	this_cpu_generic_to_op(pcp, val, &=)
#endif
#ifndef this_cpu_and_4
#define this_cpu_and_4(pcp, val)	this_cpu_generic_to_op(pcp, val, &=)
#endif
#ifndef this_cpu_and_8
#define this_cpu_and_8(pcp, val)	this_cpu_generic_to_op(pcp, val, &=)
#endif

#ifndef this_cpu_or_1
#define this_cpu_or_1(pcp, val)		this_cpu_generic_to_op(pcp, val, |=)
#endif
#ifndef this_cpu_or_2
#define this_cpu_or_2(pcp, val)		this_cpu_generic_to_op(pcp, val, |=)
#endif
#ifndef this_cpu_or_4
#define this_cpu_or_4(pcp, val)		this_cpu_generic_to_op(pcp, val, |=)
#endif
#ifndef this_cpu_or_8
#define this_cpu_or_8(pcp, val)		this_cpu_generic_to_op(pcp, val, |=)
#endif

#ifndef this_cpu_add_return_1
#define this_cpu_add_return_1(pcp, val)	this_cpu_generic_add_return(pcp, val)
#endif
#ifndef this_cpu_add_return_2
#define this_cpu_add_return_2(pcp, val)	this_cpu_generic_add_return(pcp, val)
#endif
#ifndef this_cpu_add_return_4
#define this_cpu_add_return_4(pcp, val)	this_cpu_generic_add_return(pcp, val)
#endif
#ifndef this_cpu_add_return_8
#define this_cpu_add_return_8(pcp, val)	this_cpu_generic_add_return(pcp, val)
#endif

#ifndef this_cpu_xchg_1
#define this_cpu_xchg_1(pcp, nval)	this_cpu_generic_xchg(pcp, nval)
#endif
#ifndef this_cpu_xchg_2
#define this_cpu_xchg_2(pcp, nval)	this_cpu_generic_xchg(pcp, nval)
#endif
#ifndef this_cpu_xchg_4
#define this_cpu_xchg_4(pcp, nval)	this_cpu_generic_xchg(pcp, nval)
#endif
#ifndef this_cpu_xchg_8
#define this_cpu_xchg_8(pcp, nval)	this_cpu_generic_xchg(pcp, nval)
#endif

#ifndef this_cpu_cmpxchg_1
#define this_cpu_cmpxchg_1(pcp, oval, nval) \
	this_cpu_generic_cmpxchg(pcp, oval, nval)
#endif
#ifndef this_cpu_cmpxchg_2
#define this_cpu_cmpxchg_2(pcp, oval, nval) \
	this_cpu_generic_cmpxchg(pcp, oval, nval)
#endif
#ifndef this_cpu_cmpxchg_4
#define this_cpu_cmpxchg_4(pcp, oval, nval) \
	this_cpu_generic_cmpxchg(pcp, oval, nval)
#endif
#ifndef this_cpu_cmpxchg_8
#define this_cpu_cmpxchg_8(pcp, oval, nval) \
	this_cpu_generic_cmpxchg(pcp, oval, nval)
#endif

#ifndef this_cpu_cmpxchg_double_1
#define this_cpu_cmpxchg_double_1(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#endif
#ifndef this_cpu_cmpxchg_double_2
#define this_cpu_cmpxchg_double_2(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#endif
#ifndef this_cpu_cmpxchg_double_4
#define this_cpu_cmpxchg_double_4(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#endif
#ifndef this_cpu_cmpxchg_double_8
#define this_cpu_cmpxchg_double_8(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	this_cpu_generic_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2)
#endif

#ifdef CONFIG_SMP
#define PER_CPU_SHARED_ALIGNED_SECTION	"..shared_aligned"
#define PER_CPU_ALIGNED_SECTION		"..shared_aligned"
#define PER_CPU_FIRST_SECTION		"..first"
#else
#define PER_CPU_SHARED_ALIGNED_SECTION	""
#define PER_CPU_ALIGNED_SECTION		"..shared_aligned"
#define PER_CPU_FIRST_SECTION		""
#endif

/*
 * Base implementations of per-CPU variable declarations and definitions, where
 * the section in which the variable is to be placed is provided by the
 * 'sec' argument.  This may be used to affect the parameters governing the
 * variable's storage.
 *
 * NOTE!  The sections for the DECLARE and for the DEFINE must match, lest
 * linkage errors occur due the compiler generating the wrong code to access
 * that section.
 */
#define __PCPU_ATTRS(sec)						\
	__percpu __attribute__((section(PER_CPU_BASE_SECTION sec)))

#define __PCPU_DUMMY_ATTRS						\
	__attribute__((section(".discard"), unused))

#define DEFINE_PER_CPU_SECTION(type, name, sec)				\
	__PCPU_ATTRS(sec) __typeof__(type) name

#define DECLARE_PER_CPU_SECTION(type, name, sec)			\
	extern __PCPU_ATTRS(sec) __percpu __typeof__(type) name

/*
 * Variant on the per-CPU variable declaration/definition theme used for
 * ordinary per-CPU variables.
 */
#define DECLARE_PER_CPU(type, name)					\
	DECLARE_PER_CPU_SECTION(type, name, "")

#define DEFINE_PER_CPU(type, name)					\
	DEFINE_PER_CPU_SECTION(type, name, "")

/*
 * Declaration/definition used for per-CPU variables that must come first in
 * the set of variables.
 */
#define DECLARE_PER_CPU_FIRST(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)

#define DEFINE_PER_CPU_FIRST(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)

/*
 * Declaration/definition used for per-CPU variables that must be cacheline
 * aligned under SMP conditions so that, whilst a particular instance of the
 * data corresponds to a particular CPU, inefficiencies due to direct access by
 * other CPUs are reduced by preventing the data from unnecessarily spanning
 * cachelines.
 *
 * An example of this would be statistical data, where each CPU's set of data
 * is updated by that CPU alone, but the data from across all CPUs is collated
 * by a CPU processing a read from a proc file.
 */
#define DECLARE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp

#define DEFINE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp

#define DECLARE_PER_CPU_ALIGNED(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned

#define DEFINE_PER_CPU_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned

/*
 * Declaration/definition used for per-CPU variables that must be page aligned.
 */
#define DECLARE_PER_CPU_PAGE_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)

#define DEFINE_PER_CPU_PAGE_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)

/*
 * Declaration/definition used for per-CPU variables that must be read mostly.
 */
#define DECLARE_PER_CPU_READ_MOSTLY(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..read_mostly")

#define DEFINE_PER_CPU_READ_MOSTLY(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..read_mostly")

/*
 * Accessors and operations.
 */
#ifndef __ASSEMBLY__

/*
 * __verify_pcpu_ptr() verifies @ptr is a percpu pointer without evaluating
 * @ptr and is invoked once before a percpu area is accessed by all
 * accessors and operations.  This is performed in the generic part of
 * percpu and arch overrides don't need to worry about it; however, if an
 * arch wants to implement an arch-specific percpu accessor or operation,
 * it may use __verify_pcpu_ptr() to verify the parameters.
 *
 * + 0 is required in order to convert the pointer type from a
 * potential array type to a pointer to a single item of the array.
 */
#define __verify_pcpu_ptr(ptr)						\
do {									\
	const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;	\
	(void)__vpp_verify;						\
} while (0)

#ifdef CONFIG_SMP

/*
 * Add an offset to a pointer but keep the pointer as-is.  Use RELOC_HIDE()
 * to prevent the compiler from making incorrect assumptions about the
 * pointer value.  The weird cast keeps both GCC and sparse happy.
 */
#define SHIFT_PERCPU_PTR(__p, __offset)					\
	RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset))

#define per_cpu_ptr(ptr, cpu)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)));			\
})

#define raw_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	arch_raw_cpu_ptr(ptr);						\
})

#ifdef CONFIG_DEBUG_PREEMPT
#define this_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR(ptr, my_cpu_offset);				\
})
#else
#define this_cpu_ptr(ptr) raw_cpu_ptr(ptr)
#endif

#else	/* !CONFIG_SMP */

#define VERIFY_PERCPU_PTR(__p)						\
({									\
	__verify_pcpu_ptr(__p);						\
	(typeof(*(__p)) __kernel __force *)(__p);			\
})

#define per_cpu_ptr(ptr, cpu)	({ (void)(cpu); VERIFY_PERCPU_PTR(ptr); })
#define raw_cpu_ptr(ptr)	per_cpu_ptr(ptr, 0)
#define this_cpu_ptr(ptr)	raw_cpu_ptr(ptr)

#endif	/* CONFIG_SMP */

#define per_cpu(var, cpu)	(*per_cpu_ptr(&(var), cpu))

/*
 * Must be an lvalue. Since @var must be a simple identifier,
 * we force a syntax error here if it isn't.
 */
#define get_cpu_var(var)						\
(*({									\
	preempt_disable();						\
	this_cpu_ptr(&var);						\
}))

/*
 * The weird & is necessary because sparse considers (void)(var) to be
 * a direct dereference of percpu variable (var).
 */
#define put_cpu_var(var)						\
do {									\
	(void)&(var);							\
	preempt_enable();						\
} while (0)

#define get_cpu_ptr(var)						\
({									\
	preempt_disable();						\
	this_cpu_ptr(var);						\
})

#define put_cpu_ptr(var)						\
do {									\
	(void)(var);							\
	preempt_enable();						\
} while (0)

/*
 * Branching function to split up a function into a set of functions that
 * are called for different scalar sizes of the objects handled.
 */

extern void __bad_size_call_parameter(void);

#ifdef CONFIG_DEBUG_PREEMPT
extern void __this_cpu_preempt_check(const char *op);
#else
static inline void __this_cpu_preempt_check(const char *op) { }
#endif

#define __pcpu_size_call_return(stem, variable)				\
({									\
	typeof(variable) pscr_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr_ret__ = stem##1(variable); break;			\
	case 2: pscr_ret__ = stem##2(variable); break;			\
	case 4: pscr_ret__ = stem##4(variable); break;			\
	case 8: pscr_ret__ = stem##8(variable); break;			\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pscr_ret__;							\
})

#define __pcpu_size_call_return2(stem, variable, ...)			\
({									\
	typeof(variable) pscr2_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr2_ret__ = stem##1(variable, __VA_ARGS__); break;	\
	case 2: pscr2_ret__ = stem##2(variable, __VA_ARGS__); break;	\
	case 4: pscr2_ret__ = stem##4(variable, __VA_ARGS__); break;	\
	case 8: pscr2_ret__ = stem##8(variable, __VA_ARGS__); break;	\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pscr2_ret__;							\
})

/*
 * Special handling for cmpxchg_double.  cmpxchg_double is passed two
 * percpu variables.  The first has to be aligned to a double word
 * boundary and the second has to follow directly thereafter.
 * We enforce this on all architectures even if they don't support
 * a double cmpxchg instruction, since it's a cheap requirement, and it
 * avoids breaking the requirement for architectures with the instruction.
 */
#define __pcpu_double_call_return_bool(stem, pcp1, pcp2, ...)		\
({									\
	bool pdcrb_ret__;						\
	__verify_pcpu_ptr(&(pcp1));					\
	BUILD_BUG_ON(sizeof(pcp1) != sizeof(pcp2));			\
	VM_BUG_ON((unsigned long)(&(pcp1)) % (2 * sizeof(pcp1)));	\
	VM_BUG_ON((unsigned long)(&(pcp2)) !=				\
		  (unsigned long)(&(pcp1)) + sizeof(pcp1));		\
	switch(sizeof(pcp1)) {						\
	case 1: pdcrb_ret__ = stem##1(pcp1, pcp2, __VA_ARGS__); break;	\
	case 2: pdcrb_ret__ = stem##2(pcp1, pcp2, __VA_ARGS__); break;	\
	case 4: pdcrb_ret__ = stem##4(pcp1, pcp2, __VA_ARGS__); break;	\
	case 8: pdcrb_ret__ = stem##8(pcp1, pcp2, __VA_ARGS__); break;	\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pdcrb_ret__;							\
})

#define __pcpu_size_call(stem, variable, ...)				\
do {									\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
		case 1: stem##1(variable, __VA_ARGS__);break;		\
		case 2: stem##2(variable, __VA_ARGS__);break;		\
		case 4: stem##4(variable, __VA_ARGS__);break;		\
		case 8: stem##8(variable, __VA_ARGS__);break;		\
		default: 						\
			__bad_size_call_parameter();break;		\
	}								\
} while (0)

/*
 * this_cpu operations (C) 2008-2013 Christoph Lameter <cl@linux.com>
 *
 * Optimized manipulation for memory allocated through the per cpu
 * allocator or for addresses of per cpu variables.
 *
 * These operation guarantee exclusivity of access for other operations
 * on the *same* processor. The assumption is that per cpu data is only
 * accessed by a single processor instance (the current one).
 *
 * The arch code can provide optimized implementation by defining macros
 * for certain scalar sizes. F.e. provide this_cpu_add_2() to provide per
 * cpu atomic operations for 2 byte sized RMW actions. If arch code does
 * not provide operations for a scalar size then the fallback in the
 * generic code will be used.
 *
 * cmpxchg_double replaces two adjacent scalars at once.  The first two
 * parameters are per cpu variables which have to be of the same size.  A
 * truth value is returned to indicate success or failure (since a double
 * register result is difficult to handle).  There is very limited hardware
 * support for these operations, so only certain sizes may work.
 */

/*
 * Operations for contexts where we do not want to do any checks for
 * preemptions.  Unless strictly necessary, always use [__]this_cpu_*()
 * instead.
 *
 * If there is no other protection through preempt disable and/or disabling
 * interupts then one of these RMW operations can show unexpected behavior
 * because the execution thread was rescheduled on another processor or an
 * interrupt occurred and the same percpu variable was modified from the
 * interrupt context.
 */
#define raw_cpu_read(pcp)		__pcpu_size_call_return(raw_cpu_read_, pcp)
#define raw_cpu_write(pcp, val)		__pcpu_size_call(raw_cpu_write_, pcp, val)
#define raw_cpu_add(pcp, val)		__pcpu_size_call(raw_cpu_add_, pcp, val)
#define raw_cpu_and(pcp, val)		__pcpu_size_call(raw_cpu_and_, pcp, val)
#define raw_cpu_or(pcp, val)		__pcpu_size_call(raw_cpu_or_, pcp, val)
#define raw_cpu_add_return(pcp, val)	__pcpu_size_call_return2(raw_cpu_add_return_, pcp, val)
#define raw_cpu_xchg(pcp, nval)		__pcpu_size_call_return2(raw_cpu_xchg_, pcp, nval)
#define raw_cpu_cmpxchg(pcp, oval, nval) \
	__pcpu_size_call_return2(raw_cpu_cmpxchg_, pcp, oval, nval)
#define raw_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	__pcpu_double_call_return_bool(raw_cpu_cmpxchg_double_, pcp1, pcp2, oval1, oval2, nval1, nval2)

#define raw_cpu_sub(pcp, val)		raw_cpu_add(pcp, -(val))
#define raw_cpu_inc(pcp)		raw_cpu_add(pcp, 1)
#define raw_cpu_dec(pcp)		raw_cpu_sub(pcp, 1)
#define raw_cpu_sub_return(pcp, val)	raw_cpu_add_return(pcp, -(typeof(pcp))(val))
#define raw_cpu_inc_return(pcp)		raw_cpu_add_return(pcp, 1)
#define raw_cpu_dec_return(pcp)		raw_cpu_add_return(pcp, -1)

/*
 * Operations for contexts that are safe from preemption/interrupts.  These
 * operations verify that preemption is disabled.
 */
#define __this_cpu_read(pcp)						\
({									\
	__this_cpu_preempt_check("read");				\
	raw_cpu_read(pcp);						\
})

#define __this_cpu_write(pcp, val)					\
({									\
	__this_cpu_preempt_check("write");				\
	raw_cpu_write(pcp, val);					\
})

#define __this_cpu_add(pcp, val)					\
({									\
	__this_cpu_preempt_check("add");				\
	raw_cpu_add(pcp, val);						\
})

#define __this_cpu_and(pcp, val)					\
({									\
	__this_cpu_preempt_check("and");				\
	raw_cpu_and(pcp, val);						\
})

#define __this_cpu_or(pcp, val)						\
({									\
	__this_cpu_preempt_check("or");					\
	raw_cpu_or(pcp, val);						\
})

#define __this_cpu_add_return(pcp, val)					\
({									\
	__this_cpu_preempt_check("add_return");				\
	raw_cpu_add_return(pcp, val);					\
})

#define __this_cpu_xchg(pcp, nval)					\
({									\
	__this_cpu_preempt_check("xchg");				\
	raw_cpu_xchg(pcp, nval);					\
})

#define __this_cpu_cmpxchg(pcp, oval, nval)				\
({									\
	__this_cpu_preempt_check("cmpxchg");				\
	raw_cpu_cmpxchg(pcp, oval, nval);				\
})

#define __this_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
({	__this_cpu_preempt_check("cmpxchg_double");			\
	raw_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2);	\
})

#define __this_cpu_sub(pcp, val)	__this_cpu_add(pcp, -(typeof(pcp))(val))
#define __this_cpu_inc(pcp)		__this_cpu_add(pcp, 1)
#define __this_cpu_dec(pcp)		__this_cpu_sub(pcp, 1)
#define __this_cpu_sub_return(pcp, val)	__this_cpu_add_return(pcp, -(typeof(pcp))(val))
#define __this_cpu_inc_return(pcp)	__this_cpu_add_return(pcp, 1)
#define __this_cpu_dec_return(pcp)	__this_cpu_add_return(pcp, -1)

/*
 * Operations with implied preemption/interrupt protection.  These
 * operations can be used without worrying about preemption or interrupt.
 */
#define this_cpu_read(pcp)		__pcpu_size_call_return(this_cpu_read_, pcp)
#define this_cpu_write(pcp, val)	__pcpu_size_call(this_cpu_write_, pcp, val)
#define this_cpu_add(pcp, val)		__pcpu_size_call(this_cpu_add_, pcp, val)
#define this_cpu_and(pcp, val)		__pcpu_size_call(this_cpu_and_, pcp, val)
#define this_cpu_or(pcp, val)		__pcpu_size_call(this_cpu_or_, pcp, val)
#define this_cpu_add_return(pcp, val)	__pcpu_size_call_return2(this_cpu_add_return_, pcp, val)
#define this_cpu_xchg(pcp, nval)	__pcpu_size_call_return2(this_cpu_xchg_, pcp, nval)
#define this_cpu_cmpxchg(pcp, oval, nval) \
	__pcpu_size_call_return2(this_cpu_cmpxchg_, pcp, oval, nval)
#define this_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	__pcpu_double_call_return_bool(this_cpu_cmpxchg_double_, pcp1, pcp2, oval1, oval2, nval1, nval2)

#define this_cpu_sub(pcp, val)		this_cpu_add(pcp, -(typeof(pcp))(val))
#define this_cpu_inc(pcp)		this_cpu_add(pcp, 1)
#define this_cpu_dec(pcp)		this_cpu_sub(pcp, 1)
#define this_cpu_sub_return(pcp, val)	this_cpu_add_return(pcp, -(typeof(pcp))(val))
#define this_cpu_inc_return(pcp)	this_cpu_add_return(pcp, 1)
#define this_cpu_dec_return(pcp)	this_cpu_add_return(pcp, -1)

#endif /* __ASSEMBLY__ */

/* We can use this directly for local CPU (faster). */
DECLARE_PER_CPU_READ_MOSTLY(unsigned long, this_cpu_off);

/* minimum unit size, also is the maximum supported allocation size */
#define PCPU_MIN_UNIT_SIZE		PFN_ALIGN(32 << 10)

/*
 * PERCPU_DYNAMIC_RESERVE indicates the amount of free area to piggy
 * back on the first chunk for dynamic percpu allocation if arch is
 * manually allocating and mapping it for faster access (as a part of
 * large page mapping for example).
 *
 * The following values give between one and two pages of free space
 * after typical minimal boot (2-way SMP, single disk and NIC) with
 * both defconfig and a distro config on x86_64 and 32.  More
 * intelligent way to determine this would be nice.
 */
#if BITS_PER_LONG > 32
#define PERCPU_DYNAMIC_RESERVE		(28 << 10)
#else
#define PERCPU_DYNAMIC_RESERVE		(20 << 10)
#endif

extern void *pcpu_base_addr;
extern const unsigned long *pcpu_unit_offsets;

struct pcpu_group_info {
	int			nr_units;	/* aligned # of units */
	unsigned long		base_offset;	/* base address offset */
	unsigned int		*cpu_map;	/* unit->cpu map, empty
						 * entries contain NR_CPUS */
};

struct pcpu_alloc_info {
	size_t			static_size;
	size_t			reserved_size;
	size_t			dyn_size;
	size_t			unit_size;
	size_t			atom_size;
	size_t			alloc_size;
	size_t			__ai_size;	/* internal, don't use */
	int			nr_groups;	/* 0 if grouping unnecessary */
	struct pcpu_group_info	groups[];
};

typedef void *(*pcpu_fc_alloc_fn_t)(unsigned int cpu, size_t size,
				     size_t align);
typedef void (*pcpu_fc_free_fn_t)(void *ptr, size_t size);
typedef int (pcpu_fc_cpu_distance_fn_t)(unsigned int from, unsigned int to);

extern int __init pcpu_embed_first_chunk(size_t reserved_size, size_t dyn_size,
				size_t atom_size,
				pcpu_fc_cpu_distance_fn_t cpu_distance_fn,
				pcpu_fc_alloc_fn_t alloc_fn,
				pcpu_fc_free_fn_t free_fn);

void __init setup_per_cpu_areas(void);

void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp);
void __percpu *__alloc_percpu(size_t size, size_t align);
void free_percpu(void __percpu *ptr);

#define alloc_percpu_gfp(type, gfp)					\
	(typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type),	\
						__alignof__(type), gfp)
#define alloc_percpu(type)						\
	(typeof(type) __percpu *)__alloc_percpu(sizeof(type),		\
						__alignof__(type))

#endif /* _LEGO_PERCPU_H_ */

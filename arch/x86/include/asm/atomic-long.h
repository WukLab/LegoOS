/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_ATOMIC_LONG_H_
#define _ASM_X86_ATOMIC_LONG_H_

/*
 * Suppport for atomic_long_t
 *
 * Casts for parameters are avoided for existing atomic functions in order to
 * avoid issues with cast-as-lval under gcc 4.x and other limitations that the
 * macros of a platform may have.
 */

#if BITS_PER_LONG == 64

typedef atomic64_t atomic_long_t;

#define ATOMIC_LONG_INIT(i)	ATOMIC64_INIT(i)
#define ATOMIC_LONG_PFX(x)	atomic64 ## x

#else

typedef atomic_t atomic_long_t;

#define ATOMIC_LONG_INIT(i)	ATOMIC_INIT(i)
#define ATOMIC_LONG_PFX(x)	atomic ## x

#endif

#define ATOMIC_LONG_READ_OP(mo)						\
static inline long atomic_long_read##mo(const atomic_long_t *l)		\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_read##mo)(v);			\
}
ATOMIC_LONG_READ_OP()

#undef ATOMIC_LONG_READ_OP

#define ATOMIC_LONG_SET_OP(mo)						\
static inline void atomic_long_set##mo(atomic_long_t *l, long i)	\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	ATOMIC_LONG_PFX(_set##mo)(v, i);				\
}
ATOMIC_LONG_SET_OP()

#undef ATOMIC_LONG_SET_OP

#define ATOMIC_LONG_ADD_SUB_OP(op, mo)					\
static inline long							\
atomic_long_##op##_return##mo(long i, atomic_long_t *l)			\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_##op##_return##mo)(i, v);		\
}
ATOMIC_LONG_ADD_SUB_OP(add,)
ATOMIC_LONG_ADD_SUB_OP(sub,)

#undef ATOMIC_LONG_ADD_SUB_OP

#define atomic_long_cmpxchg(l, old, new) \
	(ATOMIC_LONG_PFX(_cmpxchg)((ATOMIC_LONG_PFX(_t) *)(l), (old), (new)))

#define atomic_long_xchg(v, new) \
	(ATOMIC_LONG_PFX(_xchg)((ATOMIC_LONG_PFX(_t) *)(v), (new)))

static __always_inline void atomic_long_inc(atomic_long_t *l)
{
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;

	ATOMIC_LONG_PFX(_inc)(v);
}

static __always_inline void atomic_long_dec(atomic_long_t *l)
{
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;

	ATOMIC_LONG_PFX(_dec)(v);
}

#define ATOMIC_LONG_FETCH_OP(op, mo)					\
static inline long							\
atomic_long_fetch_##op##mo(long i, atomic_long_t *l)			\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_fetch_##op##mo)(i, v);		\
}

ATOMIC_LONG_FETCH_OP(add, )
ATOMIC_LONG_FETCH_OP(sub, )
ATOMIC_LONG_FETCH_OP(and, )
ATOMIC_LONG_FETCH_OP(andnot, )
ATOMIC_LONG_FETCH_OP(or, )
ATOMIC_LONG_FETCH_OP(xor, )

#undef ATOMIC_LONG_FETCH_OP

#define ATOMIC_LONG_FETCH_INC_DEC_OP(op, mo)					\
static inline long							\
atomic_long_fetch_##op##mo(atomic_long_t *l)				\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_fetch_##op##mo)(v);		\
}

ATOMIC_LONG_FETCH_INC_DEC_OP(inc,)
ATOMIC_LONG_FETCH_INC_DEC_OP(dec,)

#undef ATOMIC_LONG_FETCH_INC_DEC_OP

#define ATOMIC_LONG_OP(op)						\
static __always_inline void						\
atomic_long_##op(long i, atomic_long_t *l)				\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	ATOMIC_LONG_PFX(_##op)(i, v);					\
}

ATOMIC_LONG_OP(add)
ATOMIC_LONG_OP(sub)
ATOMIC_LONG_OP(and)
ATOMIC_LONG_OP(andnot)
ATOMIC_LONG_OP(or)
ATOMIC_LONG_OP(xor)

#undef ATOMIC_LONG_OP

static inline int atomic_long_sub_and_test(long i, atomic_long_t *l)
{
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;

	return ATOMIC_LONG_PFX(_sub_and_test)(i, v);
}

static inline int atomic_long_dec_and_test(atomic_long_t *l)
{
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;

	return ATOMIC_LONG_PFX(_dec_and_test)(v);
}

static inline int atomic_long_inc_and_test(atomic_long_t *l)
{
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;

	return ATOMIC_LONG_PFX(_inc_and_test)(v);
}

static inline int atomic_long_add_negative(long i, atomic_long_t *l)
{
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;

	return ATOMIC_LONG_PFX(_add_negative)(i, v);
}

#define ATOMIC_LONG_INC_DEC_OP(op, mo)					\
static inline long							\
atomic_long_##op##_return##mo(atomic_long_t *l)				\
{									\
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;		\
									\
	return (long)ATOMIC_LONG_PFX(_##op##_return##mo)(v);		\
}
ATOMIC_LONG_INC_DEC_OP(inc,)
ATOMIC_LONG_INC_DEC_OP(dec,)

#undef ATOMIC_LONG_INC_DEC_OP

static inline long atomic_long_add_unless(atomic_long_t *l, long a, long u)
{
	ATOMIC_LONG_PFX(_t) *v = (ATOMIC_LONG_PFX(_t) *)l;

	return (long)ATOMIC_LONG_PFX(_add_unless)(v, a, u);
}

#define atomic_long_inc_not_zero(l) \
	ATOMIC_LONG_PFX(_inc_not_zero)((ATOMIC_LONG_PFX(_t) *)(l))

#endif /* _ASM_X86_ATOMIC_LONG_H_ */

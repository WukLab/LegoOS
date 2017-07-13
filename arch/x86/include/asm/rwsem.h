#ifndef _ASM_X86_RWSEM_H_
#define _ASM_X86_RWSEM_H_

#ifndef _LEGO_RWSEM_H_
# error "Please include <lego/rwsem.h>"
#endif

#include <asm/asm.h>

/*
 * The bias values and the counter type limits the number of
 * potential readers/writers to 32767 for 32 bits and 2147483647
 * for 64 bits.
 */

#ifdef CONFIG_X86_64
# define RWSEM_ACTIVE_MASK		0xffffffffL
#else
# define RWSEM_ACTIVE_MASK		0x0000ffffL
#endif

#define RWSEM_UNLOCKED_VALUE		0x00000000L
#define RWSEM_ACTIVE_BIAS		0x00000001L
#define RWSEM_WAITING_BIAS		(-RWSEM_ACTIVE_MASK-1)
#define RWSEM_ACTIVE_READ_BIAS		RWSEM_ACTIVE_BIAS
#define RWSEM_ACTIVE_WRITE_BIAS		(RWSEM_WAITING_BIAS + RWSEM_ACTIVE_BIAS)

/*
 * lock for reading
 */
static inline void __down_read(struct rw_semaphore *sem)
{
}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
static inline bool __down_read_trylock(struct rw_semaphore *sem)
{
	return 1;
}

/*
 * lock for writing
 */
#define ____down_write(sem, slow_path)			\
({							\
	long tmp;					\
	struct rw_semaphore* ret;			\
	register void *__sp asm(_ASM_SP);		\
							\
	asm volatile("# beginning down_write\n\t"	\
		     LOCK_PREFIX "  xadd      %1,(%4)\n\t"	\
		     /* adds 0xffff0001, returns the old value */ \
		     "  test " __ASM_SEL(%w1,%k1) "," __ASM_SEL(%w1,%k1) "\n\t" \
		     /* was the active mask 0 before? */\
		     "  jz        1f\n"			\
		     "  call " slow_path "\n"		\
		     "1:\n"				\
		     "# ending down_write"		\
		     : "+m" (sem->count), "=d" (tmp), "=a" (ret), "+r" (__sp) \
		     : "a" (sem), "1" (RWSEM_ACTIVE_WRITE_BIAS) \
		     : "memory", "cc");			\
	ret;						\
})

static inline void __down_write(struct rw_semaphore *sem)
{
}

static inline int __down_write_killable(struct rw_semaphore *sem)
{
	return 0;
}

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
static inline bool __down_write_trylock(struct rw_semaphore *sem)
{
	return 1;
}

/*
 * unlock after reading
 */
static inline void __up_read(struct rw_semaphore *sem)
{
}

/*
 * unlock after writing
 */
static inline void __up_write(struct rw_semaphore *sem)
{
}

#endif /* _ASM_X86_RWSEM_H_ */

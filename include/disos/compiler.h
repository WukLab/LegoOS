/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */

#ifndef _DISOS_COMPILER_H_
#define _DISOS_COMPILER_H_

#ifndef __GNUC__
# error Please use GCC
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
 * When used with Link Time Optimization, gcc can optimize away C functions or
 * variables which are referenced only from assembly code.  __visible tells the
 * optimizer that something else uses this function or variable, thus preventing
 * this.
 */
#define __visible		__attribute__((externally_visible))


#endif /* _DISOS_COMPILER_H_ */

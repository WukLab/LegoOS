/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Processor Extended Cache Zerofill
 * Optimize anonymous pcache access for 99%
 */

#ifndef _LEGO_PROCESSOR_ZEROFILL_H_
#define _LEGO_PROCESSOR_ZEROFILL_H_

#include <lego/sched.h>

/*
 * Internal data structures
 */

struct zerofill_work {
	unsigned long		flags;
	unsigned long		fault_user_vaddr;
	unsigned long		fault_flags;
	unsigned int		pid;
	unsigned int		tgid;
	unsigned int		memory_nid;
} ____cacheline_aligned;

enum zerofill_work_flags {
	ZEROFILL_WORK_used,
	ZEROFILL_WORK_flush,

	NR_ZEROFILL_WORK_FLAGS,
};

#define TEST_ZEROFILL_WORK_FLAFGS(uname, lname)					\
static inline int Zerofill##uname(const struct zerofill_work *p)		\
{										\
	return test_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);		\
}

#define SET_ZEROFILL_WORK_FLAFGS(uname, lname)					\
static inline void SetZerofill##uname(struct zerofill_work *p)			\
{										\
	set_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);			\
}

#define CLEAR_ZEROFILL_WORK_FLAFGS(uname, lname)				\
static inline void ClearZerofill##uname(struct zerofill_work *p)		\
{										\
	clear_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);			\
}

#define __SET_ZEROFILL_WORK_FLAFGS(uname, lname)				\
static inline void __SetZerofill##uname(struct zerofill_work *p)		\
{										\
	__set_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);			\
}

#define __CLEAR_ZEROFILL_WORK_FLAFGS(uname, lname)				\
static inline void __ClearZerofill##uname(struct zerofill_work *p)		\
{										\
	__clear_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);			\
}

#define TEST_SET_FLAFGS(uname, lname)						\
static inline int TestSetZerofill##uname(struct zerofill_work *p)		\
{										\
	return test_and_set_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);	\
}

#define TEST_CLEAR_FLAFGS(uname, lname)						\
static inline int TestClearZerofill##uname(struct zerofill_work *p)		\
{										\
	return test_and_clear_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);	\
}

#define __TEST_SET_FLAFGS(uname, lname)						\
static inline int __TestSetZerofill##uname(struct zerofill_work *p)		\
{										\
	return __test_and_set_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);	\
}

#define __TEST_CLEAR_FLAFGS(uname, lname)					\
static inline int __TestClearZerofill##uname(struct zerofill_work *p)		\
{										\
	return __test_and_clear_bit(ZEROFILL_WORK_##lname, (void *)&p->flags);	\
}

#define ZEROFILL_WORK_FLAGS(uname, lname)					\
	TEST_ZEROFILL_WORK_FLAFGS(uname, lname)					\
	SET_ZEROFILL_WORK_FLAFGS(uname, lname)					\
	CLEAR_ZEROFILL_WORK_FLAFGS(uname, lname)				\
	__SET_ZEROFILL_WORK_FLAFGS(uname, lname)				\
	__CLEAR_ZEROFILL_WORK_FLAFGS(uname, lname)				\
	TEST_SET_FLAFGS(uname, lname)						\
	TEST_CLEAR_FLAFGS(uname, lname)						\
	__TEST_SET_FLAFGS(uname, lname)						\
	__TEST_CLEAR_FLAFGS(uname, lname)

ZEROFILL_WORK_FLAGS(Used, used)
ZEROFILL_WORK_FLAGS(Flush, flush)

/*
 * Public APIs
 */
#ifdef CONFIG_PCACHE_ZEROFILL
int zerofill_set_range(struct task_struct *p,
		       unsigned long __user start, unsigned long len);
int zerofill_clear_range(struct task_struct *p,
			 unsigned long __user start, unsigned long len);
#else
static inline int zerofill_set_range(struct task_struct *p,
		       unsigned long __user start, unsigned long len) { return 0; }
static inline int zerofill_clear_range(struct task_struct *p,
			 unsigned long __user start, unsigned long len) { return 0; }

#endif

#ifdef CONFIG_PCACHE_ZEROFILL_NOTIFY_MEMORY
void submit_zerofill_notify_work(struct task_struct *p,
			  unsigned long address, unsigned long flags);

int pcache_zerofill_notify_init(void);
#else
static inline void submit_zerofill_notify_work(struct task_struct *p,
			  unsigned long address, unsigned long flags) { }

static inline int pcache_zerofill_notify_init(void) { return 0; };
#endif

#endif /* _LEGO_PROCESSOR_ZEROFILL_H_ */

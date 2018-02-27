/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SYSCALLS_H_
#define _ASM_X86_SYSCALLS_H_

#include <lego/ptrace.h>
#include <lego/linkage.h>

#ifdef CONFIG_X86_64
void entry_SYSCALL_64(void);
#endif

#ifdef CONFIG_IA32_EMULATION
void entry_SYSENTER_compat(void);
void __end_entry_SYSENTER_compat(void);
void entry_SYSCALL_compat(void);
void entry_INT80_compat(void);
#endif

typedef asmlinkage long (*sys_call_ptr_t)(unsigned long, unsigned long,
					  unsigned long, unsigned long,
					  unsigned long, unsigned long);

extern const sys_call_ptr_t sys_call_table[];

/*
 * Only the low 32 bits of orig_ax are meaningful, so we return int.
 * This importantly ignores the high bits on 64-bit, so comparisons
 * sign-extend the low 32 bits.
 */
static inline int syscall_get_nr(struct task_struct *task, struct pt_regs *regs)
{
	return regs->orig_ax;
}

static inline void syscall_rollback(struct task_struct *task,
				    struct pt_regs *regs)
{
	regs->ax = regs->orig_ax;
}

static inline long syscall_get_error(struct task_struct *task,
				     struct pt_regs *regs)
{
	unsigned long error = regs->ax;
#ifdef CONFIG_IA32_EMULATION
	/*
	 * TS_COMPAT is set for 32-bit syscall entries and then
	 * remains set until we return to user mode.
	 */
	if (task->thread.status & (TS_COMPAT|TS_I386_REGS_POKED)) {
		/*
		 * Sign-extend the value so (int)-EFOO becomes (long)-EFOO
		 * and will match correctly in comparisons.
		 */
		BUG();
		error = (long) (int) error;
	}
#endif
	return IS_ERR_VALUE(error) ? error : 0;
}

static inline long syscall_get_return_value(struct task_struct *task,
					    struct pt_regs *regs)
{
	return regs->ax;
}

static inline void syscall_set_return_value(struct task_struct *task,
					    struct pt_regs *regs,
					    int error, long val)
{
	regs->ax = (long) error ?: val;
}

static inline void syscall_get_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 unsigned long *args)
{
# ifdef CONFIG_IA32_EMULATION
	if (task->thread.status & TS_COMPAT) {
		BUG();
		switch (i) {
		case 0:
			if (!n--) break;
			*args++ = regs->bx;
		case 1:
			if (!n--) break;
			*args++ = regs->cx;
		case 2:
			if (!n--) break;
			*args++ = regs->dx;
		case 3:
			if (!n--) break;
			*args++ = regs->si;
		case 4:
			if (!n--) break;
			*args++ = regs->di;
		case 5:
			if (!n--) break;
			*args++ = regs->bp;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
	} else
# endif
		switch (i) {
		case 0:
			if (!n--) break;
			*args++ = regs->di;
		case 1:
			if (!n--) break;
			*args++ = regs->si;
		case 2:
			if (!n--) break;
			*args++ = regs->dx;
		case 3:
			if (!n--) break;
			*args++ = regs->r10;
		case 4:
			if (!n--) break;
			*args++ = regs->r8;
		case 5:
			if (!n--) break;
			*args++ = regs->r9;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
}

static inline void syscall_set_arguments(struct task_struct *task,
					 struct pt_regs *regs,
					 unsigned int i, unsigned int n,
					 const unsigned long *args)
{
# ifdef CONFIG_IA32_EMULATION
	if (task->thread.status & TS_COMPAT) {
		BUG();
		switch (i) {
		case 0:
			if (!n--) break;
			regs->bx = *args++;
		case 1:
			if (!n--) break;
			regs->cx = *args++;
		case 2:
			if (!n--) break;
			regs->dx = *args++;
		case 3:
			if (!n--) break;
			regs->si = *args++;
		case 4:
			if (!n--) break;
			regs->di = *args++;
		case 5:
			if (!n--) break;
			regs->bp = *args++;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
	} else
# endif
		switch (i) {
		case 0:
			if (!n--) break;
			regs->di = *args++;
		case 1:
			if (!n--) break;
			regs->si = *args++;
		case 2:
			if (!n--) break;
			regs->dx = *args++;
		case 3:
			if (!n--) break;
			regs->r10 = *args++;
		case 4:
			if (!n--) break;
			regs->r8 = *args++;
		case 5:
			if (!n--) break;
			regs->r9 = *args++;
		case 6:
			if (!n--) break;
		default:
			BUG();
			break;
		}
}

#endif /* _ASM_X86_SYSCALLS_H_ */

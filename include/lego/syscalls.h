/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SYSCALLS_H_
#define _LEGO_SYSCALLS_H_

#include <lego/files.h>
#include <lego/bug.h>
#include <lego/ptrace.h>
#include <lego/rlimit.h>
#include <lego/linkage.h>
#include <lego/compiler.h>
#include <lego/time.h>

#include <asm/syscalls.h>

#define debug_syscall_print()			\
	pr_info("%s() cpu(%d) tsk(%d/%s)\n",	\
		__func__, smp_processor_id(), current->pid, current->comm);

#define syscall_enter(fmt...)							\
do {										\
	pr_info("%s() cpu(%d) tsk(%u/%u/%s) from-ip:%#lx\n",			\
		__func__, smp_processor_id(), current->pid, current->tgid,	\
		current->comm,	current_pt_regs()->ip);				\
	pr_info(fmt);								\
} while (0)

#define syscall_exit(ret)							\
	pr_info("%s() cpu(%d) tsk(%u/%u/%s) ret: %ld\n",			\
		__func__, smp_processor_id(), current->pid, current->tgid,	\
		current->comm, (long)ret);

/*
 * __MAP - apply a macro to syscall arguments
 * __MAP(n, m, t1, a1, t2, a2, ..., tn, an) will expand to
 *    m(t1, a1), m(t2, a2), ..., m(tn, an)
 * The first argument must be equal to the amount of type/name
 * pairs given.  Note that this list of pairs (i.e. the arguments
 * of __MAP starting at the third one) is in the same format as
 * for SYSCALL_DEFINE<n>/COMPAT_SYSCALL_DEFINE<n>
 */
#define __MAP0(m,...)
#define __MAP1(m,t,a) m(t,a)
#define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
#define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
#define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
#define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
#define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
#define __MAP(n,...) __MAP##n(__VA_ARGS__)

#define __SC_DECL(t, a)	t a
#define __TYPE_IS_L(t)	(__same_type((t)0, 0L))
#define __TYPE_IS_UL(t)	(__same_type((t)0, 0UL))
#define __TYPE_IS_LL(t) (__same_type((t)0, 0LL) || __same_type((t)0, 0ULL))
#define __SC_LONG(t, a) __typeof(__builtin_choose_expr(__TYPE_IS_LL(t), 0LL, 0L)) a
#define __SC_CAST(t, a)	(t) a
#define __SC_ARGS(t, a)	a
#define __SC_TEST(t, a) (void)BUILD_BUG_ON_ZERO(!__TYPE_IS_LL(t) && sizeof(t) > sizeof(long))

#define SYSCALL_DEFINE0(sname)					\
	asmlinkage long sys_##sname(void)

#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

#define SYSCALL_DEFINEx(x, sname, ...)				\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#define __SYSCALL_DEFINEx(x, name, ...)					\
	asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(SyS##name))));		\
	static inline long SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__));	\
	asmlinkage long SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = SYSC##name(__MAP(x,__SC_CAST,__VA_ARGS__));	\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		return ret;						\
	}								\
	static inline long SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__))

asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);
asmlinkage long sys_readv(unsigned long fd,
			  const struct iovec __user *vec,
			  unsigned long vlen);
asmlinkage long sys_write(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long sys_writev(unsigned long fd,
			   const struct iovec __user *vec,
			   unsigned long vlen);
asmlinkage long sys_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long sys_close(unsigned int fd);

asmlinkage long sys_getuid(void);
asmlinkage long sys_geteuid(void);
asmlinkage long sys_getgid(void);
asmlinkage long sys_getegid(void);

asmlinkage long sys_setgid(gid_t gid);
asmlinkage long sys_setuid(uid_t uid);

asmlinkage long sys_gettid(void);
asmlinkage long sys_getpid(void);
asmlinkage long sys_getppid(void);
asmlinkage long sys_fork(void);
asmlinkage long sys_vfork(void);
asmlinkage long sys_clone(unsigned long, unsigned long, int __user *,
			  int __user *, unsigned long);

asmlinkage long sys_brk(unsigned long);

asmlinkage long sys_execve(const char *filename,
			   const char *const *argv,
			   const char *const *envp);

asmlinkage long sys_mmap(unsigned long, unsigned long, unsigned long,
			 unsigned long, unsigned long, unsigned long);
asmlinkage long sys_mprotect(unsigned long start, size_t len,
			     unsigned long prot);
asmlinkage long sys_munmap(unsigned long addr, size_t len);
asmlinkage long sys_msync(unsigned long start, size_t len, int flags);

asmlinkage long sys_getrlimit(unsigned int resource,
				struct rlimit __user *rlim);

asmlinkage long sys_setrlimit(unsigned int resource,
				struct rlimit __user *rlim);

asmlinkage long sys_rt_sigprocmask(int how, sigset_t __user *nset,
				sigset_t __user *oset, size_t sigsetsize);

asmlinkage long sys_rt_sigpending(sigset_t __user *uset, size_t sigsetsize);

asmlinkage long sys_kill(pid_t pid, int sig);

asmlinkage long sys_rt_sigaction(int,
				 const struct sigaction __user *,
				 struct sigaction __user *,
				 size_t);

asmlinkage long sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo);

asmlinkage long sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);

asmlinkage long sys_futex(u32 __user *uaddr, int op, u32 val,
			struct timespec __user *utime, u32 __user *uaddr2,
			u32 val3);

/* x86-64 only */
asmlinkage long sys_arch_prctl(int, unsigned long);

#endif /* _LEGO_SYSCALLS_H_ */

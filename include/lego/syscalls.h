/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
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
#include <lego/kernel.h>
#include <lego/time.h>
#include <lego/getcpu.h>
#include <lego/socket.h>

#include <asm/syscalls.h>
#include <asm/stat.h>
#include <generated/unistd_64.h>

struct lego_dirent;
struct epoll_event;
struct pollfd;

#ifdef CONFIG_DEBUG_SYSCALL
#define debug_syscall_print()			\
	pr_info("%s() cpu(%d) tsk(%d/%s)\n",	\
		__func__, smp_processor_id(), current->pid, current->comm);

#define syscall_enter(fmt, ...)							\
do {										\
	pr_info("%s() cpu(%d) tsk(%u/%u/%s) user-ip:%#lx\n",			\
		__func__, smp_processor_id(), current->pid, current->tgid,	\
		current->comm,	current_pt_regs()->ip);				\
	pr_info("    "fmt, __VA_ARGS__);					\
} while (0)

#define __syscall_enter()							\
do {										\
	pr_info("%s() cpu(%d) tsk(%u/%u/%s) from-ip:%#lx\n",			\
		__func__, smp_processor_id(), current->pid, current->tgid,	\
		current->comm,	current_pt_regs()->ip);				\
} while (0)

#define syscall_exit(ret)							\
	pr_info("%s() cpu(%d) tsk(%u/%u/%s) ret: %#lx (%ld)\n",			\
		__func__, smp_processor_id(), current->pid, current->tgid,	\
		current->comm, (unsigned long)ret, (long)ret);

static inline int syscall_filename(const char __user *pathname)
{
	char kbuf[FILENAME_LEN_DEFAULT];
	if (strncpy_from_user(kbuf, pathname, FILENAME_LEN_DEFAULT) < 0) {
		return -EFAULT;
	}
	syscall_enter("filename: %s\n", kbuf);
	return 0;
}

#else
#define debug_syscall_print()	do { } while (0)
#define syscall_enter(fmt, ...)	do { } while (0)
#define __syscall_enter()	do { } while (0)
#define syscall_exit(ret)	do { } while (0)
#define syscall_filename(filename)	do { } while (0)
#endif /* CONFIG_DEBUG_SYSCALL */

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
asmlinkage long sys_pread64(unsigned int fd, char __user *buf,
			    size_t count, loff_t pos);
asmlinkage long sys_readv(unsigned long fd,
			  const struct iovec __user *vec,
			  unsigned long vlen);
asmlinkage long sys_write(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long sys_pwrite64(unsigned int fd, const char __user *buf,
			     size_t count, loff_t pos);
asmlinkage long sys_writev(unsigned long fd,
			   const struct iovec __user *vec,
			   unsigned long vlen);
asmlinkage long sys_open(const char __user *filename, int flags, umode_t mode);
asmlinkage long sys_openat(int dfd, const char __user *filename,
			int flags, umode_t mode);
asmlinkage long sys_creat(const char __user *pathname, umode_t mode);
asmlinkage long sys_close(unsigned int fd);

/* stats */
asmlinkage long sys_newstat(const char __user *filename,
			struct stat __user *statbuf);
asmlinkage long sys_newlstat(const char __user *filename,
			struct stat __user *statbuf);
asmlinkage long sys_newfstat(unsigned int fd, struct stat __user *statbuf);
asmlinkage long sys_newfstatat(int dfd, const char __user *filename,
			struct stat __user *statbuf, int flag);
asmlinkage long sys_statfs(const char __user *pathname, struct statfs __user *buf);

asmlinkage long sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
asmlinkage long sys_pipe2(int __user *flides, int flags);
asmlinkage long sys_pipe(int __user *flides);
asmlinkage long sys_sync(void);
asmlinkage long sys_truncate(const char __user *path, long length);
asmlinkage long sys_ftruncate(unsigned int fd, unsigned long length);
asmlinkage long sys_unlink(const char __user *pathname);
asmlinkage long sys_unlinkat(int dfd, const char __user *pathname, int flag);
asmlinkage long sys_mkdir(const char __user *filename, umode_t mode);
asmlinkage long sys_rmdir(const char __user *pathname);
asmlinkage long sys_getdents(unsigned int fd,
			struct lego_dirent __user *dirent, unsigned int count);
asmlinkage long sys_readlink(const char __user *path, char __user *buf, int bufsiz);

asmlinkage long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);

asmlinkage long sys_getuid(void);
asmlinkage long sys_geteuid(void);
asmlinkage long sys_getgid(void);
asmlinkage long sys_getegid(void);

asmlinkage long sys_setgid(gid_t gid);
asmlinkage long sys_setuid(uid_t uid);

asmlinkage long sys_gettid(void);
asmlinkage long sys_getpid(void);
asmlinkage long sys_getppid(void);
asmlinkage long sys_getpgrp(void);
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
asmlinkage long sys_mbind(unsigned long start, unsigned long len,
				unsigned long mode,
				const unsigned long __user *nmask,
				unsigned long maxnode,
				unsigned flags);

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

asmlinkage long sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);
asmlinkage long sys_time(time_t __user *tloc);
asmlinkage long sys_gettimeofday(struct timeval __user *tv,
				struct timezone __user *tz);
asmlinkage long sys_clock_gettime(const clockid_t which_clock,
				struct timespec __user *tp);
asmlinkage long setitimer(int which, struct timeval __user *value,
			struct timeval __user *ovalue);

/* Lego only */
asmlinkage long sys_checkpoint_process(pid_t pid);

/* x86-64 only */
asmlinkage long sys_arch_prctl(int, unsigned long);

/* backdoor syscall for testing pcache flush only */
asmlinkage long sys_pcache_flush(void __user *vaddr);

asmlinkage long sys_socket(int, int, int);
asmlinkage long sys_setsockopt(int fd, int level, int optname,
				char __user *optval, int optlen);
asmlinkage long sys_getsockopt(int fd, int level, int optname,
				char __user *optval, int __user *optlen);
asmlinkage long sys_getsockname(int, struct sockaddr __user *, int __user *);
asmlinkage long sys_sendto(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int);
asmlinkage long sys_recvfrom(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int __user *);
asmlinkage long sys_bind(int, struct sockaddr __user *, int);
asmlinkage long sys_accept(int, struct sockaddr __user *, int __user *);
asmlinkage long sys_listen(int, int);
asmlinkage long sys_select(int n, fd_set __user *inp, fd_set __user *outp,
			fd_set __user *exp, struct timeval __user *tvp);

asmlinkage long sys_epoll_create(int);			
asmlinkage long sys_epoll_create1(int);			
asmlinkage long sys_epoll_ctl(int epfd, int op, int fd, 
				struct epoll_event __user *event);
asmlinkage long sys_epoll_wait(int epfd, struct epoll_event __user *events,
				int maxevents, int timeout);
asmlinkage long sys_poll(struct pollfd __user *ufds, unsigned int nfds,
			long timeout_msecs);

/* ipc
 * message queue system call
 */
asmlinkage long sys_mq_send(char* mq_name, unsigned long name_size, unsigned long msg_size, const char* msg);
asmlinkage long sys_mq_open(char* mq_name, unsigned long name_size, unsigned long msg_size);
asmlinkage long sys_mq_receive(char* mq_name, unsigned long name_size, unsigned long* msg_size, char* msg);
asmlinkage long sys_mq_close(char* mq_name, unsigned long name_size);

/* to get the local nid in pComponent*/
asmlinkage long sys_get_local_nid(void);

/* to send an rpc echo to pComponent */
asmlinkage long sys_recho(unsigned int dest_nid);
#endif /* _LEGO_SYSCALLS_H_ */

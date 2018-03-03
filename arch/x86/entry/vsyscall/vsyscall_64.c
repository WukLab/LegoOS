/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/kernel.h>
#include <lego/syscalls.h>
#include <generated/unistd_64.h>
#include <asm/fixmap.h>
#include <asm/vsyscall.h>
#include <asm/traps.h>

#ifdef CONFIG_X86_DEBUG_VSYSCALL
#define vsyscall_debug(fmt, ...)		\
	pr_debug("%s() CPU%d " fmt "\n",	\
		__func__, smp_processor_id(), __VA_ARGS__)
#else
#define vsyscall_debug(fmt, ...)	do { } while (0)
#endif

static enum { EMULATE, NATIVE, NONE } vsyscall_mode =
#if defined(CONFIG_LEGACY_VSYSCALL_NATIVE)
	NATIVE;
#elif defined(CONFIG_LEGACY_VSYSCALL_NONE)
	NONE;
#else
	EMULATE;
#endif

static void warn_bad_vsyscall(struct pt_regs *regs, const char *message)
{
	printk("%s[%d] %s ip:%lx cs:%lx sp:%lx ax:%lx si:%lx di:%lx\n",
		current->comm, current->pid,
		message, regs->ip, regs->cs,
		regs->sp, regs->ax, regs->si, regs->di);
}

static int addr_to_vsyscall_nr(unsigned long addr)
{
	int nr;

	if ((addr & ~0xC00UL) != VSYSCALL_ADDR)
		return -EINVAL;

	nr = (addr & 0xC00UL) >> 10;
	if (nr >= 3)
		return -EINVAL;

	return nr;
}

static bool write_ok_or_segv(unsigned long ptr, size_t size)
{
	/*
	 * XXX: if access_ok, get_user, and put_user handled
	 * sig_on_uaccess_err, this could go away.
	 */

	if (!access_ok(VERIFY_WRITE, (void __user *)ptr, size)) {
		siginfo_t info;
		struct thread_struct *thread = &current->thread;

		thread->error_code	= 6;  /* user fault, no page, write */
		thread->cr2		= ptr;
		thread->trap_nr		= X86_TRAP_PF;

		memset(&info, 0, sizeof(info));
		info.si_signo		= SIGSEGV;
		info.si_errno		= 0;
		info.si_code		= SEGV_MAPERR;
		info.si_addr		= (void __user *)ptr;

		force_sig_info(SIGSEGV, &info, current);
		return false;
	} else {
		return true;
	}
}

static inline int secure_computing(void *sd) { return 0; }

bool emulate_vsyscall(struct pt_regs *regs, unsigned long address)
{
	struct task_struct *tsk;
	unsigned long caller;
	int vsyscall_nr, syscall_nr, tmp;
	int prev_sig_on_uaccess_err;
	long ret;

	/*
	 * No point in checking CS -- the only way to get here is a user mode
	 * trap to a high address, which means that we're in 64-bit user code.
	 */

	WARN_ON_ONCE(address != regs->ip);

	if (vsyscall_mode == NONE) {
		warn_bad_vsyscall(regs, "vsyscall attempted with vsyscall=none");
		return false;
	}

	vsyscall_nr = addr_to_vsyscall_nr(address);

	if (vsyscall_nr < 0) {
		warn_bad_vsyscall(regs,
				  "misaligned vsyscall (exploit attempt or buggy program) -- "
				  "look up the vsyscall kernel parameter if you need a workaround");
		goto sigsegv;
	}

	if (get_user(caller, (unsigned long __user *)regs->sp) != 0) {
		warn_bad_vsyscall(regs, "vsyscall with bad stack (exploit attempt?)");
		goto sigsegv;
	}

	tsk = current;

	/*
	 * Check for access_ok violations and find the syscall nr.
	 *
	 * NULL is a valid user pointer (in the access_ok sense) on 32-bit and
	 * 64-bit, so we don't need to special-case it here.  For all the
	 * vsyscalls, NULL means "don't write anything" not "write it at
	 * address 0".
	 */
	switch (vsyscall_nr) {
	case 0:
		if (!write_ok_or_segv(regs->di, sizeof(struct timeval)) ||
		    !write_ok_or_segv(regs->si, sizeof(struct timezone))) {
			ret = -EFAULT;
			goto check_fault;
		}

		syscall_nr = __NR_gettimeofday;
		break;

	case 1:
		if (!write_ok_or_segv(regs->di, sizeof(time_t))) {
			ret = -EFAULT;
			goto check_fault;
		}

		syscall_nr = __NR_time;
		break;

	case 2:
		if (!write_ok_or_segv(regs->di, sizeof(unsigned)) ||
		    !write_ok_or_segv(regs->si, sizeof(unsigned))) {
			ret = -EFAULT;
			goto check_fault;
		}

		syscall_nr = __NR_getcpu;
		break;
	}

	vsyscall_debug("[%s][%d] vsyscall_nr: %d(%pS)",
		tsk->comm, tsk->pid, vsyscall_nr, sys_call_table[syscall_nr]);

	/*
	 * Handle seccomp.  regs->ip must be the original value.
	 * See seccomp_send_sigsys and Documentation/prctl/seccomp_filter.txt.
	 *
	 * We could optimize the seccomp disabled case, but performance
	 * here doesn't matter.
	 */
	regs->orig_ax = syscall_nr;
	regs->ax = -ENOSYS;
	tmp = secure_computing(NULL);
	if ((!tmp && regs->orig_ax != syscall_nr) || regs->ip != address) {
		warn_bad_vsyscall(regs, "seccomp tried to change syscall nr or ip");
		do_exit(SIGSYS);
	}
	regs->orig_ax = -1;
	if (tmp)
		goto do_ret;  /* skip requested */

	/*
	 * With a real vsyscall, page faults cause SIGSEGV.  We want to
	 * preserve that behavior to make writing exploits harder.
	 *
	 * This part will be taken care of by no_context().
	 */
	prev_sig_on_uaccess_err = current->thread.sig_on_uaccess_err;
	current->thread.sig_on_uaccess_err = 1;

	ret = -EFAULT;
	switch (vsyscall_nr) {
	case 0:
		ret = sys_gettimeofday(
			(struct timeval __user *)regs->di,
			(struct timezone __user *)regs->si);
		break;

	case 1:
		ret = sys_time((time_t __user *)regs->di);
		break;

	case 2:
		ret = sys_getcpu((unsigned __user *)regs->di,
				 (unsigned __user *)regs->si,
				 NULL);
		break;
	}

	current->thread.sig_on_uaccess_err = prev_sig_on_uaccess_err;

check_fault:
	if (ret == -EFAULT) {
		/* Bad news -- userspace fed a bad pointer to a vsyscall. */
		warn_bad_vsyscall(regs, "vsyscall fault (exploit attempt?)");

		/*
		 * If we failed to generate a signal for any reason,
		 * generate one here.  (This should be impossible.)
		 */
		if (WARN_ON_ONCE(!sigismember(&tsk->pending.signal, SIGBUS) &&
				 !sigismember(&tsk->pending.signal, SIGSEGV)))
			goto sigsegv;

		return true;  /* Don't emulate the ret. */
	}

	regs->ax = ret;

do_ret:
	/* Emulate a ret instruction. */
	regs->ip = caller;
	regs->sp += 8;
	return true;

sigsegv:
	force_sig(SIGSEGV, current);
	return true;
}

void __init map_vsyscall(void)
{
	extern char __vsyscall_page;
	unsigned long physaddr_vsyscall = __pa_symbol(&__vsyscall_page);

	if (vsyscall_mode != NONE)
		__set_fixmap(VSYSCALL_PAGE, physaddr_vsyscall,
			     vsyscall_mode == NATIVE
			     ? PAGE_KERNEL_VSYSCALL
			     : PAGE_KERNEL_VVAR);

	pr_debug("vsyscall: va: %#lx pa: %#lx\n", __fix_to_virt(VSYSCALL_PAGE), physaddr_vsyscall);
	BUILD_BUG_ON((unsigned long)__fix_to_virt(VSYSCALL_PAGE) !=
		     (unsigned long)VSYSCALL_ADDR);
}

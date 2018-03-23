/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/percpu.h>
#include <lego/syscalls.h>

#include <asm/asm.h>
#include <asm/msr.h>
#include <asm/prctl.h>
#include <asm/kdebug.h>
#include <asm/ptrace.h>
#include <asm/segment.h>
#include <asm/processor.h>
#include <asm/switch_to.h>
#include <asm/fpu/internal.h>

__visible DEFINE_PER_CPU(unsigned long, rsp_scratch);

/*
 * per-CPU TSS segments. Threads are completely 'soft' on LegoOS,
 * no more per-task TSS's. The TSS size is kept cacheline-aligned
 * so they are allowed to end up in the .data..cacheline_aligned
 * section. Since TSS's are completely CPU-local, we want them
 * on exact cacheline boundaries, to eliminate cacheline ping-pong.
 */

DEFINE_PER_CPU(struct tss_struct, cpu_tss) = {
	.x86_tss = {
		.sp0 = TOP_OF_INIT_STACK,
	},
};

long do_arch_prctl(struct task_struct *task, int code, unsigned long addr)
{
	int ret = 0;
	int doit = task == current;
	int cpu;

	switch (code) {
	case ARCH_SET_GS:
		if (addr >= TASK_SIZE_MAX)
			return -EPERM;
		cpu = get_cpu();
		task->thread.gsindex = 0;
		task->thread.gsbase = addr;
		if (doit) {
			load_gs_index(0);
			wrmsrl_safe(MSR_KERNEL_GS_BASE, addr);
		}
		put_cpu();
		break;
	case ARCH_SET_FS:
		/* Not strictly needed for fs, but do it for symmetry
		   with gs */
		if (addr >= TASK_SIZE_MAX)
			return -EPERM;
		cpu = get_cpu();
		task->thread.fsindex = 0;
		task->thread.fsbase = addr;
		if (doit) {
			/* set the selector to 0 to not confuse __switch_to */
			loadsegment(fs, 0);
			wrmsrl_safe(MSR_FS_BASE, addr);
		}
		put_cpu();
		break;
	case ARCH_GET_FS: {
		unsigned long base;
		if (doit)
			rdmsrl(MSR_FS_BASE, base);
		else
			base = task->thread.fsbase;
		ret = put_user(base, (unsigned long __user *)addr);
		break;
	}
	case ARCH_GET_GS: {
		unsigned long base;
		if (doit)
			rdmsrl(MSR_KERNEL_GS_BASE, base);
		else
			base = task->thread.gsbase;
		ret = put_user(base, (unsigned long __user *)addr);
		break;
	}

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

SYSCALL_DEFINE2(arch_prctl, int, code, unsigned long, addr)
{
	syscall_enter("code: %d, addr: %lx\n", code, addr);
	return do_arch_prctl(current, code, addr);
}

/* Seriously, this is magic function */
int copy_thread_tls(unsigned long clone_flags, unsigned long sp,
		unsigned long arg, struct task_struct *p, unsigned long tls)
{
	struct pt_regs *childregs;
	struct fork_frame *fork_frame;
	struct inactive_task_frame *frame;
	struct task_struct *me = current;
	int err;

	p->thread.sp0 = (unsigned long)task_stack_page(p) + THREAD_SIZE;
	childregs = task_pt_regs(p);
	fork_frame = container_of(childregs, struct fork_frame, regs);
	frame = &fork_frame->frame;
	frame->bp = 0;
	/* __switch_to() will return to ret_from_fork */
	frame->ret_addr = (unsigned long)ret_from_fork;
	/* __switch_to_asm will switch to this sp */
	p->thread.sp = (unsigned long)fork_frame;
	p->thread.io_bitmap_ptr = NULL;

	savesegment(gs, p->thread.gsindex);
	p->thread.gsbase = p->thread.gsindex ? 0 : me->thread.gsbase;
	savesegment(fs, p->thread.fsindex);
	p->thread.fsbase = p->thread.fsindex ? 0 : me->thread.fsbase;
	savesegment(es, p->thread.es);
	savesegment(ds, p->thread.ds);

	if (unlikely(p->flags & PF_KTHREAD)) {
		/* kernel thread */
		memset(childregs, 0, sizeof(struct pt_regs));
		frame->bx = sp;		/* function */
		frame->r12 = arg;
		return 0;
	}
	frame->bx = 0;
	*childregs = *current_pt_regs();

	childregs->ax = 0;
	if (sp)
		childregs->sp = sp;

	/*
	 * Set a new TLS for the child thread?
	 */
	if (clone_flags & CLONE_SETTLS) {
#ifdef CONFIG_IA32_EMULATION
		if (in_ia32_syscall())
			BUG();
		else
#endif
			err = do_arch_prctl(p, ARCH_SET_FS, tls);
		if (err)
			goto out;
	}

	err = 0;
out:
	return err;
}

/**
 * start_thread	- Starting a new user thread
 * @regs: pointer to pt_regs
 * @new_ip: the first instruction IP of user thread
 * @new_sp: the new stack pointer of user thread
 *
 * We do not return to usermode here, we simply replace the return IP of the
 * regs frame. While the kernel thread returns, it will simply merge to syscall
 * return path (check ret_from_fork() in entry.S for detial).
 */
static void
start_thread_common(struct pt_regs *regs, unsigned long new_ip,
		    unsigned long new_sp,
		    unsigned int _cs, unsigned int _ss, unsigned int _ds)
{
	loadsegment(fs, 0);
	loadsegment(es, _ds);
	loadsegment(ds, _ds);
	load_gs_index(0);
	regs->ip		= new_ip;
	regs->sp		= new_sp;
	regs->cs		= _cs;
	regs->ss		= _ss;
	regs->flags		= X86_EFLAGS_IF;

	regs->bx		= 0;
	regs->cx		= 0;
	regs->dx		= 0;
	regs->si		= 0;
	regs->di		= 0;
	regs->bp		= 0;
	regs->r8		= 0;
	regs->r9		= 0;
	regs->r10		= 0;
	regs->r11		= 0;
	regs->r12		= 0;
	regs->r13		= 0;
	regs->r14		= 0;
	regs->r15		= 0;
	force_iret();
}

void
start_thread(struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp)
{
	start_thread_common(regs, new_ip, new_sp,
			    __USER_CS, __USER_DS, 0);
}

#ifdef CONFIG_COMPAT
void compat_start_thread(struct pt_regs *regs, u32 new_ip, u32 new_sp)
{
	start_thread_common(regs, new_ip, new_sp,
			    test_thread_flag(TIF_X32)
			    ? __USER_CS : __USER32_CS,
			    __USER_DS, __USER_DS);
}
#endif

/*
 * switch_to(x,y) should switch tasks from x to y.
 */
__visible struct task_struct *
__switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread;
	struct thread_struct *next = &next_p->thread;
	struct fpu *prev_fpu = &prev->fpu;
	struct fpu *next_fpu = &next->fpu;
	int cpu = smp_processor_id();
	struct tss_struct *tss = &per_cpu(cpu_tss, cpu);
	unsigned prev_fsindex, prev_gsindex;
	fpu_switch_t fpu_switch;

	fpu_switch = switch_fpu_prepare(prev_fpu, next_fpu, cpu);

	/*
	 * We must save %fs and %gs before load_TLS() because
	 * %fs and %gs may be cleared by load_TLS().
	 * (e.g. xen_load_tls())
	 */
	savesegment(fs, prev_fsindex);
	savesegment(gs, prev_gsindex);

	/*
	 * Load TLS before restoring any segments so that segment loads
	 * reference the correct GDT entries.
	 */
	load_TLS(next, cpu);

	/* Switch DS and ES.
	 *
	 * Reading them only returns the selectors, but writing them (if
	 * nonzero) loads the full descriptor from the GDT or LDT.  The
	 * LDT for next is loaded in switch_mm, and the GDT is loaded
	 * above.
	 *
	 * We therefore need to write new values to the segment
	 * registers on every context switch unless both the new and old
	 * values are zero.
	 *
	 * Note that we don't need to do anything for CS and SS, as
	 * those are saved and restored as part of pt_regs.
	 */
	savesegment(es, prev->es);
	if (unlikely(next->es | prev->es))
		loadsegment(es, next->es);

	savesegment(ds, prev->ds);
	if (unlikely(next->ds | prev->ds))
		loadsegment(ds, next->ds);

	/*
	 * Switch FS and GS.
	 *
	 * These are even more complicated than DS and ES: they have
	 * 64-bit bases are that controlled by arch_prctl.  The bases
	 * don't necessarily match the selectors, as user code can do
	 * any number of things to cause them to be inconsistent.
	 *
	 * We don't promise to preserve the bases if the selectors are
	 * nonzero.  We also don't promise to preserve the base if the
	 * selector is zero and the base doesn't match whatever was
	 * most recently passed to ARCH_SET_FS/GS.  (If/when the
	 * FSGSBASE instructions are enabled, we'll need to offer
	 * stronger guarantees.)
	 *
	 * As an invariant,
	 * (fsbase != 0 && fsindex != 0) || (gsbase != 0 && gsindex != 0) is
	 * impossible.
	 */
	if (next->fsindex) {
		/* Loading a nonzero value into FS sets the index and base. */
		loadsegment(fs, next->fsindex);
	} else {
		if (next->fsbase) {
			/* Next index is zero but next base is nonzero. */
			if (prev_fsindex)
				loadsegment(fs, 0);
			wrmsrl(MSR_FS_BASE, next->fsbase);
		} else {
			/* Next base and index are both zero. */
			if (cpu_has(X86_BUG_NULL_SEG)) {
				/*
				 * We don't know the previous base and can't
				 * find out without RDMSR.  Forcibly clear it.
				 */
				loadsegment(fs, __USER_DS);
				loadsegment(fs, 0);
			} else {
				/*
				 * If the previous index is zero and ARCH_SET_FS
				 * didn't change the base, then the base is
				 * also zero and we don't need to do anything.
				 */
				if (prev->fsbase || prev_fsindex)
					loadsegment(fs, 0);
			}
		}
	}
	/*
	 * Save the old state and preserve the invariant.
	 * NB: if prev_fsindex == 0, then we can't reliably learn the base
	 * without RDMSR because Intel user code can zero it without telling
	 * us and AMD user code can program any 32-bit value without telling
	 * us.
	 */
	if (prev_fsindex)
		prev->fsbase = 0;
	prev->fsindex = prev_fsindex;

	if (next->gsindex) {
		/* Loading a nonzero value into GS sets the index and base. */
		load_gs_index(next->gsindex);
	} else {
		if (next->gsbase) {
			/* Next index is zero but next base is nonzero. */
			if (prev_gsindex)
				load_gs_index(0);
			wrmsrl(MSR_KERNEL_GS_BASE, next->gsbase);
		} else {
			/* Next base and index are both zero. */
			if (cpu_has(X86_BUG_NULL_SEG)) {
				/*
				 * We don't know the previous base and can't
				 * find out without RDMSR.  Forcibly clear it.
				 *
				 * This contains a pointless SWAPGS pair.
				 * Fixing it would involve an explicit check
				 * for Xen or a new pvop.
				 */
				load_gs_index(__USER_DS);
				load_gs_index(0);
			} else {
				/*
				 * If the previous index is zero and ARCH_SET_GS
				 * didn't change the base, then the base is
				 * also zero and we don't need to do anything.
				 */
				if (prev->gsbase || prev_gsindex)
					load_gs_index(0);
			}
		}
	}
	/*
	 * Save the old state and preserve the invariant.
	 * NB: if prev_gsindex == 0, then we can't reliably learn the base
	 * without RDMSR because Intel user code can zero it without telling
	 * us and AMD user code can program any 32-bit value without telling
	 * us.
	 */
	if (prev_gsindex)
		prev->gsbase = 0;
	prev->gsindex = prev_gsindex;

	switch_fpu_finish(next_fpu, fpu_switch);

	this_cpu_write(current_task, next_p);

	/* Reload sp0 This changes current_thread_info(). */
	load_sp0(tss, next);

	return prev_p;
}

/*
 * this gets called so that we can store lazy state into memory and copy the
 * current task into the new thread.
 */
int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	memcpy(dst, src, arch_task_struct_size);

	return fpu__copy(&dst->thread.fpu, &src->thread.fpu);
}

/*
 * Free current thread data structures etc..
 */
void exit_thread(struct task_struct *tsk)
{
	struct thread_struct *t = &tsk->thread;
	unsigned long *bp = t->io_bitmap_ptr;
	struct fpu *fpu = &t->fpu;

	if (bp) {
		struct tss_struct *tss = &per_cpu(cpu_tss, get_cpu());

		t->io_bitmap_ptr = NULL;
		clear_thread_flag(TIF_IO_BITMAP);
		/*
		 * Careful, clear this in the TSS too:
		 */
		memset(tss->io_bitmap, 0xff, t->io_bitmap_max);
		t->io_bitmap_max = 0;
		put_cpu();
		kfree(bp);
	}

	fpu__drop(fpu);
}

void flush_thread(void)
{
	struct task_struct *tsk = current;

	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));

	fpu__clear(&tsk->thread.fpu);
}

static int die_counter;

int __die(const char *str, struct pt_regs *regs, long err)
{
	printk(KERN_DEFAULT
	       "%s: %04lx [#%d]%s%s%s%s\n", str, err & 0xffff, ++die_counter,
	       IS_ENABLED(CONFIG_PREEMPT)	? " PREEMPT"	: "",
	       IS_ENABLED(CONFIG_SMP)		? " SMP"	: "",
	       IS_ENABLED(CONFIG_COMP_PROCESSOR)? " PROCESSOR"	: "",
	       IS_ENABLED(CONFIG_COMP_MEMORY)	? " MEMORY"	: "");

	show_regs(regs);

	/* Executive summary in case the oops scrolled away */
	printk(KERN_ALERT "RIP ");
	pr_cont(" [<%p>] %pS\n", (void *)regs->ip, (void *)regs->ip);
	printk(" RSP <%016lx>\n", regs->sp);

	return 0;
}

/*
 * This is gone through when something in the kernel has done something bad
 * and is about to be terminated:
 */
void die(const char *str, struct pt_regs *regs, long err)
{
	__die(str, regs, err);
	panic("Fatal exception");
}

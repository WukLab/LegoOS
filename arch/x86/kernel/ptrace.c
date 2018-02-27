/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/regset.h>
#include <lego/kernel.h>
#include <asm/user.h>
#include <asm/prctl.h>
#include <asm/fpu/regset.h>
#include <uapi/elf.h>

enum x86_regset {
	REGSET_GENERAL,
	REGSET_FP,
	REGSET_XFP,
	REGSET_IOPERM64 = REGSET_XFP,
	REGSET_XSTATE,
	REGSET_TLS,
	REGSET_IOPERM32,
};

struct pt_regs_offset {
	const char *name;
	int offset;
};

#define REG_OFFSET_NAME(r) {.name = #r, .offset = offsetof(struct pt_regs, r)}
#define REG_OFFSET_END {.name = NULL, .offset = 0}

static const struct pt_regs_offset regoffset_table[] = {
#ifdef CONFIG_X86_64
	REG_OFFSET_NAME(r15),
	REG_OFFSET_NAME(r14),
	REG_OFFSET_NAME(r13),
	REG_OFFSET_NAME(r12),
	REG_OFFSET_NAME(r11),
	REG_OFFSET_NAME(r10),
	REG_OFFSET_NAME(r9),
	REG_OFFSET_NAME(r8),
#endif
	REG_OFFSET_NAME(bx),
	REG_OFFSET_NAME(cx),
	REG_OFFSET_NAME(dx),
	REG_OFFSET_NAME(si),
	REG_OFFSET_NAME(di),
	REG_OFFSET_NAME(bp),
	REG_OFFSET_NAME(ax),
#ifdef CONFIG_X86_32
	REG_OFFSET_NAME(ds),
	REG_OFFSET_NAME(es),
	REG_OFFSET_NAME(fs),
	REG_OFFSET_NAME(gs),
#endif
	REG_OFFSET_NAME(orig_ax),
	REG_OFFSET_NAME(ip),
	REG_OFFSET_NAME(cs),
	REG_OFFSET_NAME(flags),
	REG_OFFSET_NAME(sp),
	REG_OFFSET_NAME(ss),
	REG_OFFSET_END,
};

/**
 * regs_query_register_offset() - query register offset from its name
 * @name:	the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
int regs_query_register_offset(const char *name)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->offset;
	return -EINVAL;
}

/**
 * regs_query_register_name() - query register name from its offset
 * @offset:	the offset of a register in struct pt_regs.
 *
 * regs_query_register_name() returns the name of a register from its
 * offset in struct pt_regs. If the @offset is invalid, this returns NULL;
 */
const char *regs_query_register_name(unsigned int offset)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (roff->offset == offset)
			return roff->name;
	return NULL;
}

/*
 * does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

/*
 * Determines which flags the user has access to [1 = access, 0 = no access].
 */
#define FLAG_MASK_32		((unsigned long)			\
				 (X86_EFLAGS_CF | X86_EFLAGS_PF |	\
				  X86_EFLAGS_AF | X86_EFLAGS_ZF |	\
				  X86_EFLAGS_SF | X86_EFLAGS_TF |	\
				  X86_EFLAGS_DF | X86_EFLAGS_OF |	\
				  X86_EFLAGS_RF | X86_EFLAGS_AC))

/*
 * Determines whether a value may be installed in a segment register.
 */
static inline bool invalid_selector(u16 value)
{
	return unlikely(value != 0 && (value & SEGMENT_RPL_MASK) != USER_RPL);
}

#define FLAG_MASK		(FLAG_MASK_32 | X86_EFLAGS_NT)

static unsigned long *pt_regs_access(struct pt_regs *regs, unsigned long offset)
{
	BUILD_BUG_ON(offsetof(struct pt_regs, r15) != 0);
	return &regs->r15 + (offset / sizeof(regs->r15));
}

static u16 get_segment_reg(struct task_struct *task, unsigned long offset)
{
	/*
	 * Returning the value truncates it to 16 bits.
	 */
	unsigned int seg;

	switch (offset) {
	case offsetof(struct user_regs_struct, fs):
		if (task == current) {
			/* Older gas can't assemble movq %?s,%r?? */
			asm("movl %%fs,%0" : "=r" (seg));
			return seg;
		}
		return task->thread.fsindex;
	case offsetof(struct user_regs_struct, gs):
		if (task == current) {
			asm("movl %%gs,%0" : "=r" (seg));
			return seg;
		}
		return task->thread.gsindex;
	case offsetof(struct user_regs_struct, ds):
		if (task == current) {
			asm("movl %%ds,%0" : "=r" (seg));
			return seg;
		}
		return task->thread.ds;
	case offsetof(struct user_regs_struct, es):
		if (task == current) {
			asm("movl %%es,%0" : "=r" (seg));
			return seg;
		}
		return task->thread.es;

	case offsetof(struct user_regs_struct, cs):
	case offsetof(struct user_regs_struct, ss):
		break;
	}
	return *pt_regs_access(task_pt_regs(task), offset);
}

static int set_segment_reg(struct task_struct *task,
			   unsigned long offset, u16 value)
{
	/*
	 * The value argument was already truncated to 16 bits.
	 */
	if (invalid_selector(value))
		return -EIO;

	switch (offset) {
	case offsetof(struct user_regs_struct,fs):
		task->thread.fsindex = value;
		if (task == current)
			loadsegment(fs, task->thread.fsindex);
		break;
	case offsetof(struct user_regs_struct,gs):
		task->thread.gsindex = value;
		if (task == current)
			load_gs_index(task->thread.gsindex);
		break;
	case offsetof(struct user_regs_struct,ds):
		task->thread.ds = value;
		if (task == current)
			loadsegment(ds, task->thread.ds);
		break;
	case offsetof(struct user_regs_struct,es):
		task->thread.es = value;
		if (task == current)
			loadsegment(es, task->thread.es);
		break;

		/*
		 * Can't actually change these in 64-bit mode.
		 */
	case offsetof(struct user_regs_struct,cs):
		if (unlikely(value == 0))
			return -EIO;
		task_pt_regs(task)->cs = value;
		break;
	case offsetof(struct user_regs_struct,ss):
		if (unlikely(value == 0))
			return -EIO;
		task_pt_regs(task)->ss = value;
		break;
	}

	return 0;
}

static unsigned long get_flags(struct task_struct *task)
{
	unsigned long retval = task_pt_regs(task)->flags;

	/*
	 * If the debugger set TF, hide it from the readout.
	 */
	if (test_tsk_thread_flag(task, TIF_FORCED_TF))
		retval &= ~X86_EFLAGS_TF;

	return retval;
}

static int set_flags(struct task_struct *task, unsigned long value)
{
	struct pt_regs *regs = task_pt_regs(task);

	/*
	 * If the user value contains TF, mark that
	 * it was not "us" (the debugger) that set it.
	 * If not, make sure it stays set if we had.
	 */
	if (value & X86_EFLAGS_TF)
		clear_tsk_thread_flag(task, TIF_FORCED_TF);
	else if (test_tsk_thread_flag(task, TIF_FORCED_TF))
		value |= X86_EFLAGS_TF;

	regs->flags = (regs->flags & ~FLAG_MASK) | (value & FLAG_MASK);

	return 0;
}

static int putreg(struct task_struct *child,
		  unsigned long offset, unsigned long value)
{
	switch (offset) {
	case offsetof(struct user_regs_struct, cs):
	case offsetof(struct user_regs_struct, ds):
	case offsetof(struct user_regs_struct, es):
	case offsetof(struct user_regs_struct, fs):
	case offsetof(struct user_regs_struct, gs):
	case offsetof(struct user_regs_struct, ss):
		return set_segment_reg(child, offset, value);

	case offsetof(struct user_regs_struct, flags):
		return set_flags(child, value);

#ifdef CONFIG_X86_64
	case offsetof(struct user_regs_struct,fs_base):
		if (value >= TASK_SIZE_MAX)
			return -EIO;
		/*
		 * When changing the segment base, use do_arch_prctl
		 * to set either thread.fs or thread.fsindex and the
		 * corresponding GDT slot.
		 */
		if (child->thread.fsbase != value)
			return do_arch_prctl(child, ARCH_SET_FS, value);
		return 0;
	case offsetof(struct user_regs_struct,gs_base):
		/*
		 * Exactly the same here as the %fs handling above.
		 */
		if (value >= TASK_SIZE_MAX)
			return -EIO;
		if (child->thread.gsbase != value)
			return do_arch_prctl(child, ARCH_SET_GS, value);
		return 0;
#endif
	}

	*pt_regs_access(task_pt_regs(child), offset) = value;
	return 0;
}

static unsigned long getreg(struct task_struct *task, unsigned long offset)
{
	switch (offset) {
	case offsetof(struct user_regs_struct, cs):
	case offsetof(struct user_regs_struct, ds):
	case offsetof(struct user_regs_struct, es):
	case offsetof(struct user_regs_struct, fs):
	case offsetof(struct user_regs_struct, gs):
	case offsetof(struct user_regs_struct, ss):
		return get_segment_reg(task, offset);

	case offsetof(struct user_regs_struct, flags):
		return get_flags(task);

#ifdef CONFIG_X86_64
	case offsetof(struct user_regs_struct, fs_base): {
		/*
		 * XXX: This will not behave as expected if called on
		 * current or if fsindex != 0.
		 */
		return task->thread.fsbase;
	}
	case offsetof(struct user_regs_struct, gs_base): {
		/*
		 * XXX: This will not behave as expected if called on
		 * current or if fsindex != 0.
		 */
		return task->thread.gsbase;
	}
#endif
	}

	return *pt_regs_access(task_pt_regs(task), offset);
}

static int genregs_get(struct task_struct *target,
		       const struct user_regset *regset,
		       unsigned int pos, unsigned int count,
		       void *kbuf, void __user *ubuf)
{
	if (kbuf) {
		unsigned long *k = kbuf;
		while (count >= sizeof(*k)) {
			*k++ = getreg(target, pos);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		unsigned long __user *u = ubuf;
		while (count >= sizeof(*u)) {
			if (__put_user(getreg(target, pos), u++))
				return -EFAULT;
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}

	return 0;
}

static int genregs_set(struct task_struct *target,
		       const struct user_regset *regset,
		       unsigned int pos, unsigned int count,
		       const void *kbuf, const void __user *ubuf)
{
	int ret = 0;
	if (kbuf) {
		const unsigned long *k = kbuf;
		while (count >= sizeof(*k) && !ret) {
			ret = putreg(target, pos, *k++);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		const unsigned long  __user *u = ubuf;
		while (count >= sizeof(*u) && !ret) {
			unsigned long word;
			ret = __get_user(word, u++);
			if (ret)
				break;
			ret = putreg(target, pos, word);
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}
	return ret;
}

/*
 * These access the current or another (stopped) task's io permission
 * bitmap for debugging or core dump.
 */
static int ioperm_active(struct task_struct *target,
			 const struct user_regset *regset)
{
	return target->thread.io_bitmap_max / regset->size;
}

static int ioperm_get(struct task_struct *target,
		      const struct user_regset *regset,
		      unsigned int pos, unsigned int count,
		      void *kbuf, void __user *ubuf)
{
	if (!target->thread.io_bitmap_ptr)
		return -ENXIO;

	return user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				   target->thread.io_bitmap_ptr,
				   0, IO_BITMAP_BYTES);
}

#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
static const struct user_regset_view user_x86_32_view; /* Initialized below. */
#endif

#ifdef CONFIG_IA32_EMULATION

#include <lego/compat.h>
#include <lego/syscalls.h>
#include <asm/ia32.h>
#include <asm/user32.h>

#define R32(l,q)							\
	case offsetof(struct user32, regs.l):				\
		regs->q = value; break

#define SEG32(rs)							\
	case offsetof(struct user32, regs.rs):				\
		return set_segment_reg(child,				\
				       offsetof(struct user_regs_struct, rs), \
				       value);				\
		break

static int putreg32(struct task_struct *child, unsigned regno, u32 value)
{
	struct pt_regs *regs = task_pt_regs(child);

	switch (regno) {

	SEG32(cs);
	SEG32(ds);
	SEG32(es);
	SEG32(fs);
	SEG32(gs);
	SEG32(ss);

	R32(ebx, bx);
	R32(ecx, cx);
	R32(edx, dx);
	R32(edi, di);
	R32(esi, si);
	R32(ebp, bp);
	R32(eax, ax);
	R32(eip, ip);
	R32(esp, sp);

	case offsetof(struct user32, regs.orig_eax):
		/*
		 * Warning: bizarre corner case fixup here.  A 32-bit
		 * debugger setting orig_eax to -1 wants to disable
		 * syscall restart.  Make sure that the syscall
		 * restart code sign-extends orig_ax.  Also make sure
		 * we interpret the -ERESTART* codes correctly if
		 * loaded into regs->ax in case the task is not
		 * actually still sitting at the exit from a 32-bit
		 * syscall with TS_COMPAT still set.
		 */
		regs->orig_ax = value;
		if (syscall_get_nr(child, regs) >= 0)
			child->thread.status |= TS_I386_REGS_POKED;
		break;

	case offsetof(struct user32, regs.eflags):
		return set_flags(child, value);

	case offsetof(struct user32, u_debugreg[0]) ...
		offsetof(struct user32, u_debugreg[7]):
		regno -= offsetof(struct user32, u_debugreg[0]);
		BUG();

	default:
		if (regno > sizeof(struct user32) || (regno & 3))
			return -EIO;

		/*
		 * Other dummy fields in the virtual user structure
		 * are ignored
		 */
		break;
	}
	return 0;
}

#undef R32
#undef SEG32

#define R32(l,q)							\
	case offsetof(struct user32, regs.l):				\
		*val = regs->q; break

#define SEG32(rs)							\
	case offsetof(struct user32, regs.rs):				\
		*val = get_segment_reg(child,				\
				       offsetof(struct user_regs_struct, rs)); \
		break

static int getreg32(struct task_struct *child, unsigned regno, u32 *val)
{
	struct pt_regs *regs = task_pt_regs(child);

	switch (regno) {

	SEG32(ds);
	SEG32(es);
	SEG32(fs);
	SEG32(gs);

	R32(cs, cs);
	R32(ss, ss);
	R32(ebx, bx);
	R32(ecx, cx);
	R32(edx, dx);
	R32(edi, di);
	R32(esi, si);
	R32(ebp, bp);
	R32(eax, ax);
	R32(orig_eax, orig_ax);
	R32(eip, ip);
	R32(esp, sp);

	case offsetof(struct user32, regs.eflags):
		*val = get_flags(child);
		break;

	case offsetof(struct user32, u_debugreg[0]) ...
		offsetof(struct user32, u_debugreg[7]):
		regno -= offsetof(struct user32, u_debugreg[0]);
		BUG();
		break;

	default:
		if (regno > sizeof(struct user32) || (regno & 3))
			return -EIO;

		/*
		 * Other dummy fields in the virtual user structure
		 * are ignored
		 */
		*val = 0;
		break;
	}
	return 0;
}

#undef R32
#undef SEG32

static int genregs32_get(struct task_struct *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 void *kbuf, void __user *ubuf)
{
	if (kbuf) {
		compat_ulong_t *k = kbuf;
		while (count >= sizeof(*k)) {
			getreg32(target, pos, k++);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		compat_ulong_t __user *u = ubuf;
		while (count >= sizeof(*u)) {
			compat_ulong_t word;
			getreg32(target, pos, &word);
			if (__put_user(word, u++))
				return -EFAULT;
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}

	return 0;
}

static int genregs32_set(struct task_struct *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 const void *kbuf, const void __user *ubuf)
{
	int ret = 0;
	if (kbuf) {
		const compat_ulong_t *k = kbuf;
		while (count >= sizeof(*k) && !ret) {
			ret = putreg32(target, pos, *k++);
			count -= sizeof(*k);
			pos += sizeof(*k);
		}
	} else {
		const compat_ulong_t __user *u = ubuf;
		while (count >= sizeof(*u) && !ret) {
			compat_ulong_t word;
			ret = __get_user(word, u++);
			if (ret)
				break;
			ret = putreg32(target, pos, word);
			count -= sizeof(*u);
			pos += sizeof(*u);
		}
	}
	return ret;
}
#endif /* CONFIG_IA32_EMULATION */

#ifdef CONFIG_X86_64

static struct user_regset x86_64_regsets[] = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct user_regs_struct) / sizeof(long),
		.size = sizeof(long), .align = sizeof(long),
		.get = genregs_get, .set = genregs_set
	},
	[REGSET_FP] = {
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct user_i387_struct) / sizeof(long),
		.size = sizeof(long), .align = sizeof(long),
		.active = regset_xregset_fpregs_active, .get = xfpregs_get, .set = xfpregs_set
	},
	[REGSET_XSTATE] = {
		.core_note_type = NT_X86_XSTATE,
		.size = sizeof(u64), .align = sizeof(u64),
		.active = xstateregs_active, .get = xstateregs_get,
		.set = xstateregs_set
	},
	[REGSET_IOPERM64] = {
		.core_note_type = NT_386_IOPERM,
		.n = IO_BITMAP_LONGS,
		.size = sizeof(long), .align = sizeof(long),
		.active = ioperm_active, .get = ioperm_get
	},
};

static const struct user_regset_view user_x86_64_view = {
	.name = "x86_64", .e_machine = EM_X86_64,
	.regsets = x86_64_regsets, .n = ARRAY_SIZE(x86_64_regsets)
};

#else  /* CONFIG_X86_32 */

#define user_regs_struct32	user_regs_struct
#define genregs32_get		genregs_get
#define genregs32_set		genregs_set

#endif	/* CONFIG_X86_64 */

#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
struct user_desc {
	unsigned int  entry_number;
	unsigned int  base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit:1;
	unsigned int  contents:2;
	unsigned int  read_exec_only:1;
	unsigned int  limit_in_pages:1;
	unsigned int  seg_not_present:1;
	unsigned int  useable:1;
#ifdef __x86_64__
	/*
	 * Because this bit is not present in 32-bit user code, user
	 * programs can pass uninitialized values here.  Therefore, in
	 * any context in which a user_desc comes from a 32-bit program,
	 * the kernel must act as though lm == 0, regardless of the
	 * actual value.
	 */
	unsigned int  lm:1;
#endif
};

static struct user_regset x86_32_regsets[] = {
	[REGSET_GENERAL] = {
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct user_regs_struct32) / sizeof(u32),
		.size = sizeof(u32), .align = sizeof(u32),
		.get = genregs32_get, .set = genregs32_set
	},
	[REGSET_FP] = {
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct user_i387_ia32_struct) / sizeof(u32),
		.size = sizeof(u32), .align = sizeof(u32),
		.active = regset_fpregs_active, .get = fpregs_get, .set = fpregs_set
	},
	[REGSET_XFP] = {
		.core_note_type = NT_PRXFPREG,
		.n = sizeof(struct user32_fxsr_struct) / sizeof(u32),
		.size = sizeof(u32), .align = sizeof(u32),
		.active = regset_xregset_fpregs_active, .get = xfpregs_get, .set = xfpregs_set
	},
	[REGSET_XSTATE] = {
		.core_note_type = NT_X86_XSTATE,
		.size = sizeof(u64), .align = sizeof(u64),
		.active = xstateregs_active, .get = xstateregs_get,
		.set = xstateregs_set
	},
	[REGSET_TLS] = {
		.core_note_type = NT_386_TLS,
		.n = GDT_ENTRY_TLS_ENTRIES, .bias = GDT_ENTRY_TLS_MIN,
		.size = sizeof(struct user_desc),
		.align = sizeof(struct user_desc),
	},
	[REGSET_IOPERM32] = {
		.core_note_type = NT_386_IOPERM,
		.n = IO_BITMAP_BYTES / sizeof(u32),
		.size = sizeof(u32), .align = sizeof(u32),
		.active = ioperm_active, .get = ioperm_get
	},
};

static const struct user_regset_view user_x86_32_view = {
	.name = "i386", .e_machine = EM_386,
	.regsets = x86_32_regsets, .n = ARRAY_SIZE(x86_32_regsets)
};
#endif

/*
 * This represents bytes 464..511 in the memory layout exported through
 * the REGSET_XSTATE interface.
 */
u64 xstate_fx_sw_bytes[USER_XSTATE_FX_SW_WORDS];

/*
 * Called by FPU code
 * Damn FPU!
 */
void __init update_regset_xstate_info(unsigned int size, u64 xstate_mask)
{
#ifdef CONFIG_X86_64
	x86_64_regsets[REGSET_XSTATE].n = size / sizeof(u64);
#endif
#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
	x86_32_regsets[REGSET_XSTATE].n = size / sizeof(u64);
#endif
	xstate_fx_sw_bytes[USER_XSTATE_XCR0_WORD] = xstate_mask;
}

const struct user_regset_view *task_user_regset_view(struct task_struct *task)
{
#ifdef CONFIG_IA32_EMULATION
	if (!user_64bit_mode(task_pt_regs(task)))
#endif
#if defined CONFIG_X86_32 || defined CONFIG_IA32_EMULATION
		return &user_x86_32_view;
#endif
#ifdef CONFIG_X86_64
	return &user_x86_64_view;
#endif
}


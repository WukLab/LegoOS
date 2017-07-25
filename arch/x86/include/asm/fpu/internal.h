#ifndef _ASM_X86_FPU_INTERNAL_H_
#define _ASM_X86_FPU_INTERNAL_H_

#include <asm/alternative.h>
#include <asm/fpu/api.h>
#include <asm/fpu/xstate.h>

/*
 * High level FPU state handling functions:
 */
extern void fpu__activate_curr(struct fpu *fpu);
extern void fpu__activate_fpstate_read(struct fpu *fpu);
extern void fpu__activate_fpstate_write(struct fpu *fpu);
extern void fpu__current_fpstate_write_begin(void);
extern void fpu__current_fpstate_write_end(void);
extern void fpu__save(struct fpu *fpu);
extern void fpu__restore(struct fpu *fpu);
extern int  fpu__restore_sig(void __user *buf, int ia32_frame);
extern void fpu__drop(struct fpu *fpu);
extern int  fpu__copy(struct fpu *dst_fpu, struct fpu *src_fpu);
extern void fpu__clear(struct fpu *fpu);
extern int  fpu__exception_code(struct fpu *fpu, int trap_nr);
extern int  dump_fpu(struct pt_regs *ptregs);

/*
 * Boot time FPU initialization functions:
 */
extern void fpu__init_cpu(void);
extern void fpu__init_system_xstate(void);
extern void fpu__init_cpu_xstate(void);
extern void fpu__init_system(struct cpu_info *c);
extern void fpu__init_check_bugs(void);
extern void fpu__resume_cpu(void);
extern u64 fpu__get_supported_xfeatures_mask(void);

/*
 * fpstate handling functions:
 */

extern union fpregs_state init_fpstate;

extern void fpstate_init(union fpregs_state *state);

/*
 * Debugging facility:
 */
#ifdef CONFIG_X86_DEBUG_FPU
# define WARN_ON_FPU(x) WARN_ON_ONCE(x)
#else
# define WARN_ON_FPU(x) ({ (void)(x); 0; })
#endif

/*
 * FPU related CPU feature flag helper routines:
 */
static __always_inline __pure bool use_eager_fpu(void)
{
	return cpu_has(X86_FEATURE_EAGER_FPU);
}

static __always_inline __pure bool use_xsaveopt(void)
{
	return cpu_has(X86_FEATURE_XSAVEOPT);
}

static __always_inline __pure bool use_xsave(void)
{
	return cpu_has(X86_FEATURE_XSAVE);
}

static __always_inline __pure bool use_fxsr(void)
{
	return cpu_has(X86_FEATURE_FXSR);
}

/* These macros all use (%edi)/(%rdi) as the single memory argument. */
#define XSAVE		".byte " REX_PREFIX "0x0f,0xae,0x27"
#define XSAVEOPT	".byte " REX_PREFIX "0x0f,0xae,0x37"
#define XSAVES		".byte " REX_PREFIX "0x0f,0xc7,0x2f"
#define XRSTOR		".byte " REX_PREFIX "0x0f,0xae,0x2f"
#define XRSTORS		".byte " REX_PREFIX "0x0f,0xc7,0x1f"

#define XSTATE_OP(op, st, lmask, hmask, err)				\
	asm volatile("1:" op "\n\t"					\
		     "xor %[err], %[err]\n"				\
		     "2:\n\t"						\
		     ".pushsection .fixup,\"ax\"\n\t"			\
		     "3: movl $-2,%[err]\n\t"				\
		     "jmp 2b\n\t"					\
		     ".popsection\n\t"					\
		     _ASM_EXTABLE(1b, 3b)				\
		     : [err] "=r" (err)					\
		     : "D" (st), "m" (*st), "a" (lmask), "d" (hmask)	\
		     : "memory")

/*
 * If XSAVES is enabled, it replaces XSAVEOPT because it supports a compact
 * format and supervisor states in addition to modified optimization in
 * XSAVEOPT.
 *
 * Otherwise, if XSAVEOPT is enabled, XSAVEOPT replaces XSAVE because XSAVEOPT
 * supports modified optimization which is not supported by XSAVE.
 *
 * We use XSAVE as a fallback.
 *
 * The 661 label is defined in the ALTERNATIVE* macros as the address of the
 * original instruction which gets replaced. We need to use it here as the
 * address of the instruction where we might get an exception at.
 */
#define XSTATE_XSAVE(st, lmask, hmask, err)				\
	asm volatile(ALTERNATIVE_2(XSAVE,				\
				   XSAVEOPT, X86_FEATURE_XSAVEOPT,	\
				   XSAVES,   X86_FEATURE_XSAVES)	\
		     "\n"						\
		     "xor %[err], %[err]\n"				\
		     "3:\n"						\
		     ".pushsection .fixup,\"ax\"\n"			\
		     "4: movl $-2, %[err]\n"				\
		     "jmp 3b\n"						\
		     ".popsection\n"					\
		     _ASM_EXTABLE(661b, 4b)				\
		     : [err] "=r" (err)					\
		     : "D" (st), "m" (*st), "a" (lmask), "d" (hmask)	\
		     : "memory")

/*
 * Use XRSTORS to restore context if it is enabled. XRSTORS supports compact
 * XSAVE area format.
 */
#define XSTATE_XRESTORE(st, lmask, hmask, err)				\
	asm volatile(ALTERNATIVE(XRSTOR,				\
				 XRSTORS, X86_FEATURE_XSAVES)		\
		     "\n"						\
		     "xor %[err], %[err]\n"				\
		     "3:\n"						\
		     ".pushsection .fixup,\"ax\"\n"			\
		     "4: movl $-2, %[err]\n"				\
		     "jmp 3b\n"						\
		     ".popsection\n"					\
		     _ASM_EXTABLE(661b, 4b)				\
		     : [err] "=r" (err)					\
		     : "D" (st), "m" (*st), "a" (lmask), "d" (hmask)	\
		     : "memory")

/*
 * This function is called only during boot time when x86 caps are not set
 * up and alternative can not be used yet.
 */
static inline void copy_xregs_to_kernel_booting(struct xregs_state *xstate)
{
	u64 mask = -1;
	u32 lmask = mask;
	u32 hmask = mask >> 32;
	int err;

	if (cpu_has(X86_FEATURE_XSAVES))
		XSTATE_OP(XSAVES, xstate, lmask, hmask, err);
	else
		XSTATE_OP(XSAVE, xstate, lmask, hmask, err);

	/* We should never fault when copying to a kernel buffer: */
	WARN_ON_FPU(err);
}

/*
 * This function is called only during boot time when x86 caps are not set
 * up and alternative can not be used yet.
 */
static inline void copy_kernel_to_xregs_booting(struct xregs_state *xstate)
{
	u64 mask = -1;
	u32 lmask = mask;
	u32 hmask = mask >> 32;
	int err;

	if (cpu_has(X86_FEATURE_XSAVES))
		XSTATE_OP(XRSTORS, xstate, lmask, hmask, err);
	else
		XSTATE_OP(XRSTOR, xstate, lmask, hmask, err);

	/* We should never fault when copying from a kernel buffer: */
	WARN_ON_FPU(err);
}

/*
 * Save processor xstate to xsave area.
 */
static inline void copy_xregs_to_kernel(struct xregs_state *xstate)
{
	u64 mask = -1;
	u32 lmask = mask;
	u32 hmask = mask >> 32;
	int err;

	XSTATE_XSAVE(xstate, lmask, hmask, err);

	/* We should never fault when copying to a kernel buffer: */
	WARN_ON_FPU(err);
}

static inline void copy_fxregs_to_kernel(struct fpu *fpu)
{
	if (IS_ENABLED(CONFIG_X86_32))
		asm volatile( "fxsave %[fx]" : [fx] "=m" (fpu->state.fxsave));
	else if (IS_ENABLED(CONFIG_AS_FXSAVEQ))
		asm volatile("fxsaveq %[fx]" : [fx] "=m" (fpu->state.fxsave));
	else {
		/* Using "rex64; fxsave %0" is broken because, if the memory
		 * operand uses any extended registers for addressing, a second
		 * REX prefix will be generated (to the assembler, rex64
		 * followed by semicolon is a separate instruction), and hence
		 * the 64-bitness is lost.
		 *
		 * Using "fxsaveq %0" would be the ideal choice, but is only
		 * supported starting with gas 2.16.
		 *
		 * Using, as a workaround, the properly prefixed form below
		 * isn't accepted by any binutils version so far released,
		 * complaining that the same type of prefix is used twice if
		 * an extended register is needed for addressing (fix submitted
		 * to mainline 2005-11-21).
		 *
		 *  asm volatile("rex64/fxsave %0" : "=m" (fpu->state.fxsave));
		 *
		 * This, however, we can work around by forcing the compiler to
		 * select an addressing mode that doesn't require extended
		 * registers.
		 */
		asm volatile( "rex64/fxsave (%[fx])"
			     : "=m" (fpu->state.fxsave)
			     : [fx] "R" (&fpu->state.fxsave));
	}
}

/*
 * These must be called with preempt disabled. Returns
 * 'true' if the FPU state is still intact and we can
 * keep registers active.
 *
 * The legacy FNSAVE instruction cleared all FPU state
 * unconditionally, so registers are essentially destroyed.
 * Modern FPU state can be kept in registers, if there are
 * no pending FP exceptions.
 */
static inline int copy_fpregs_to_fpstate(struct fpu *fpu)
{
	if (likely(use_xsave())) {
		copy_xregs_to_kernel(&fpu->state.xsave);
		return 1;
	}

	if (likely(use_fxsr())) {
		copy_fxregs_to_kernel(fpu);
		return 1;
	}

	/*
	 * Legacy FPU register saving, FNSAVE always clears FPU registers,
	 * so we have to mark them inactive:
	 */
	asm volatile("fnsave %[fp]; fwait" : [fp] "=m" (fpu->state.fsave));

	return 0;
}

/*
 * Restore processor xstate from xsave area.
 */
static inline void copy_kernel_to_xregs(struct xregs_state *xstate, u64 mask)
{
	u32 lmask = mask;
	u32 hmask = mask >> 32;
	int err;

	XSTATE_XRESTORE(xstate, lmask, hmask, err);

	/* We should never fault when copying from a kernel buffer: */
	WARN_ON_FPU(err);
}

#define check_insn(insn, output, input...)				\
({									\
	int err;							\
	asm volatile("1:" #insn "\n\t"					\
		     "2:\n"						\
		     ".section .fixup,\"ax\"\n"				\
		     "3:  movl $-1,%[err]\n"				\
		     "    jmp  2b\n"					\
		     ".previous\n"					\
		     _ASM_EXTABLE(1b, 3b)				\
		     : [err] "=r" (err), output				\
		     : "0"(0), input);					\
	err;								\
})

static inline void copy_kernel_to_fxregs(struct fxregs_state *fx)
{
	int err;

	if (IS_ENABLED(CONFIG_X86_32)) {
		err = check_insn(fxrstor %[fx], "=m" (*fx), [fx] "m" (*fx));
	} else {
		if (IS_ENABLED(CONFIG_AS_FXSAVEQ)) {
			err = check_insn(fxrstorq %[fx], "=m" (*fx), [fx] "m" (*fx));
		} else {
			/* See comment in copy_fxregs_to_kernel() below. */
			err = check_insn(rex64/fxrstor (%[fx]), "=m" (*fx), [fx] "R" (fx), "m" (*fx));
		}
	}
	/* Copying from a kernel buffer to FPU registers should never fail: */
	WARN_ON_FPU(err);
}

static inline void copy_kernel_to_fregs(struct fregs_state *fx)
{
	int err = check_insn(frstor %[fx], "=m" (*fx), [fx] "m" (*fx));

	WARN_ON_FPU(err);
}

static inline void copy_kernel_to_fpregs(union fpregs_state *fpstate)
{
	if (use_xsave()) {
		copy_kernel_to_xregs(&fpstate->xsave, -1);
	} else {
		if (use_fxsr())
			copy_kernel_to_fxregs(&fpstate->fxsave);
		else
			copy_kernel_to_fregs(&fpstate->fsave);
	}
}

/*
 * FPU context switch related helper methods:
 */

DECLARE_PER_CPU(struct fpu *, fpu_fpregs_owner_ctx);

/*
 * Must be run with preemption disabled: this clears the fpu_fpregs_owner_ctx,
 * on this CPU.
 *
 * This will disable any lazy FPU state restore of the current FPU state,
 * but if the current thread owns the FPU, it will still be saved by.
 */
static inline void __cpu_disable_lazy_restore(unsigned int cpu)
{
	per_cpu(fpu_fpregs_owner_ctx, cpu) = NULL;
}

static inline int fpu_want_lazy_restore(struct fpu *fpu, unsigned int cpu)
{
	return fpu == this_cpu_read(fpu_fpregs_owner_ctx) && cpu == fpu->last_cpu;
}

/*
 * Wrap lazy FPU TS handling in a 'hw fpregs activation/deactivation'
 * idiom, which is then paired with the sw-flag (fpregs_active) later on:
 */

static inline void __fpregs_activate_hw(void)
{
	if (!use_eager_fpu())
		clts();
}

static inline void __fpregs_deactivate_hw(void)
{
	if (!use_eager_fpu())
		stts();
}

/* Must be paired with a 'clts' (fpregs_activate_hw()) before! */
static inline void __fpregs_activate(struct fpu *fpu)
{
	WARN_ON_FPU(fpu->fpregs_active);

	fpu->fpregs_active = 1;
	this_cpu_write(fpu_fpregs_owner_ctx, fpu);
}

/* Must be paired with an 'stts' (fpregs_deactivate_hw()) after! */
static inline void __fpregs_deactivate(struct fpu *fpu)
{
	WARN_ON_FPU(!fpu->fpregs_active);

	fpu->fpregs_active = 0;
	this_cpu_write(fpu_fpregs_owner_ctx, NULL);
}

/*
 * Encapsulate the CR0.TS handling together with the
 * software flag.
 *
 * These generally need preemption protection to work,
 * do try to avoid using these on their own.
 */
static inline void fpregs_activate(struct fpu *fpu)
{
	__fpregs_activate_hw();
	__fpregs_activate(fpu);
}

static inline void fpregs_deactivate(struct fpu *fpu)
{
	__fpregs_deactivate(fpu);
	__fpregs_deactivate_hw();
}

/*
 * MXCSR and XCR definitions:
 */

extern unsigned int mxcsr_feature_mask;

#define XCR_XFEATURE_ENABLED_MASK	0x00000000

static inline u64 xgetbv(u32 index)
{
	u32 eax, edx;

	asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
		     : "=a" (eax), "=d" (edx)
		     : "c" (index));
	return eax + ((u64)edx << 32);
}

static inline void xsetbv(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	asm volatile(".byte 0x0f,0x01,0xd1" /* xsetbv */
		     : : "a" (eax), "d" (edx), "c" (index));
}

#endif /* _ASM_X86_FPU_INTERNAL_H_ */

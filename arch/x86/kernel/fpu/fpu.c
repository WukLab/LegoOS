#include <asm/asm.h>
#include <asm/processor.h>
#include <lego/kernel.h>
#include <asm/fpu/internal.h>

/*
 * Represents the initial FPU state. It's mostly (but not completely) zeroes,
 * depending on the FPU hardware format:
 */
union fpregs_state init_fpstate __read_mostly;

static inline void fpstate_init_fxstate(struct fxregs_state *fx)
{
	fx->cwd = 0x37f;
	fx->mxcsr = MXCSR_DEFAULT;
}

/*
 * Legacy x87 fpstate state init:
 */
static inline void fpstate_init_fstate(struct fregs_state *fp)
{
	fp->cwd = 0xffff037fu;
	fp->swd = 0xffff0000u;
	fp->twd = 0xffffffffu;
	fp->fos = 0xffff0000u;
}

static void fpstate_init(union fpregs_state *state)
{
	if (!cpu_has(X86_FEATURE_FPU))
		return;

	memset(state, 0, fpu_kernel_xstate_size);

	/*
	 * XRSTORS requires that this bit is set in xcomp_bv, or
	 * it will #GP. Make sure it is replaced after the memset().
	 */
	if (cpu_has(X86_FEATURE_XSAVES))
		state->xsave.header.xcomp_bv = XCOMP_BV_COMPACTED_FORMAT |
					       xfeatures_mask;

	if (cpu_has(X86_FEATURE_FXSR))
		fpstate_init_fxstate(&state->fxsave);
	else
		fpstate_init_fstate(&state->fsave);
}

/*
 * Boot time FPU feature detection code:
 */
unsigned int mxcsr_feature_mask __read_mostly = 0xffffffffu;

static void __init fpu__init_system_mxcsr(void)
{
	unsigned int mask = 0;

	if (cpu_has(X86_FEATURE_FXSR)) {
		/* Static because GCC does not get 16-byte stack alignment right: */
		static struct fxregs_state fxregs __initdata;

		asm volatile("fxsave %0" : "+m" (fxregs));

		mask = fxregs.mxcsr_mask;

		/*
		 * If zero then use the default features mask,
		 * which has all features set, except the
		 * denormals-are-zero feature bit:
		 */
		if (mask == 0)
			mask = 0x0000ffbf;
	}
	mxcsr_feature_mask &= mask;
}

/*
 * Once per bootup FPU initialization sequences that will run on most x86 CPUs:
 */
static void __init fpu__init_system_generic(void)
{
	/*
	 * Set up the legacy init FPU context. (xstate init might overwrite this
	 * with a more modern format, if the CPU supports it.)
	 */
	fpstate_init(&init_fpstate);

	fpu__init_system_mxcsr();
}

/*
 * Set up the user and kernel xstate sizes based on the legacy FPU context size.
 *
 * We set this up first, and later it will be overwritten by
 * fpu__init_system_xstate() if the CPU knows about xstates.
 */
static void __init fpu__init_system_xstate_size_legacy(void)
{
	static int on_boot_cpu __initdata = 1;
	struct cpu_info *c = &default_cpu_info;

	WARN_ON(!on_boot_cpu);
	on_boot_cpu = 0;

	/*
	 * Note that xstate sizes might be overwritten later during
	 * fpu__init_system_xstate().
	 */

	if (!cpu_has(X86_FEATURE_FPU)) {
		/*
		 * Disable xsave as we do not support it if i387
		 * emulation is enabled.
		 */
		cpu_clear_cap(c, X86_FEATURE_XSAVE);
		cpu_clear_cap(c, X86_FEATURE_XSAVEOPT);
		fpu_kernel_xstate_size = sizeof(struct swregs_state);
	} else {
		if (cpu_has(X86_FEATURE_FXSR))
			fpu_kernel_xstate_size =
				sizeof(struct fxregs_state);
		else
			fpu_kernel_xstate_size =
				sizeof(struct fregs_state);
	}

	fpu_user_xstate_size = fpu_kernel_xstate_size;
}

#define XSTATE_CPUID		0x0000000d

/*
 * Enable and initialize the xsave feature.
 * Called once per system bootup.
 */
void __init fpu__init_system_xstate(void)
{
	unsigned int eax, ebx, ecx, edx;
	static int on_boot_cpu __initdata = 1;
	int err;

	WARN_ON(!on_boot_cpu);
	on_boot_cpu = 0;

	if (!cpu_has(X86_FEATURE_XSAVE)) {
		pr_info("x86/fpu: Legacy x87 FPU detected.\n");
		return;
	}

	if (default_cpu_info.cpuid_level < XSTATE_CPUID) {
		WARN_ON(1);
		return;
	}

	cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	xfeatures_mask = eax + ((u64)edx << 32);

	if ((xfeatures_mask & XFEATURE_MASK_FPSSE) != XFEATURE_MASK_FPSSE) {
		/*
		 * This indicates that something really unexpected happened
		 * with the enumeration.  Disable XSAVE and try to continue
		 * booting without it.  This is too early to BUG().
		 */
		pr_err("x86/fpu: FP/SSE not present amongst the CPU's xstate features: 0x%llx.\n", xfeatures_mask);
		goto out_disable;
	}

	xfeatures_mask &= fpu__get_supported_xfeatures_mask();

	/* Enable xstate instructions to be able to continue with initialization: */
	fpu__init_cpu_xstate();
	err = init_xstate_size();
	if (err)
		goto out_disable;

	/*
	 * Update info used for ptrace frames; use standard-format size and no
	 * supervisor xstates:
	 */
	update_regset_xstate_info(fpu_user_xstate_size,	xfeatures_mask & ~XFEATURE_MASK_SUPERVISOR);

	fpu__init_prepare_fx_sw_frame();
	setup_init_fpu_buf();
	setup_xstate_comp();
	print_xstate_offset_size();

	pr_info("x86/fpu: Enabled xstate features 0x%llx, context size is %d bytes, using '%s' format.\n",
		xfeatures_mask,
		fpu_kernel_xstate_size,
		cpu_has(X86_FEATURE_XSAVES) ? "compacted" : "standard");
	return;

out_disable:
	/* something went wrong, try to boot without any XSAVE support */
	fpu__init_disable_system_xstate();
}

/*
 * Pick the FPU context switching strategy:
 *
 * When eagerfpu is AUTO or ENABLE, we ensure it is ENABLE if either of
 * the following is true:
 *
 * (1) the cpu has xsaveopt, as it has the optimization and doing eager
 *     FPU switching has a relatively low cost compared to a plain xsave;
 * (2) the cpu has xsave features (e.g. MPX) that depend on eager FPU
 *     switching. Should the kernel boot with noxsaveopt, we support MPX
 *     with eager FPU switching at a higher cost.
 */
static void __init fpu__init_system_ctx_switch(void)
{
	static bool on_boot_cpu __initdata = 1;

	WARN_ON(!on_boot_cpu);
	on_boot_cpu = 0;

	WARN_ON(current->thread.fpu.fpstate_active);

	if (cpu_has(X86_FEATURE_XSAVEOPT) && eagerfpu != DISABLE)
		eagerfpu = ENABLE;

	if (xfeatures_mask & XFEATURE_MASK_EAGER)
		eagerfpu = ENABLE;

	if (eagerfpu == ENABLE)
		cpu_set_cap(X86_FEATURE_EAGER_FPU);

	printk(KERN_INFO "x86/fpu: Using '%s' FPU context switches.\n", eagerfpu == ENABLE ? "eager" : "lazy");
}

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/ctype.h>
#include <lego/sched.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/delay.h>

#include <asm/asm.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/pgtable.h>
#include <asm/syscalls.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <asm/fpu/internal.h>

__u32 cpu_caps_cleared[NCAPINTS + NBUGINTS];
__u32 cpu_caps_set[NCAPINTS + NBUGINTS];

/* Everything about CPU, filled at early boot */
struct cpu_info default_cpu_info __read_mostly;

static const struct cpu_vendor default_cpu = {
	.c_init		= NULL,
	.c_vendor	= "Unknown",
	.c_x86_vendor	= X86_VENDOR_UNKNOWN,
};

static const struct cpu_vendor *this_cpu = &default_cpu;

static unsigned int x86_family(unsigned int sig)
{
	unsigned int x86;

	x86 = (sig >> 8) & 0xf;

	if (x86 == 0xf)
		x86 += (sig >> 20) & 0xff;

	return x86;
}

static unsigned int x86_model(unsigned int sig)
{
	unsigned int fam, model;

	 fam = x86_family(sig);

	model = (sig >> 4) & 0xf;

	if (fam >= 0x6)
		model += ((sig >> 16) & 0xf) << 4;

	return model;
}

static unsigned int x86_stepping(unsigned int sig)
{
	return sig & 0xf;
}

/*
 * Some CPU features depend on higher CPUID levels, which may not always
 * be available due to CPUID level capping or broken virtualization
 * software.  Add those features to this table to auto-disable them.
 */
struct cpuid_dependent_feature {
	u32 feature;
	u32 level;
};

static const struct cpuid_dependent_feature
cpuid_dependent_features[] = {
	{ X86_FEATURE_MWAIT,		0x00000005 },
	{ X86_FEATURE_DCA,		0x00000009 },
	{ X86_FEATURE_XSAVE,		0x0000000d },
	{ 0, 0 }
};

static void filter_cpuid_features(struct cpu_info *c, bool warn)
{
	const struct cpuid_dependent_feature *df;

	for (df = cpuid_dependent_features; df->feature; df++) {

		if (!cpu_has(df->feature))
			continue;
		/*
		 * Note: cpuid_level is set to -1 if unavailable, but
		 * extended_extended_level is set to 0 if unavailable
		 * and the legitimate extended levels are all negative
		 * when signed; hence the weird messing around with
		 * signs here...
		 */
		if (!((s32)df->level < 0 ?
		     (u32)df->level > (u32)c->extended_cpuid_level :
		     (s32)df->level > (s32)c->cpuid_level))
			continue;

		clear_cpu_cap(c, df->feature);
		if (!warn)
			continue;

		pr_warn("CPU: CPU feature " X86_CAP_FMT " disabled, no CPUID level 0x%x\n",
			x86_cap_flag(df->feature), df->level);
	}
}

static const struct cpu_vendor *cpu_vendors[X86_VENDOR_NUM] = {};

static void get_cpu_vendor(struct cpu_info *c)
{
	char *v = c->x86_vendor_id;
	int i;

	for (i = 0; i < X86_VENDOR_NUM; i++) {
		if (!cpu_vendors[i])
			break;

		if (!strcmp(v, cpu_vendors[i]->c_ident[0]) ||
		    (cpu_vendors[i]->c_ident[1] &&
		     !strcmp(v, cpu_vendors[i]->c_ident[1]))) {

			this_cpu = cpu_vendors[i];
			c->x86_vendor = this_cpu->c_x86_vendor;
			return;
		}
	}

	printk(KERN_ERR "CPU: vendor_id '%s' unknown, using generic init.\n" \
			"CPU: Your system may be unstable.\n", v);
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	this_cpu = &default_cpu;
}

void get_cpu_cap(struct cpu_info *c)
{
	u32 eax, ebx, ecx, edx;

	/* Intel-defined flags: level 0x00000001 */
	if (c->cpuid_level >= 0x00000001) {
		cpuid(0x00000001, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_1_ECX] = ecx;
		c->x86_capability[CPUID_1_EDX] = edx;
	}

	/* Thermal and Power Management Leaf: level 0x00000006 (eax) */
	if (c->cpuid_level >= 0x00000006)
		c->x86_capability[CPUID_6_EAX] = cpuid_eax(0x00000006);

	/* Additional Intel-defined flags: level 0x00000007 */
	if (c->cpuid_level >= 0x00000007) {
		cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_7_0_EBX] = ebx;
		c->x86_capability[CPUID_7_ECX] = ecx;
	}

	/* Extended state features: level 0x0000000d */
	if (c->cpuid_level >= 0x0000000d) {
		cpuid_count(0x0000000d, 1, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_D_1_EAX] = eax;
	}

	/* Additional Intel-defined flags: level 0x0000000F */
	if (c->cpuid_level >= 0x0000000F) {

		/* QoS sub-leaf, EAX=0Fh, ECX=0 */
		cpuid_count(0x0000000F, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[CPUID_F_0_EDX] = edx;

		if (cpu_has(X86_FEATURE_CQM_LLC)) {
			/* will be overridden if occupancy monitoring exists */
			c->x86_cache_max_rmid = ebx;

			/* QoS sub-leaf, EAX=0Fh, ECX=1 */
			cpuid_count(0x0000000F, 1, &eax, &ebx, &ecx, &edx);
			c->x86_capability[CPUID_F_1_EDX] = edx;

			if ((cpu_has(X86_FEATURE_CQM_OCCUP_LLC)) ||
			      ((cpu_has(X86_FEATURE_CQM_MBM_TOTAL)) ||
			       (cpu_has(X86_FEATURE_CQM_MBM_LOCAL)))) {
				c->x86_cache_max_rmid = ecx;
				c->x86_cache_occ_scale = ebx;
			}
		} else {
			c->x86_cache_max_rmid = -1;
			c->x86_cache_occ_scale = -1;
		}
	}

	/* AMD-defined flags: level 0x80000001 */
	eax = cpuid_eax(0x80000000);
	c->extended_cpuid_level = eax;

	if ((eax & 0xffff0000) == 0x80000000) {
		if (eax >= 0x80000001) {
			cpuid(0x80000001, &eax, &ebx, &ecx, &edx);

			c->x86_capability[CPUID_8000_0001_ECX] = ecx;
			c->x86_capability[CPUID_8000_0001_EDX] = edx;
		}
	}

	if (c->extended_cpuid_level >= 0x80000007) {
		cpuid(0x80000007, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_8000_0007_EBX] = ebx;
		c->x86_power = edx;
	}

	if (c->extended_cpuid_level >= 0x80000008) {
		cpuid(0x80000008, &eax, &ebx, &ecx, &edx);

		c->x86_virt_bits = (eax >> 8) & 0xff;
		c->x86_phys_bits = eax & 0xff;
		c->x86_capability[CPUID_8000_0008_EBX] = ebx;
	}
#ifdef CONFIG_X86_32
	else if (cpu_has(X86_FEATURE_PAE) || cpu_has(X86_FEATURE_PSE36))
		c->x86_phys_bits = 36;
#endif

	if (c->extended_cpuid_level >= 0x8000000a)
		c->x86_capability[CPUID_8000_000A_EDX] = cpuid_edx(0x8000000a);

	init_scattered_cpuid_features(c);
}

static void get_model_name(struct cpu_info *c)
{
	unsigned int *v;
	char *p, *q, *s;

	if (c->extended_cpuid_level < 0x80000004)
		return;

	v = (unsigned int *)c->x86_model_id;
	cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
	cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
	cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
	c->x86_model_id[48] = 0;

	/* Trim whitespace */
	p = q = s = &c->x86_model_id[0];

	while (*p == ' ')
		p++;

	while (*p) {
		/* Note the last non-whitespace index */
		if (!isspace(*p))
			s = q;

		*q++ = *p++;
	}

	*(s + 1) = '\0';
}

u16 __read_mostly tlb_lli_4k[NR_INFO];
u16 __read_mostly tlb_lli_2m[NR_INFO];
u16 __read_mostly tlb_lli_4m[NR_INFO];
u16 __read_mostly tlb_lld_4k[NR_INFO];
u16 __read_mostly tlb_lld_2m[NR_INFO];
u16 __read_mostly tlb_lld_4m[NR_INFO];
u16 __read_mostly tlb_lld_1g[NR_INFO];

static void cpu_detect_tlb(struct cpu_info *c)
{
	if (this_cpu->c_detect_tlb)
		this_cpu->c_detect_tlb(c);

	pr_info("Last level iTLB entries: 4KB %d, 2MB %d, 4MB %d\n",
		tlb_lli_4k[ENTRIES], tlb_lli_2m[ENTRIES],
		tlb_lli_4m[ENTRIES]);

	pr_info("Last level dTLB entries: 4KB %d, 2MB %d, 4MB %d, 1GB %d\n",
		tlb_lld_4k[ENTRIES], tlb_lld_2m[ENTRIES],
		tlb_lld_4m[ENTRIES], tlb_lld_1g[ENTRIES]);
}

void print_cpu_info(struct cpu_info *c)
{
	const char *vendor = NULL;

	if (c->x86_vendor < X86_VENDOR_NUM) {
		vendor = this_cpu->c_vendor;
	} else {
		if (c->cpuid_level >= 0)
			vendor = c->x86_vendor_id;
	}

	if (vendor && !strstr(c->x86_model_id, vendor))
		printk(KERN_INFO "%s ", vendor);

	if (c->x86_model_id[0])
		printk(KERN_INFO "%s", c->x86_model_id);
	else
		printk(KERN_INFO "%d86", c->x86);

	printk(KERN_CONT " (family: 0x%x, model: 0x%x", c->x86, c->x86_model);

	if (c->x86_mask || c->cpuid_level >= 0)
		printk(KERN_CONT ", stepping: 0x%x)\n", c->x86_mask);
	else
		printk(KERN_CONT ")\n");
}

void cpu_detect(struct cpu_info *c)
{
	/* Get vendor name */
	cpuid(0x00000000, (unsigned int *)&c->cpuid_level,
	      (unsigned int *)&c->x86_vendor_id[0],
	      (unsigned int *)&c->x86_vendor_id[8],
	      (unsigned int *)&c->x86_vendor_id[4]);

	c->x86 = 4;
	/* Intel-defined flags: level 0x00000001 */
	if (c->cpuid_level >= 0x00000001) {
		u32 junk, tfms, cap0, misc;

		cpuid(0x00000001, &tfms, &misc, &junk, &cap0);
		c->x86		= x86_family(tfms);
		c->x86_model	= x86_model(tfms);
		c->x86_mask	= x86_stepping(tfms);

		if (cap0 & (1<<19)) {
			c->x86_clflush_size = ((misc >> 8) & 0xff) * 8;
			c->x86_cache_alignment = c->x86_clflush_size;
		}
	}
}

/*
 * Do minimum CPU detection early.
 * Fields really needed: vendor, cpuid_level, family, model, mask,
 * cache alignment.
 * The others are not touched to avoid unwanted side effects.
 *
 * WARNING: this function is only called on the BP.  Don't add code here
 * that is supposed to run on all CPUs.
 */
static void __init early_identify_cpu(struct cpu_info *c)
{
#ifdef CONFIG_X86_64
	c->x86_clflush_size = 64;
	c->x86_phys_bits = 36;
	c->x86_virt_bits = 48;
#else
	c->x86_clflush_size = 32;
	c->x86_phys_bits = 32;
	c->x86_virt_bits = 32;
#endif
	c->x86_cache_alignment = c->x86_clflush_size;

	memset(&c->x86_capability, 0, sizeof c->x86_capability);
	c->extended_cpuid_level = 0;

	/*
	 * We assume this cpu has CPUID present
	 * otherwise good luck.
	 */

	cpu_detect(c);
	get_cpu_vendor(c);
	get_cpu_cap(c);

	if (this_cpu->c_early_init)
		this_cpu->c_early_init(c);

	c->cpu_index = 0;
	filter_cpuid_features(c, true);

	if (this_cpu->c_bsp_init)
		this_cpu->c_bsp_init(c);

	setup_force_cpu_cap(X86_FEATURE_ALWAYS);

	if (c->x86_vendor != X86_VENDOR_AMD)
		setup_force_cpu_bug(X86_BUG_CPU_MELTDOWN);

	setup_force_cpu_bug(X86_BUG_SPECTRE_V1);
	setup_force_cpu_bug(X86_BUG_SPECTRE_V2);

	fpu__init_system(c);

#ifdef CONFIG_X86_32
	/*
	 * Regardless of whether PCID is enumerated, the SDM says
	 * that it can't be enabled in 32-bit mode.
	 */
	setup_clear_cpu_cap(X86_FEATURE_PCID);
#endif
}

/*
 * Detect CPU type and save basic information
 * about underlying CPU.
 */
void __init early_cpu_init(void)
{
	const struct cpu_vendor *const *v;
	struct cpu_info *c = &default_cpu_info;
	int count = 0;

	for (v = __x86_cpu_vendor_start; v < __x86_cpu_vendor_end; v++) {
		const struct cpu_vendor *cpuvendor = *v;

		if (count >= X86_VENDOR_NUM)
			break;
		cpu_vendors[count] = cpuvendor;
		count++;
	}
	early_identify_cpu(c);
}

/*
 * The NOPL instruction is supposed to exist on all CPUs of family >= 6;
 * unfortunately, that's not true in practice because of early VIA
 * chips and (more importantly) broken virtualizers that are not easy
 * to detect. In the latter case it doesn't even *fail* reliably, so
 * probing for it doesn't even work. Disable it completely on 32-bit
 * unless we can find a reliable way to detect all the broken cases.
 * Enable it explicitly on 64-bit for non-constant inputs of cpu_has().
 */
static void detect_nopl(struct cpu_info *c)
{
#ifdef CONFIG_X86_32
	clear_cpu_cap(c, X86_FEATURE_NOPL);
#else
	set_cpu_cap(c, X86_FEATURE_NOPL);
#endif
}

static void detect_null_seg_behavior(struct cpu_info *c)
{
#ifdef CONFIG_X86_64
	/*
	 * Empirically, writing zero to a segment selector on AMD does
	 * not clear the base, whereas writing zero to a segment
	 * selector on Intel does clear the base.  Intel's behavior
	 * allows slightly faster context switches in the common case
	 * where GS is unused by the prev and next threads.
	 *
	 * Since neither vendor documents this anywhere that I can see,
	 * detect it directly instead of hardcoding the choice by
	 * vendor.
	 *
	 * I've designated AMD's behavior as the "bug" because it's
	 * counterintuitive and less friendly.
	 */

	unsigned long old_base, tmp;
	rdmsrl(MSR_FS_BASE, old_base);
	wrmsrl(MSR_FS_BASE, 1);
	loadsegment(fs, 0);
	rdmsrl(MSR_FS_BASE, tmp);
	if (tmp != 0)
		set_cpu_bug(c, X86_BUG_NULL_SEG);
	wrmsrl(MSR_FS_BASE, old_base);
#endif
}

static void generic_identify(struct cpu_info *c)
{
	c->extended_cpuid_level = 0;

	cpu_detect(c);
	get_cpu_vendor(c);
	get_cpu_cap(c);
	cpu_detect_tlb(c);

	if (c->cpuid_level >= 0x00000001) {
		c->initial_apicid = (cpuid_ebx(1) >> 24) & 0xFF;
		c->phys_proc_id = c->initial_apicid;
	}

	get_model_name(c); /* Default name */

	detect_nopl(c);
	detect_null_seg_behavior(c);

	/*
	 * ESPFIX is a strange bug.  All real CPUs have it.  Paravirt
	 * systems that run Linux at CPL > 0 may or may not have the
	 * issue, but, even if they have the issue, there's absolutely
	 * nothing we can do about it because we can't use the real IRET
	 * instruction.
	 *
	 * NB: For the time being, only 32-bit kernels support
	 * X86_BUG_ESPFIX as such.  64-bit kernels directly choose
	 * whether to apply espfix using paravirt hooks.  If any
	 * non-paravirt system ever shows up that does *not* have the
	 * ESPFIX issue, we can change this.
	 */
#ifdef CONFIG_X86_32
	set_cpu_bug(c, X86_BUG_ESPFIX);
#endif
}

static void apply_forced_caps(struct cpu_info *c)
{
	int i;

	for (i = 0; i < NCAPINTS + NBUGINTS; i++) {
		c->x86_capability[i] &= ~cpu_caps_cleared[i];
		c->x86_capability[i] |= cpu_caps_set[i];
	}
}

/*
 * This does the hard work of actually picking apart the CPU stuff...
 */
void identify_cpu(struct cpu_info *c)
{
	c->loops_per_jiffy = loops_per_jiffy;
	c->x86_cache_size = -1;
	c->x86_vendor = X86_VENDOR_UNKNOWN;
	c->x86_model = c->x86_mask = 0;	/* So far unknown... */
	c->x86_vendor_id[0] = '\0'; /* Unset */
	c->x86_model_id[0] = '\0';  /* Unset */
	c->x86_max_cores = 1;
	c->x86_coreid_bits = 0;
	c->cu_id = 0xff;
#ifdef CONFIG_X86_64
	c->x86_clflush_size = 64;
	c->x86_phys_bits = 36;
	c->x86_virt_bits = 48;
#else
	c->cpuid_level = -1;	/* CPUID not detected */
	c->x86_clflush_size = 32;
	c->x86_phys_bits = 32;
	c->x86_virt_bits = 32;
#endif
	c->x86_cache_alignment = c->x86_clflush_size;
	memset(&c->x86_capability, 0, sizeof c->x86_capability);

	generic_identify(c);
	BUG_ON(!c->x86_model_id[0]);

	if (this_cpu->c_identify)
		this_cpu->c_identify(c);

	/* Clear/Set all flags overridden by options, after probe */
	apply_forced_caps(c);

	/*
	 * Vendor-specific initialization.  In this section we
	 * canonicalize the feature flags, meaning if there are
	 * features a certain CPU supports which CPUID doesn't
	 * tell us, CPUID claiming incorrect flags, or other bugs,
	 * we handle them here.
	 *
	 * At the end of this section, c->x86_capability better
	 * indicate the features this CPU genuinely supports!
	 */
	if (this_cpu->c_init)
		this_cpu->c_init(c);

	/*
	 * The vendor-specific functions might have changed features.
	 * Now we do "generic changes."
	 */

	/* Filter out anything that depends on CPUID levels we don't have */
	filter_cpuid_features(c, true);

	/*
	 * Clear/Set all flags overridden by options, need do it
	 * before following smp all cpus cap AND.
	 */
	apply_forced_caps(c);
}


void switch_to_new_gdt(int cpu)
{
	struct desc_ptr gdt_descr;

	gdt_descr.address = (long)get_cpu_gdt_table(cpu);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);

	/* Reload %gs per-cpu base */
	load_percpu_segment(cpu);
}

static void syscall_init(void)
{
	wrmsr(MSR_STAR, 0, (__USER32_CS << 16) | __KERNEL_CS);
	wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);

#ifdef CONFIG_IA32_EMULATION
	wrmsrl(MSR_CSTAR, (unsigned long)entry_SYSCALL_compat);
	/*
	 * This only works on Intel CPUs.
	 * On AMD CPUs these MSRs are 32-bit, CPU truncates MSR_IA32_SYSENTER_EIP.
	 * This does not cause SYSENTER to jump to the wrong location, because
	 * AMD doesn't allow SYSENTER in long mode (either 32- or 64-bit).
	 */
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)__KERNEL_CS);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, (u64)entry_SYSENTER_compat);
#else
	wrmsrl(MSR_CSTAR, (unsigned long)ignore_sysret);
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)GDT_ENTRY_INVALID_SEG);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP, 0ULL);
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, 0ULL);
#endif


	/* Flags to clear on syscall */
	wrmsrl(MSR_SYSCALL_MASK,
	       X86_EFLAGS_TF|X86_EFLAGS_DF|X86_EFLAGS_IF|
	       X86_EFLAGS_IOPL|X86_EFLAGS_AC|X86_EFLAGS_NT);
}

/*
 * The following percpu variables are hot.  Align current_task to
 * cacheline size such that they fall in the same cacheline.
 */
DEFINE_PER_CPU(struct task_struct *, current_task) ____cacheline_aligned =
	&init_task;

/*
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT
 * and IDT. We reload them nevertheless, this function acts as a
 * 'CPU state barrier', nothing should get across.
 */
void cpu_init(void)
{
	int cpu = smp_processor_id();
	struct tss_struct *tss;
	int i;

#if 0
	pr_debug("Initializing CPU#%d\n", cpu);
#endif

	/*
	 * Initialize the CR4 shadow before doing anything that could
	 * try to read it.
	 */
	cr4_init_shadow();

	cr4_clear_bits(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);

	/* Initialize the per-CPU GDT table */
	switch_to_new_gdt(cpu);
	loadsegment(fs, 0);

	/* All CPUs share the same IDT table */
	load_idt((const struct desc_ptr *)&idt_desc);

	memset(current->thread.tls_array, 0, GDT_ENTRY_TLS_ENTRIES * 8);
	syscall_init();

	wrmsrl(MSR_FS_BASE, 0);
	wrmsrl(MSR_KERNEL_GS_BASE, 0);
	barrier();

	tss = &per_cpu(cpu_tss, cpu);
	tss->x86_tss.io_bitmap_base = offsetof(struct tss_struct, io_bitmap);

	/*
	 * <= is required because the CPU will access up to
	 * 8 bits beyond the end of the IO permission bitmap.
	 */
	for (i = 0; i <= IO_BITMAP_LONGS; i++)
		tss->io_bitmap[i] = ~0UL;

	load_sp0(tss, &current->thread);

	/* Save the descriptor into the GDT table first */
	set_tss_desc(cpu, tss);

	/* Then setup the TR register to point to TSS segment */
	load_tr_desc();

	atomic_inc(&init_mm.mm_count);
	current->mm = &init_mm;
	current->active_mm = &init_mm;

	fpu__init_cpu();
}

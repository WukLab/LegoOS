/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/processor.h>

#include <lego/smp.h>
#include <lego/ctype.h>
#include <lego/sched.h>
#include <lego/string.h>
#include <lego/kernel.h>

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

static void get_basic_cpu_info(struct cpu_info *c)
{
	c->x86_clflush_size = 64;
	c->x86_phys_bits = 36;
	c->x86_virt_bits = 48;
	c->x86_cache_alignment = c->x86_clflush_size;

	memset(&c->x86_capability, 0, sizeof c->x86_capability);
	c->extended_cpuid_level = 0;

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

static void get_cpufeatures(struct cpu_info *c)
{
	u32 eax, ebx, ecx, edx;

	/* Intel-defined flags: level 0x00000001 */
	if (c->cpuid_level >= 0x00000001) {
		cpuid(0x00000001, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_1_ECX] = ecx;
		c->x86_capability[CPUID_1_EDX] = edx;
	}

	/* Additional Intel-defined flags: level 0x00000007 */
	if (c->cpuid_level >= 0x00000007) {
		cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx);

		c->x86_capability[CPUID_7_0_EBX] = ebx;

		c->x86_capability[CPUID_6_EAX] = cpuid_eax(0x00000006);
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
		c->x86_cache_max_rmid = -1;
		c->x86_cache_occ_scale = -1;
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

	if (c->extended_cpuid_level >= 0x8000000a)
		c->x86_capability[CPUID_8000_000A_EDX] = cpuid_edx(0x8000000a);
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

static void print_cpu_info(struct cpu_info *c)
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

	get_basic_cpu_info(c);
	get_cpu_vendor(c);
	get_cpufeatures(c);
	get_model_name(c);
	cpu_detect_tlb(c);

	print_cpu_info(c);
}

/*
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT
 * and IDT. We reload them nevertheless, this function acts as a
 * 'CPU state barrier', nothing should get across.
 */
void cpu_init(void)
{
	int i;
	int cpu = smp_processor_id();
	struct tss_struct *tss;

	/* TODO: per-cpu tss */
	tss = &cpu_tss;

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
}

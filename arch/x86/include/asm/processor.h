/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_PROCESSOR_H_
#define _ASM_X86_PROCESSOR_H_

#include <asm/tss.h>
#include <asm/smp.h>
#include <asm/desc.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <asm/alternative.h>
#include <asm/fpu/types.h>
#include <asm/thread_info.h>
#include <asm/processor-flags.h>
#include <asm/processor-features.h>

#include <lego/kernel.h>
#include <lego/percpu.h>

#ifdef CONFIG_X86_32
# define BASE_PREFETCH		""
# define ARCH_HAS_PREFETCH
#else
# define BASE_PREFETCH		"prefetcht0 %P1"
#endif

/*
 * Prefetch instructions for Pentium III (+) and AMD Athlon (+)
 *
 * It's not worth to care about 3dnow prefetches for the K6
 * because they are microcoded there and very slow.
 */
static inline void prefetch(const void *x)
{
	alternative_input(BASE_PREFETCH, "prefetchnta %P1",
			  X86_FEATURE_XMM,
			  "m" (*(const char *)x));
}

/*
 * 3dnow prefetch to get an exclusive cache line.
 * Useful for spinlocks to avoid one state transition in the
 * cache coherency protocol:
 */
static inline void prefetchw(const void *x)
{
	alternative_input(BASE_PREFETCH, "prefetchw %P1",
			  X86_FEATURE_3DNOWPREFETCH,
			  "m" (*(const char *)x));
}

/**
 * struct cpu_info
 *
 * Everything you want to know about your CPU.
 * It is filled at early boot stage.
 */
struct cpu_info {
	__u8			x86;		/* CPU family */
	__u8			x86_vendor;	/* CPU vendor */
	__u8			x86_model;
	__u8			x86_mask;
#ifdef CONFIG_X86_32
	char			wp_works_ok;	/* It doesn't on 386's */

	/* Problems on some 486Dx4's and old 386's: */
	char			rfu;
	char			pad0;
	char			pad1;
#else
	/* Number of 4K pages in DTLB/ITLB combined(in pages): */
	int			x86_tlbsize;
#endif
	__u8			x86_virt_bits;
	__u8			x86_phys_bits;
	/* CPUID returned core id bits: */
	__u8			x86_coreid_bits;
	__u8			cu_id;
	/* Max extended CPUID function supported: */
	__u32			extended_cpuid_level;
	/* Maximum supported CPUID level, -1=no CPUID: */
	int			cpuid_level;
	__u32			x86_capability[NCAPINTS + NBUGINTS];
	char			x86_vendor_id[16];
	char			x86_model_id[64];
	/* in KB - valid for CPUS which support this call: */
	int			x86_cache_size;
	int			x86_cache_alignment;	/* In bytes */
	/* Cache QoS architectural values: */
	int			x86_cache_max_rmid;	/* max index */
	int			x86_cache_occ_scale;	/* scale to bytes */
	int			x86_power;
	unsigned long		loops_per_jiffy;
	/* cpuid returned max cores value: */
	u16			 x86_max_cores;
	u16			apicid;
	u16			initial_apicid;
	u16			x86_clflush_size;
	/* number of cores as seen by the OS: */
	u16			booted_cores;
	/* Physical processor id: */
	u16			phys_proc_id;
	/* Logical processor id: */
	u16			logical_proc_id;
	/* Core id: */
	u16			cpu_core_id;
	/* Index into per_cpu list: */
	u16			cpu_index;
	u32			microcode;
};

#define X86_VENDOR_INTEL	0
#define X86_VENDOR_CYRIX	1
#define X86_VENDOR_AMD		2
#define X86_VENDOR_UMC		3
#define X86_VENDOR_CENTAUR	5
#define X86_VENDOR_TRANSMETA	7
#define X86_VENDOR_NSC		8
#define X86_VENDOR_NUM		9

#define X86_VENDOR_UNKNOWN	0xff

/*
 * X86 Vendor Hooks
 * - Intel (suppoted)
 * - and many others (no)
 */
struct cpu_vendor {
	const char	*c_vendor;
	/* some have two possibilities for cpuid string */
	const char	*c_ident[2];
	void            (*c_early_init)(struct cpu_info *);
	void		(*c_bsp_init)(struct cpu_info *);
	void		(*c_init)(struct cpu_info *);
	void		(*c_identify)(struct cpu_info *);
	void		(*c_detect_tlb)(struct cpu_info *);
	void		(*c_bsp_resume)(struct cpu_info *);
	int		c_x86_vendor;
};

#define cpu_vendor_register(cpu_vendorX) \
	static const struct cpu_vendor *const __cpu_vendor_##cpu_vendorX __used \
	__attribute__((__section__(".x86_cpu_vendor.init"))) = \
	&cpu_vendorX;

extern const struct cpu_vendor *const __x86_cpu_vendor_start[];
extern const struct cpu_vendor *const __x86_cpu_vendor_end[];

struct _tlb_table {
	unsigned char descriptor;
	char tlb_type;
	unsigned int entries;
	/* unsigned int ways; */
	char info[128];
};

enum tlb_infos {
	ENTRIES,
	NR_INFO
};

extern u16 __read_mostly tlb_lli_4k[NR_INFO];
extern u16 __read_mostly tlb_lli_2m[NR_INFO];
extern u16 __read_mostly tlb_lli_4m[NR_INFO];
extern u16 __read_mostly tlb_lld_4k[NR_INFO];
extern u16 __read_mostly tlb_lld_2m[NR_INFO];
extern u16 __read_mostly tlb_lld_4m[NR_INFO];
extern u16 __read_mostly tlb_lld_1g[NR_INFO];

typedef struct {
	unsigned long		seg;
} mm_segment_t;

struct thread_struct {
	/* Cached TLS descriptors: */
	struct desc_struct	tls_array[GDT_ENTRY_TLS_ENTRIES];

	unsigned long		sp0;
	unsigned long		sp;

	unsigned short		es;
	unsigned short		ds;
	unsigned short		fsindex;
	unsigned short		gsindex;

	/* thread synchronous flags */
	unsigned int		status;

	unsigned long		fsbase;
	unsigned long		gsbase;

	/* Fault info: */
	unsigned long		cr2;
	unsigned long		trap_nr;
	unsigned long		error_code;

	/* IO permissions: */
	unsigned long		*io_bitmap_ptr;
	unsigned long		iopl;
	/* Max allowed port in the bitmap, in bytes: */
	unsigned		io_bitmap_max;

	mm_segment_t		addr_limit;

	unsigned int		sig_on_uaccess_err:1;
	unsigned int		uaccess_err:1;	/* uaccess failed */

	/* Floating point and extended processor state */
	struct fpu		fpu;
	/*
	 * WARNING: 'fpu' is dynamically-sized.
	 * It *MUST* be at the end.
	 */
};

static inline void load_sp0(struct tss_struct *tss,
			    struct thread_struct *thread)
{
	tss->x86_tss.sp0 = thread->sp0;
}

static inline unsigned long current_top_of_stack(void)
{
	return this_cpu_read_stable(cpu_tss.x86_tss.sp0);
}

#define TOP_OF_INIT_STACK ((unsigned long)&init_stack + sizeof(init_stack) - \
			   TOP_OF_KERNEL_STACK_PADDING)

/*
 * User space process size. 47bits minus one guard page.  The guard
 * page is necessary on Intel CPUs: if a SYSCALL instruction is at
 * the highest possible canonical userspace address, then that
 * syscall will enter the kernel with a non-canonical return
 * address, and SYSRET will explode dangerously.  We avoid this
 * particular problem by preventing anything from being mapped
 * at the maximum canonical address.
 */
#define TASK_SIZE	((1UL << 47) - PAGE_SIZE)
#define STACK_TOP	TASK_SIZE
#define TASK_SIZE_MAX	TASK_SIZE
#define STACK_TOP_MAX	TASK_SIZE

#define INIT_THREAD  {						\
	.sp0			= TOP_OF_INIT_STACK,		\
	.addr_limit		= KERNEL_DS,			\
}

#define task_pt_regs(tsk)	((struct pt_regs *)(tsk)->thread.sp0 - 1)

void init_scattered_cpuid_features(struct cpu_info *c);
void get_cpu_cap(struct cpu_info *c);
void print_cpu_info(struct cpu_info *c);
void identify_cpu(struct cpu_info *c);
void detect_extended_topology(struct cpu_info *c);
void __init early_cpu_init(void);
void cpu_init(void);

/* entry.S, for syscall  */
asmlinkage void ignore_sysret(void);

struct pt_regs;
void start_thread(struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp);

int arch_dup_task_struct(struct task_struct *, struct task_struct *);
extern unsigned int fpu_kernel_xstate_size;
extern unsigned int fpu_user_xstate_size;

long do_arch_prctl(struct task_struct *task, int code, unsigned long addr);

#endif /* _ASM_X86_PROCESSOR_H_ */

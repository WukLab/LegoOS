/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_APIC_H_
#define _ASM_X86_APIC_H_

#include <asm/msr.h>
#include <asm/fixmap.h>
#include <asm/processor.h>
#include <asm/apic_types.h>

#include <lego/types.h>
#include <lego/cpumask.h>
#include <lego/compiler.h>

/*
 * Debugging macros
 */
#define APIC_QUIET   0
#define APIC_VERBOSE 1
#define APIC_DEBUG   2

/* Macros for apic_extnmi which controls external NMI masking */
#define APIC_EXTNMI_BSP		0 /* Default */
#define APIC_EXTNMI_ALL		1
#define APIC_EXTNMI_NONE	2

/*
 * Define the default level of output to be very little
 * This can be turned up by using apic=verbose for more
 * information and apic=debug for _lots_ of information.
 * apic_verbosity is defined in apic.c
 */
#define apic_printk(v, s, a...) do {       \
		if ((v) <= apic_verbosity) \
			pr_info(s, ##a);    \
	} while (0)

extern unsigned int apic_verbosity;

struct local_apic {

/*000*/	struct { u32 __reserved[4]; } __reserved_01;

/*010*/	struct { u32 __reserved[4]; } __reserved_02;

/*020*/	struct { /* APIC ID Register */
		u32   __reserved_1	: 24,
			phys_apic_id	:  4,
			__reserved_2	:  4;
		u32 __reserved[3];
	} id;

/*030*/	const
	struct { /* APIC Version Register */
		u32   version		:  8,
			__reserved_1	:  8,
			max_lvt		:  8,
			__reserved_2	:  8;
		u32 __reserved[3];
	} version;

/*040*/	struct { u32 __reserved[4]; } __reserved_03;

/*050*/	struct { u32 __reserved[4]; } __reserved_04;

/*060*/	struct { u32 __reserved[4]; } __reserved_05;

/*070*/	struct { u32 __reserved[4]; } __reserved_06;

/*080*/	struct { /* Task Priority Register */
		u32   priority	:  8,
			__reserved_1	: 24;
		u32 __reserved_2[3];
	} tpr;

/*090*/	const
	struct { /* Arbitration Priority Register */
		u32   priority	:  8,
			__reserved_1	: 24;
		u32 __reserved_2[3];
	} apr;

/*0A0*/	const
	struct { /* Processor Priority Register */
		u32   priority	:  8,
			__reserved_1	: 24;
		u32 __reserved_2[3];
	} ppr;

/*0B0*/	struct { /* End Of Interrupt Register */
		u32   eoi;
		u32 __reserved[3];
	} eoi;

/*0C0*/	struct { u32 __reserved[4]; } __reserved_07;

/*0D0*/	struct { /* Logical Destination Register */
		u32   __reserved_1	: 24,
			logical_dest	:  8;
		u32 __reserved_2[3];
	} ldr;

/*0E0*/	struct { /* Destination Format Register */
		u32   __reserved_1	: 28,
			model		:  4;
		u32 __reserved_2[3];
	} dfr;

/*0F0*/	struct { /* Spurious Interrupt Vector Register */
		u32	spurious_vector	:  8,
			apic_enabled	:  1,
			focus_cpu	:  1,
			__reserved_2	: 22;
		u32 __reserved_3[3];
	} svr;

/*100*/	struct { /* In Service Register */
/*170*/		u32 bitfield;
		u32 __reserved[3];
	} isr [8];

/*180*/	struct { /* Trigger Mode Register */
/*1F0*/		u32 bitfield;
		u32 __reserved[3];
	} tmr [8];

/*200*/	struct { /* Interrupt Request Register */
/*270*/		u32 bitfield;
		u32 __reserved[3];
	} irr [8];

/*280*/	union { /* Error Status Register */
		struct {
			u32   send_cs_error			:  1,
				receive_cs_error		:  1,
				send_accept_error		:  1,
				receive_accept_error		:  1,
				__reserved_1			:  1,
				send_illegal_vector		:  1,
				receive_illegal_vector		:  1,
				illegal_register_address	:  1,
				__reserved_2			: 24;
			u32 __reserved_3[3];
		} error_bits;
		struct {
			u32 errors;
			u32 __reserved_3[3];
		} all_errors;
	} esr;

/*290*/	struct { u32 __reserved[4]; } __reserved_08;

/*2A0*/	struct { u32 __reserved[4]; } __reserved_09;

/*2B0*/	struct { u32 __reserved[4]; } __reserved_10;

/*2C0*/	struct { u32 __reserved[4]; } __reserved_11;

/*2D0*/	struct { u32 __reserved[4]; } __reserved_12;

/*2E0*/	struct { u32 __reserved[4]; } __reserved_13;

/*2F0*/	struct { u32 __reserved[4]; } __reserved_14;

/*300*/	struct { /* Interrupt Command Register 1 */
		u32   vector			:  8,
			delivery_mode		:  3,
			destination_mode	:  1,
			delivery_status		:  1,
			__reserved_1		:  1,
			level			:  1,
			trigger			:  1,
			__reserved_2		:  2,
			shorthand		:  2,
			__reserved_3		:  12;
		u32 __reserved_4[3];
	} icr1;

/*310*/	struct { /* Interrupt Command Register 2 */
		union {
			u32   __reserved_1	: 24,
				phys_dest	:  4,
				__reserved_2	:  4;
			u32   __reserved_3	: 24,
				logical_dest	:  8;
		} dest;
		u32 __reserved_4[3];
	} icr2;

/*320*/	struct { /* LVT - Timer */
		u32   vector		:  8,
			__reserved_1	:  4,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			timer_mode	:  1,
			__reserved_3	: 14;
		u32 __reserved_4[3];
	} lvt_timer;

/*330*/	struct { /* LVT - Thermal Sensor */
		u32  vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			__reserved_3	: 15;
		u32 __reserved_4[3];
	} lvt_thermal;

/*340*/	struct { /* LVT - Performance Counter */
		u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			__reserved_3	: 15;
		u32 __reserved_4[3];
	} lvt_pc;

/*350*/	struct { /* LVT - LINT0 */
		u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			polarity	:  1,
			remote_irr	:  1,
			trigger		:  1,
			mask		:  1,
			__reserved_2	: 15;
		u32 __reserved_3[3];
	} lvt_lint0;

/*360*/	struct { /* LVT - LINT1 */
		u32   vector		:  8,
			delivery_mode	:  3,
			__reserved_1	:  1,
			delivery_status	:  1,
			polarity	:  1,
			remote_irr	:  1,
			trigger		:  1,
			mask		:  1,
			__reserved_2	: 15;
		u32 __reserved_3[3];
	} lvt_lint1;

/*370*/	struct { /* LVT - Error */
		u32   vector		:  8,
			__reserved_1	:  4,
			delivery_status	:  1,
			__reserved_2	:  3,
			mask		:  1,
			__reserved_3	: 15;
		u32 __reserved_4[3];
	} lvt_error;

/*380*/	struct { /* Timer Initial Count Register */
		u32   initial_count;
		u32 __reserved_2[3];
	} timer_icr;

/*390*/	const
	struct { /* Timer Current Count Register */
		u32   curr_count;
		u32 __reserved_2[3];
	} timer_ccr;

/*3A0*/	struct { u32 __reserved[4]; } __reserved_16;

/*3B0*/	struct { u32 __reserved[4]; } __reserved_17;

/*3C0*/	struct { u32 __reserved[4]; } __reserved_18;

/*3D0*/	struct { u32 __reserved[4]; } __reserved_19;

/*3E0*/	struct { /* Timer Divide Configuration Register */
		u32   divisor		:  4,
			__reserved_1	: 28;
		u32 __reserved_2[3];
	} timer_dcr;

/*3F0*/	struct { u32 __reserved[4]; } __reserved_20;

} __attribute__ ((packed));

#ifdef CONFIG_X86_32
 #define BAD_APICID 0xFFu
#else
 #define BAD_APICID 0xFFFFu
#endif

enum ioapic_irq_destination_types {
	dest_Fixed		= 0,
	dest_LowestPrio		= 1,
	dest_SMI		= 2,
	dest__reserved_1	= 3,
	dest_NMI		= 4,
	dest_INIT		= 5,
	dest__reserved_2	= 6,
	dest_ExtINT		= 7
};

struct apic {
	const char *name;

	int (*probe)(void);
	int (*apic_id_valid)(int apicid);
	int (*apic_id_registered)(void);

	int irq_delivery_mode;
	int irq_dest_mode;

	int dest_logical;

	const struct cpumask *(*target_cpus)(void);

	void (*vector_allocation_domain)(int cpu, struct cpumask *retmask,
					 const struct cpumask *mask);

	unsigned int (*get_apic_id)(unsigned long x);
	unsigned long (*set_apic_id)(unsigned int id);

	void (*init_apic_ldr)(void);

	int (*phys_pkg_id)(int cpuid_apic, int index_msb);

	int (*cpu_mask_to_apicid_and)(const struct cpumask *cpumask,
				      const struct cpumask *andmask,
				      unsigned int *apicid);

	/* ipi */
	void (*send_IPI)(int cpu, int vector);
	void (*send_IPI_mask)(const struct cpumask *mask, int vector);
	void (*send_IPI_mask_allbutself)(const struct cpumask *mask, int vector);
	void (*send_IPI_allbutself)(int vector);
	void (*send_IPI_all)(int vector);
	void (*send_IPI_self)(int vector);

	/* wakeup_secondary_cpu */
	int (*wakeup_secondary_cpu)(int apicid, unsigned long start_eip);

	void (*inquire_remote_apic)(int apicid);

	/* apic ops */
	u32 (*read)(u32 reg);
	void (*write)(u32 reg, u32 v);
	/*
	 * ->eoi_write() has the same signature as ->write().
	 *
	 * Drivers can support both ->eoi_write() and ->write() by passing the same
	 * callback value. Kernel can override ->eoi_write() and fall back
	 * on write for EOI.
	 */
	void (*eoi_write)(u32 reg, u32 v);
	u64 (*icr_read)(void);
	void (*icr_write)(u32 low, u32 high);
	void (*wait_icr_idle)(void);
	u32 (*safe_wait_icr_idle)(void);
};

/*
 * Pointer to the local APIC driver in use on this system (there's
 * always just one such driver in use - the kernel decides via an
 * early probing process which one it picks - and then sticks to it):
 */
extern struct apic *apic;

/*
 * APIC drivers are probed based on how they are listed in the .apicdrivers
 * section. So the order is important and enforced by the ordering
 * of different apic driver files in the Makefile.
 *
 * For the files having two apic drivers, we use apic_drivers()
 * to enforce the order with in them.
 */
#define apic_driver(sym)						\
	static const struct apic *__apicdrivers_##sym __used		\
	__aligned(sizeof(struct apic *))				\
	__section(.apicdrivers) = { &sym }

#define apic_drivers(sym1, sym2)					\
	static struct apic *__apicdrivers_##sym1##sym2[2] __used	\
	__aligned(sizeof(struct apic *))				\
	__section(.apicdrivers) = { &sym1, &sym2 }

extern struct apic *__apicdrivers[], *__apicdrivers_end[];

static inline void native_apic_msr_write(u32 reg, u32 v)
{
	if (reg == APIC_DFR || reg == APIC_ID || reg == APIC_LDR ||
	    reg == APIC_LVR)
		return;

	wrmsr(APIC_BASE_MSR + (reg >> 4), v, 0);
}

static inline void native_apic_msr_eoi_write(u32 reg, u32 v)
{
	wrmsr(APIC_BASE_MSR + (APIC_EOI >> 4), APIC_EOI_ACK, 0);
}

static inline u32 native_apic_msr_read(u32 reg)
{
	u64 msr;

	if (reg == APIC_DFR)
		return -1;

	rdmsrl(APIC_BASE_MSR + (reg >> 4), msr);
	return (u32)msr;
}

static inline u32 native_apic_mem_read(u32 reg)
{
	return *((volatile u32 *)(APIC_BASE + reg));
}

static inline void native_apic_mem_write(u32 reg, u32 v)
{
	volatile u32 *addr = (volatile u32 *)(APIC_BASE + reg);
	*addr = v;
}

#ifdef CONFIG_X86_X2APIC
extern int x2apic_mode;
extern int x2apic_phys;

void __init check_x2apic(void);

static inline int apic_is_x2apic_enabled(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_APICBASE, msr);
	return msr & X2APIC_ENABLE;
}

static inline int x2apic_enabled(void)
{
	return cpu_has(X86_FEATURE_X2APIC) && apic_is_x2apic_enabled();
}

static inline int x2apic_supported(void)
{
	return cpu_has(X86_FEATURE_X2APIC);
}
#else
#define x2apic_mode 0
static inline void check_x2apic(void) { }
static inline void x2apic_setup(void) { }
static inline int x2apic_enabled(void) { return 0; }
static inline int x2apic_supported(void) { return 0; }
#endif /* CONFIG_X86_X2APIC */

void __init setup_apic_driver(void);

void native_apic_wait_icr_idle(void);
u32 native_safe_apic_wait_icr_idle(void);
void native_apic_icr_write(u32 low, u32 id);
u64 native_apic_icr_read(void);

static inline u32 apic_read(u32 reg)
{
	return apic->read(reg);
}

static inline void apic_write(u32 reg, u32 val)
{
	apic->write(reg, val);
}

static inline void apic_eoi(void)
{
	apic->eoi_write(APIC_EOI, APIC_EOI_ACK);
}

static inline u64 apic_icr_read(void)
{
	return apic->icr_read();
}

static inline void apic_icr_write(u32 low, u32 high)
{
	apic->icr_write(low, high);
}

static inline void apic_wait_icr_idle(void)
{
	apic->wait_icr_idle();
}

static inline u32 safe_apic_wait_icr_idle(void)
{
	return apic->safe_wait_icr_idle();
}

static inline unsigned int read_apic_id(void)
{
	unsigned int reg;

	reg = apic_read(APIC_ID);

	return apic->get_apic_id(reg);
}

static inline void ack_APIC_irq(void)
{
	/*
	 * ack_APIC_irq() actually gets compiled as a single instruction
	 * ... yummie.
	 */
	apic_eoi();
}

void __init sync_Arb_IDs(void);

void __init apic_set_eoi_write(void (*eoi_write)(u32 reg, u32 v));

void __init init_apic_mappings(void);

void __init register_lapic_address(unsigned long address);

void __init x86_apic_ioapic_init(void);

void __init init_bsp_APIC(void);

int cpu_to_apicid(int cpu);
int apic_register_new_cpu(int apicid, int enabled);

int __init apic_bsp_setup(void);
void __init apic_ap_setup(void);

void setup_secondary_APIC_clock(void);
void disable_local_APIC(void);

extern unsigned int boot_cpu_physical_apicid;

#endif /* _ASM_X86_APIC_H_ */

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * X86's ugly descriptor
 */

#ifndef _ASM_X86_DESC_H_
#define _ASM_X86_DESC_H_

#include <asm/tss.h>
#include <asm/page.h>
#include <asm/segment.h>
#include <asm/irq_vectors.h>

#include <lego/bug.h>
#include <lego/types.h>
#include <lego/string.h>

/* 8 byte segment descriptor */
struct desc_struct {
	union {
		struct {
			unsigned int a;
			unsigned int b;
		};
		struct {
			u16 limit0;
			u16 base0;
			unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
			unsigned limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
		};
	};
} __attribute__((packed));

#define GDT_ENTRY_INIT(flags, base, limit) { { { \
		.a = ((limit) & 0xffff) | (((base) & 0xffff) << 16), \
		.b = (((base) & 0xff0000) >> 16) | (((flags) & 0xf0ff) << 8) | \
			((limit) & 0xf0000) | ((base) & 0xff000000), \
	} } }

enum {
	GATE_INTERRUPT = 0xE,
	GATE_TRAP = 0xF,
	GATE_CALL = 0xC,
	GATE_TASK = 0x5,
};

/* 16byte gate */
struct gate_struct64 {
	u16 offset_low;
	u16 segment;
	unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
	u16 offset_middle;
	u32 offset_high;
	u32 zero1;
} __attribute__((packed));

#define PTR_LOW(x) ((unsigned long long)(x) & 0xFFFF)
#define PTR_MIDDLE(x) (((unsigned long long)(x) >> 16) & 0xFFFF)
#define PTR_HIGH(x) ((unsigned long long)(x) >> 32)

enum {
	DESC_TSS = 0x9,
	DESC_LDT = 0x2,
	DESCTYPE_S = 0x10,	/* !system */
};

/* LDT or TSS descriptor in the GDT. 16 bytes. */
struct ldttss_desc64 {
	u16 limit0;
	u16 base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	u32 base3;
	u32 zero1;
} __attribute__((packed));

#ifdef CONFIG_X86_64
typedef struct gate_struct64 gate_desc;
typedef struct ldttss_desc64 ldt_desc;
typedef struct ldttss_desc64 tss_desc;
#define gate_offset(g) ((g).offset_low | ((unsigned long)(g).offset_middle << 16) | ((unsigned long)(g).offset_high << 32))
#define gate_segment(g) ((g).segment)
#else
typedef struct desc_struct gate_desc;
typedef struct desc_struct ldt_desc;
typedef struct desc_struct tss_desc;
#define gate_offset(g)		(((g).b & 0xffff0000) | ((g).a & 0x0000ffff))
#define gate_segment(g)		((g).a >> 16)
#endif

struct desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed));

struct gdt_page {
	struct desc_struct gdt[GDT_ENTRIES];
} __attribute__((aligned(PAGE_SIZE)));

DECLARE_PER_CPU_PAGE_ALIGNED(struct gdt_page, cpu_gdt_page);

static inline struct desc_struct *get_cpu_gdt_table(unsigned int cpu)
{
	return per_cpu(cpu_gdt_page, cpu).gdt;
}

#ifdef CONFIG_X86_64
static inline void pack_gate(gate_desc *gate, unsigned type, unsigned long func,
			     unsigned dpl, unsigned ist, unsigned seg)
{
	gate->offset_low	= PTR_LOW(func);
	gate->segment		= __KERNEL_CS;
	gate->ist		= ist;
	gate->p			= 1;
	gate->dpl		= dpl;
	gate->zero0		= 0;
	gate->zero1		= 0;
	gate->type		= type;
	gate->offset_middle	= PTR_MIDDLE(func);
	gate->offset_high	= PTR_HIGH(func);
}
#else
static inline void pack_gate(gate_desc *gate, unsigned char type,
			     unsigned long base, unsigned dpl, unsigned flags,
			     unsigned short seg)
{
	gate->a = (seg << 16) | (base & 0xffff);
	gate->b = (base & 0xffff0000) | (((0x80 | type | (dpl << 5)) & 0xff) << 8);
}

#endif

/*
 * @t: thread_struct
 * @cpu: cpu
 *
 * Defined as macro to avoid includ hole
 */
#define load_TLS(t, cpu)					\
do {								\
	struct desc_struct *gdt = get_cpu_gdt_table(cpu);	\
	unsigned int i;						\
								\
	for (i = 0; i < GDT_ENTRY_TLS_ENTRIES; i++)		\
		gdt[GDT_ENTRY_TLS_MIN + i] = t->tls_array[i];	\
} while (0)

static inline void load_tr_desc(void)
{
	asm volatile ("ltr %w0"::"q" (GDT_ENTRY_TSS*8));
}

static inline void load_gdt(const struct desc_ptr *p)
{
	asm volatile ("lgdt %0"::"m" (*p));
}

static inline void load_idt(const struct desc_ptr *p)
{
	asm volatile ("lidt %0"::"m" (*p));
}

static inline void store_gdt(struct desc_ptr *p)
{
	asm volatile ("sgdt %0":"=m" (*p));
}

static inline void store_idt(struct desc_ptr *p)
{
	asm volatile ("sidt %0":"=m" (*p));
}

static inline void write_idt_entry(gate_desc *idt, int entry,
				   const gate_desc *gate)
{
	memcpy(&idt[entry], gate, sizeof(*gate));
}

static inline void write_gdt_entry(struct desc_struct *gdt, int entry,
				   const void *desc, int type)
{
	unsigned int size;

	switch (type) {
	case DESC_TSS:	size = sizeof(tss_desc);	break;
	case DESC_LDT:	size = sizeof(ldt_desc);	break;
	default:	size = sizeof(*gdt);		break;
	}

	memcpy(&gdt[entry], desc, size);
}

static inline void pack_descriptor(struct desc_struct *desc, unsigned long base,
				   unsigned long limit, unsigned char type,
				   unsigned char flags)
{
	desc->a = ((base & 0xffff) << 16) | (limit & 0xffff);
	desc->b = (base & 0xff000000) | ((base & 0xff0000) >> 16) |
		(limit & 0x000f0000) | ((type & 0xff) << 8) |
		((flags & 0xf) << 20);
	desc->p = 1;
}

static inline void set_tssldt_descriptor(void *d, unsigned long addr,
					 unsigned type, unsigned size)
{
#ifdef CONFIG_X86_64
	struct ldttss_desc64 *desc = d;

	memset(desc, 0, sizeof(*desc));

	desc->limit0		= size & 0xFFFF;
	desc->base0		= PTR_LOW(addr);
	desc->base1		= PTR_MIDDLE(addr) & 0xFF;
	desc->type		= type;
	desc->p			= 1;
	desc->limit1		= (size >> 16) & 0xF;
	desc->base2		= (PTR_MIDDLE(addr) >> 8) & 0xFF;
	desc->base3		= PTR_HIGH(addr);
#else
	pack_descriptor((struct desc_struct *)d, addr, size, 0x80 | type, 0);
#endif
}

static inline void __set_tss_desc(unsigned cpu, unsigned int entry, void *addr)
{
	struct desc_struct *d = get_cpu_gdt_table(cpu);
	tss_desc tss;

	/*
	 * sizeof(unsigned long) coming from an extra "long" at the end
	 * of the iobitmap. See tss_struct definition in processor.h
	 *
	 * -1? seg base+limit should be pointing to the address of the
	 * last valid byte
	 */
	set_tssldt_descriptor(&tss, (unsigned long)addr, DESC_TSS,
			      IO_BITMAP_OFFSET + IO_BITMAP_BYTES +
			      sizeof(unsigned long) - 1);
	write_gdt_entry(d, entry, &tss, DESC_TSS);
}

#define set_tss_desc(cpu, addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)

extern gate_desc idt_table[NR_VECTORS];
extern struct desc_ptr idt_desc;

/*
 * (a)
 *
 * The processor check the DPL of the interrupt or trap gate
 * only if the interrupt or exception is generated by INT n.
 * 
 * The CPL must be less than or equal to the DPL of the gate.
 * That's why system call gate use 0x3 as its DPL.
 *
 * For hardware-generated interrutps and processor-deteced
 * exceptions, the processor ignores the DPL of the gates.
 *
 * (b)
 *
 * The only difference between trap and interrupt gates is the
 * way the processor handles the IF flags in EFLAGS register.
 *
 * Through a [trap gate], it does not affect the IF flag.
 *
 * Through an [interrupt gate], the processor clears the IF flag
 * to prevent other interrupts from interfering with the current
 * interrupt handler. A subsequent IRET instruction restores
 * the IF flag to its value in the saved contents of the EFLAGS
 * register on the stack. (The IF flag does not affect the
 * generation of exceptions or NMI interrupts).
 */

static inline void __set_gate(int gate, unsigned type, void *addr,
			      unsigned dpl, unsigned ist, unsigned seg)
{
	gate_desc s;

	pack_gate(&s, type, (unsigned long)addr, dpl, ist, seg);

	/*
	 * does not need to be atomic because it is only done once at
	 * setup time
	 */
	write_idt_entry(idt_table, gate, &s);
}

/*
 * The following two routines:
 *	set_system_intr_gate
 *	set_system_trap_gate
 * are used to set intr/trap gate with 0x3 DPL, those gates can be called
 * via INT instruction from userspace.
 */

static inline void set_system_intr_gate(unsigned int gate, void *addr)
{
	BUG_ON(gate > 0xFF);
	__set_gate(gate, GATE_INTERRUPT, addr, 0x3, 0, __KERNEL_CS);
}

static inline void set_system_trap_gate(unsigned int gate, void *addr)
{
	BUG_ON(gate > 0xFF);
	__set_gate(gate, GATE_TRAP, addr, 0x3, 0, __KERNEL_CS);
}

/*
 * The following two routines:
 *	set_intr_gate
 *	set_trap_gate
 * are used to set intr/trap gate with 0x0 DPL, those gates can NOT be called
 * via INT instruction from userspace
 */

static inline void set_intr_gate(unsigned int gate, void *addr)
{
	BUG_ON(gate > 0xFF);
	__set_gate(gate, GATE_INTERRUPT, addr, 0, 0, __KERNEL_CS);
}

static inline void set_trap_gate(unsigned int gate, void *addr)
{
	BUG_ON(gate > 0xFF);
	__set_gate(gate, GATE_TRAP, addr, 0, 0, __KERNEL_CS);
}

static inline void set_task_gate(unsigned int gate, unsigned int gdt_entry)
{
	BUG_ON(gate > 0xFF);
	__set_gate(gate, GATE_TASK, (void *)0, 0, 0, (gdt_entry << 3));
}

/* used_vectors is BITMAP for irq is not managed by percpu vector_irq */
extern DECLARE_BITMAP(used_vectors, NR_VECTORS);
extern int first_system_vector;

static inline void alloc_system_vector(int vector)
{
	if (!test_bit(vector, used_vectors)) {
		set_bit(vector, used_vectors);
		if (first_system_vector > vector)
			first_system_vector = vector;
	} else {
		BUG();
	}
}

#define alloc_intr_gate(n, addr)				\
	do {							\
		alloc_system_vector(n);				\
		set_intr_gate(n, addr);				\
	} while (0)

void load_percpu_segment(int cpu);
void switch_to_new_gdt(int cpu);

/* Access rights as returned by LAR */
#define AR_TYPE_RODATA		(0 * (1 << 9))
#define AR_TYPE_RWDATA		(1 * (1 << 9))
#define AR_TYPE_RODATA_EXPDOWN	(2 * (1 << 9))
#define AR_TYPE_RWDATA_EXPDOWN	(3 * (1 << 9))
#define AR_TYPE_XOCODE		(4 * (1 << 9))
#define AR_TYPE_XRCODE		(5 * (1 << 9))
#define AR_TYPE_XOCODE_CONF	(6 * (1 << 9))
#define AR_TYPE_XRCODE_CONF	(7 * (1 << 9))
#define AR_TYPE_MASK		(7 * (1 << 9))

#define AR_DPL0			(0 * (1 << 13))
#define AR_DPL3			(3 * (1 << 13))
#define AR_DPL_MASK		(3 * (1 << 13))

#define AR_A			(1 << 8)   /* "Accessed" */
#define AR_S			(1 << 12)  /* If clear, "System" segment */
#define AR_P			(1 << 15)  /* "Present" */
#define AR_AVL			(1 << 20)  /* "AVaiLable" (no HW effect) */
#define AR_L			(1 << 21)  /* "Long mode" for code segments */
#define AR_DB			(1 << 22)  /* D/B, effect depends on type */
#define AR_G			(1 << 23)  /* "Granularity" (limit in pages) */

#endif /* _ASM_X86_DESC_H_ */

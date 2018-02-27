/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/nops.h>
#include <asm/processor.h>
#include <asm/alternative.h>

#include <lego/irq.h>
#include <lego/bug.h>
#include <lego/init.h>
#include <lego/string.h>
#include <lego/kernel.h>

/* Defined in linker script */
extern struct alt_instr __alt_instructions[], __alt_instructions_end[];

/* Debug flag for other subsystems */
int __read_mostly alternatives_patched;

/* Kernel parameters */
static int __initdata debug_alternative;

static int __init debug_alt(char *str)
{
	debug_alternative = 1;
	return 1;
}
__setup("early_alternative_debug", debug_alt);

#define DPRINTK(fmt, args...)						\
do {									\
	if (debug_alternative)						\
		printk(KERN_DEBUG "%s: " fmt "\n", __func__, ##args);	\
} while (0)

#define DUMP_BYTES(buf, len, fmt, args...)				\
do {									\
	if (unlikely(debug_alternative)) {				\
		int j;							\
									\
		if (!(len))						\
			break;						\
									\
		printk(KERN_DEBUG fmt, ##args);				\
		for (j = 0; j < (len) - 1; j++)				\
			printk(KERN_CONT "%02hhx ", buf[j]);		\
		printk(KERN_CONT "%02hhx\n", buf[j]);			\
	}								\
} while (0)

/*
 * Each GENERIC_NOPX is of X bytes, and defined as an array of bytes
 * that correspond to that nop. Getting from one nop to the next, we
 * add to the array the offset that is equal to the sum of all sizes of
 * nops preceding the one we are after.
 *
 * Note: The GENERIC_NOP5_ATOMIC is at the end, as it breaks the
 * nice symmetry of sizes of the previous nops.
 */
#if defined(GENERIC_NOP1) && !defined(CONFIG_X86_64)
static const unsigned char intelnops[] =
{
	GENERIC_NOP1,
	GENERIC_NOP2,
	GENERIC_NOP3,
	GENERIC_NOP4,
	GENERIC_NOP5,
	GENERIC_NOP6,
	GENERIC_NOP7,
	GENERIC_NOP8,
	GENERIC_NOP5_ATOMIC
};
static const unsigned char * const intel_nops[ASM_NOP_MAX+2] =
{
	NULL,
	intelnops,
	intelnops + 1,
	intelnops + 1 + 2,
	intelnops + 1 + 2 + 3,
	intelnops + 1 + 2 + 3 + 4,
	intelnops + 1 + 2 + 3 + 4 + 5,
	intelnops + 1 + 2 + 3 + 4 + 5 + 6,
	intelnops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	intelnops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

#ifdef K8_NOP1
static const unsigned char k8nops[] =
{
	K8_NOP1,
	K8_NOP2,
	K8_NOP3,
	K8_NOP4,
	K8_NOP5,
	K8_NOP6,
	K8_NOP7,
	K8_NOP8,
	K8_NOP5_ATOMIC
};
static const unsigned char * const k8_nops[ASM_NOP_MAX+2] =
{
	NULL,
	k8nops,
	k8nops + 1,
	k8nops + 1 + 2,
	k8nops + 1 + 2 + 3,
	k8nops + 1 + 2 + 3 + 4,
	k8nops + 1 + 2 + 3 + 4 + 5,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

#if defined(K7_NOP1) && !defined(CONFIG_X86_64)
static const unsigned char k7nops[] =
{
	K7_NOP1,
	K7_NOP2,
	K7_NOP3,
	K7_NOP4,
	K7_NOP5,
	K7_NOP6,
	K7_NOP7,
	K7_NOP8,
	K7_NOP5_ATOMIC
};
static const unsigned char * const k7_nops[ASM_NOP_MAX+2] =
{
	NULL,
	k7nops,
	k7nops + 1,
	k7nops + 1 + 2,
	k7nops + 1 + 2 + 3,
	k7nops + 1 + 2 + 3 + 4,
	k7nops + 1 + 2 + 3 + 4 + 5,
	k7nops + 1 + 2 + 3 + 4 + 5 + 6,
	k7nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	k7nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

#ifdef P6_NOP1
static const unsigned char p6nops[] =
{
	P6_NOP1,
	P6_NOP2,
	P6_NOP3,
	P6_NOP4,
	P6_NOP5,
	P6_NOP6,
	P6_NOP7,
	P6_NOP8,
	P6_NOP5_ATOMIC
};
static const unsigned char * const p6_nops[ASM_NOP_MAX+2] =
{
	NULL,
	p6nops,
	p6nops + 1,
	p6nops + 1 + 2,
	p6nops + 1 + 2 + 3,
	p6nops + 1 + 2 + 3 + 4,
	p6nops + 1 + 2 + 3 + 4 + 5,
	p6nops + 1 + 2 + 3 + 4 + 5 + 6,
	p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

/* Initialize these to a safe default */
#ifdef CONFIG_X86_64
const unsigned char * const *ideal_nops = p6_nops;
#else
const unsigned char * const *ideal_nops = intel_nops;
#endif

static void __init set_ideal_nops(const unsigned char * const *nops)
{
	ideal_nops = nops;
	pr_info("x86/nops: ideal_nops is %pS\n", nops);
}

void __init arch_init_ideal_nops(void)
{
	switch (default_cpu_info.x86_vendor) {
	case X86_VENDOR_INTEL:
		/*
		 * Due to a decoder implementation quirk, some
		 * specific Intel CPUs actually perform better with
		 * the "k8_nops" than with the SDM-recommended NOPs.
		 */
		if (default_cpu_info.x86 == 6 &&
		    default_cpu_info.x86_model >= 0x0f &&
		    default_cpu_info.x86_model != 0x1c &&
		    default_cpu_info.x86_model != 0x26 &&
		    default_cpu_info.x86_model != 0x27 &&
		    default_cpu_info.x86_model < 0x30) {
			set_ideal_nops(k8_nops);
		} else if (cpu_has(X86_FEATURE_NOPL)) {
			   set_ideal_nops(p6_nops);
		} else {
#ifdef CONFIG_X86_64
			set_ideal_nops(k8_nops);
#else
			set_ideal_nops(intel_nops);
#endif
		}
		break;

	case X86_VENDOR_AMD:
		if (default_cpu_info.x86 > 0xf) {
			set_ideal_nops(p6_nops);
			return;
		}

		/* fall through */

	default:
#ifdef CONFIG_X86_64
		set_ideal_nops(k8_nops);
#else
		if (cpu_has(X86_FEATURE_K8))
			set_ideal_nops(k8_nops);
		else if (boot_cpu_has(X86_FEATURE_K7))
			set_ideal_nops(k7_nops);
		else
			set_ideal_nops(intel_nops);
#endif
	}
}

/* Use this to add nops to a buffer, then text_poke the whole buffer. */
static void __init add_nops(void *insns, unsigned int len)
{
	while (len > 0) {
		unsigned int noplen = len;
		if (noplen > ASM_NOP_MAX)
			noplen = ASM_NOP_MAX;
		memcpy(insns, ideal_nops[noplen], noplen);
		insns += noplen;
		len -= noplen;
	}
}

/*
 * Are we looking at a near JMP with a 1 or 4-byte displacement.
 */
static inline bool is_jmp(const u8 opcode)
{
	return opcode == 0xeb || opcode == 0xe9;
}

static void __init
recompute_jump(struct alt_instr *a, u8 *orig_insn, u8 *repl_insn, u8 *insnbuf)
{
	u8 *next_rip, *tgt_rip;
	s32 n_dspl, o_dspl;
	int repl_len;

	if (a->replacementlen != 5)
		return;

	o_dspl = *(s32 *)(insnbuf + 1);

	/* next_rip of the replacement JMP */
	next_rip = repl_insn + a->replacementlen;
	/* target rip of the replacement JMP */
	tgt_rip  = next_rip + o_dspl;
	n_dspl = tgt_rip - orig_insn;

	DPRINTK("target RIP: %p, new_displ: 0x%x", tgt_rip, n_dspl);

	if (tgt_rip - orig_insn >= 0) {
		if (n_dspl - 2 <= 127)
			goto two_byte_jmp;
		else
			goto five_byte_jmp;
	/* negative offset */
	} else {
		if (((n_dspl - 2) & 0xff) == (n_dspl - 2))
			goto two_byte_jmp;
		else
			goto five_byte_jmp;
	}

two_byte_jmp:
	n_dspl -= 2;

	insnbuf[0] = 0xeb;
	insnbuf[1] = (s8)n_dspl;
	add_nops(insnbuf + 2, 3);

	repl_len = 2;
	goto done;

five_byte_jmp:
	n_dspl -= 5;

	insnbuf[0] = 0xe9;
	*(s32 *)&insnbuf[1] = n_dspl;

	repl_len = 5;

done:

	DPRINTK("final displ: 0x%08x, JMP 0x%lx",
		n_dspl, (unsigned long)orig_insn + n_dspl + repl_len);
}

/*
 * Well, this function is called if the feature is not present,
 * so we have to keep using the old instruction.
 *
 * But do update the old padding code to ideal nops.
 */
static void __init optimize_nops(struct alt_instr *a, u8 *instr)
{
	unsigned long flags;

	if (instr[0] != 0x90)
		return;

	local_irq_save(flags);
	add_nops(instr + (a->instrlen - a->padlen), a->padlen);
	sync_core();
	local_irq_restore(flags);

	DUMP_BYTES(instr, a->instrlen, "%p: [%d:%d) optimized NOPs: ",
		   instr, a->instrlen - a->padlen, a->padlen);
}

/**
 * text_poke_early - Update instructions on a live kernel at boot time
 * @addr: address to modify
 * @opcode: source of the copy
 * @len: length to copy
 *
 * When you use this code to patch more than one byte of an instruction
 * you need to make sure that other CPUs cannot execute this code in parallel.
 * Also no thread must be currently preempted in the middle of these
 * instructions. And on the local CPU you need to be protected again NMI or MCE
 * handlers seeing an inconsistent instruction while you patch.
 */
void * __init text_poke_early(void *addr, const void *opcode, size_t len)
{
	unsigned long flags;
	local_irq_save(flags);
	memcpy(addr, opcode, len);
	sync_core();
	local_irq_restore(flags);
	/* Could also do a CLFLUSH here to speed up CPU recovery; but
	   that causes hangs on some VIA CPUs. */
	return addr;
}

#define MAX_PATCH_LEN (255-1)

/*
 * Replace instructions with better alternatives for this CPU type. This runs
 * before SMP is initialized to avoid SMP problems with self modifying code.
 * This implies that asymmetric systems where APs have less capabilities than
 * the boot processor are not handled. Tough. Make sure you disable such
 * features by hand.
 */
void __init apply_alternatives(struct alt_instr *start,
					 struct alt_instr *end)
{
	struct alt_instr *a;
	u8 *instr, *replacement;
	u8 insnbuf[MAX_PATCH_LEN];

	DPRINTK("alt table [%p - %p]", start, end);

	/*
	 * The scan order should be from start to end. A later scanned
	 * alternative code can overwrite previously scanned alternative code.
	 * Some kernel functions (e.g. memcpy, memset, etc) use this order to
	 * patch code.
	 *
	 * So be careful if you want to change the scan order to any other
	 * order.
	 */
	for (a = start; a < end; a++) {
		int insnbuf_sz = 0;

		instr = (u8 *)&a->instr_offset + a->instr_offset;
		replacement = (u8 *)&a->repl_offset + a->repl_offset;
		BUG_ON(a->instrlen > sizeof(insnbuf));
		BUG_ON(a->cpuid >= (NCAPINTS + NBUGINTS) * 32);
		if (!cpu_has(a->cpuid)) {
			if (a->padlen > 1)
				optimize_nops(a, instr);

			continue;
		}

		DPRINTK("feat: %d*32+%d, old: (%p, len: %d), repl: (%p, len: %d), pad: %d",
			a->cpuid >> 5,
			a->cpuid & 0x1f,
			instr, a->instrlen,
			replacement, a->replacementlen, a->padlen);

		DUMP_BYTES(instr, a->instrlen, "  %pS: old_insn: ", instr);
		DUMP_BYTES(replacement, a->replacementlen, "  %pS: rpl_insn: ", replacement);

		memcpy(insnbuf, replacement, a->replacementlen);
		insnbuf_sz = a->replacementlen;

		/* 0xe8 is a relative jump; fix the offset. */
		if (*insnbuf == 0xe8 && a->replacementlen == 5) {
			*(s32 *)(insnbuf + 1) += replacement - instr;
			DPRINTK("Fix CALL offset: 0x%x, CALL 0x%lx",
				*(s32 *)(insnbuf + 1),
				(unsigned long)instr + *(s32 *)(insnbuf + 1) + 5);
		}

		if (a->replacementlen && is_jmp(replacement[0]))
			recompute_jump(a, instr, replacement, insnbuf);

		if (a->instrlen > a->replacementlen) {
			add_nops(insnbuf + a->replacementlen,
				 a->instrlen - a->replacementlen);
			insnbuf_sz += a->instrlen - a->replacementlen;
		}
		DUMP_BYTES(insnbuf, insnbuf_sz, "  %pS: final_insn: ", instr);

		text_poke_early(instr, insnbuf, insnbuf_sz);
	}
}

/**
 * This function is invoked really early during boot.
 * It will walk through all "registered" alternatives,
 * and replace the old instruction with new instruction.
 *
 * Since we re strictly doing this in early boot, so we don't
 * need to concern too much about machine-check error or other
 * heartbreaking bugs.
 *
 * It is actually just several memcpy!
 */
void __init alternative_instructions(void)
{
	BUG_ON(system_state != SYSTEM_BOOTING);

	apply_alternatives(__alt_instructions, __alt_instructions_end);
	alternatives_patched = 1;
}

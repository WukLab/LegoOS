/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_COMP_PROCESSOR_H_
#define _LEGO_COMP_PROCESSOR_H_

#include <lego/sched.h>
#include <lego/signal.h>
#include <generated/unistd_64.h>
#include <lego/comp_common.h>	/* must come at last */

#define DEF_MEM_HOMENODE 1
//#define DEF_MEM_HOMENODE 2 //if storage in 0, processor 1 and memory 2
#define DEF_NET_TIMEOUT	 10	/* second */

#ifdef CONFIG_COMP_PROCESSOR
void __init processor_component_init(void);
int __init pcache_range_register(u64 start, u64 size);

#ifdef CONFIG_CHECKPOINT
int checkpoint_thread(struct task_struct *);
#else
static inline int checkpoint_thread(struct task_struct *tsk) { return 0; }
#endif /* CONFIG_CHECKPOINT */

int do_execve(const char *filename,
	      const char * const *argv,
	      const char * const *envp);

/**
 * Check if the cacheline mapped to @address is present
 * at pcache.
 *
 * Return true if present, otherwise return false.
 */
static inline bool pcache_present(unsigned long __user address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(current->mm, address);
	if (!pgd_present(*pgd))
		return false;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return false;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return false;

	pte = pte_offset(pmd, address);
	if (!pte_present(*pte))
		return false;

	return true;
}

static inline pte_t *addr2pte(unsigned long __user address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(current->mm, address);
	if (!pgd_present(*pgd))
		return NULL;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return NULL;

	pte = pte_offset(pmd, address);
	if (!pte_present(*pte))
		return NULL;
	
	return pte;
}

void open_stdio_files(void);

#else /* !CONFIG_COMP_PROCESSOR */
static inline void processor_component_init(void) { }
static inline int pcache_range_register(u64 start, u64 size)
{
	return 0;
}

static inline int checkpoint_thread(struct task_struct *tsk)
{
	BUG();
}

static inline int do_execve(const char *filename, const char * const *argv,
			    const char * const *envp)
{
	BUG();
}
#endif /* CONFIG_COMP_PROCESSOR */

#endif /* _LEGO_COMP_PROCESSOR_H_ */

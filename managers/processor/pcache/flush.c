/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>
#include <asm/io.h>

#include <processor/pcache.h>


int pcache_flush_cacheline_va_user(unsigned long __user vaddr)
{
#define DEBUG_CACHE_TEST

	void *msg;
	u32 len_msg;
	int retval = 0;
	unsigned long __user round_down_vaddr;
	void *va_cacheline;

	int err;
	u64 offset = 0;

	struct p2m_flush_payload *payload;
	void *content;

	round_down_vaddr = round_down(vaddr, PCACHE_LINE_SIZE);
	va_cacheline = (void *) round_down_vaddr;

	len_msg = sizeof(struct p2m_flush_payload) + PCACHE_LINE_SIZE;
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		pr_info("No memory for copying flushing page to ib msg.\n");
		return -ENOMEM;
	}
	
	payload = (struct p2m_flush_payload *) msg;
	content = (void *) (msg + sizeof(struct p2m_flush_payload));
	  
	payload->flush_vaddr = vaddr;
	payload->pid = current->pid;
	payload->llc_cacheline_size = PCACHE_LINE_SIZE; 

#ifdef DEBUG_CACHE_TEST
	pr_info("pcache_flush_single : vaddr : %#lx\nround_down_vaddr: %#lx\n",
			vaddr, round_down_vaddr);
#endif
	
	//memcpy(content, (void *) vaddr, PCACHE_LINE_SIZE);
	err = copy_from_user(content, va_cacheline, PCACHE_LINE_SIZE);
	if(unlikely(err)) {
		panic("Cannot copy cacheline content.\n");
	}

#ifdef DEBUG_CACHE_TEST
	offset = vaddr - round_down_vaddr;
	pr_info("pcache_flush_single : string from content [%s]\n", (char*) (content+offset));
#endif

	net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_LLC_FLUSH,
			msg, len_msg, &retval, sizeof(retval),
		       	false, DEF_NET_TIMEOUT);

	kfree(msg);
	return retval;
}

void pcache_flush_current(void)
{
	/* scanning page table */
	unsigned long cur_addr = 0;
	pte_t entry;
	struct mm_struct *mm = current->mm;
	spinlock_t *ptl;

	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	while(cur_addr < TASK_SIZE_MAX) {

		pgd = pgd_offset(mm, cur_addr);
		if (!pgd_present(*pgd))
			goto next_round;

		pud = pud_offset(pgd, cur_addr);
		if (!pud_present(*pud))
		       goto next_round;

		pmd = pmd_offset(pud, cur_addr);
		if (!pmd_present(*pmd))	
			goto next_round;

		ptep = pte_offset_lock(mm, pmd, cur_addr, &ptl);	
		if (!ptep || !pte_dirty(*ptep))
			goto unlock;

		entry = (*ptep);
		entry = pte_wrprotect(entry);
		/* wrprotect the page table entry */
		pte_set(ptep, entry);

		pcache_flush_cacheline_va_user(cur_addr);

		entry = pte_mkclean(pte_mkwrite(entry));
		pte_set(ptep, entry);
unlock:
		spin_unlock(ptl);
next_round:
		cur_addr += PAGE_SIZE;
	}	
}

/* backdoor syscall for testing pcache flush only */
SYSCALL_DEFINE1(pcache_flush, void __user *, vaddr)
{
	unsigned long __user address;
	address = (unsigned long __user) vaddr;
	return pcache_flush_cacheline_va_user(address);
}

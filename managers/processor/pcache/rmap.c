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
#include <lego/ratelimit.h>
#include <processor/pcache.h>
#include <processor/processor.h>

#include <asm/io.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_DEBUG_PCACHE_RMAP
#define rmap_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void rmap_debug(const char *fmt, ...) { }
#endif

/*
 * Our rmap points to PTE directly,
 * and rmap operations are carried out with pcache locked
 *
 * Thus the lock ordering is:
 * 	lock pset (optional)
 * 	lock pcache
 * 	lock pte
 */

static struct pcache_rmap *alloc_pcache_rmap(void)
{
	struct pcache_rmap *rmap;

	rmap = kmalloc(sizeof(*rmap), GFP_KERNEL);
	if (rmap) {
		INIT_LIST_HEAD(&rmap->next);
		rmap->flags = 0;
	}
	return rmap;
}

static void free_pcache_rmap(struct pcache_rmap *rmap)
{
	PCACHE_BUG_ON_RMAP(RmapReserved(rmap), rmap);
	kfree(rmap);
}

/*
 * We are traversing the reverse mapping, which means
 * upper level mappings must exist and present.
 * If not, BUG indeed.
 */
static __always_inline pmd_t *
rmap_get_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, address);
	BUG_ON(!pgd && !pgd_present(*pgd));

	pud = pud_offset(pgd, address);
	BUG_ON(!pud && !pud_present(*pud));

	pmd = pmd_offset(pud, address);
	BUG_ON(!pmd && !pmd_present(*pmd));

	return pmd;
}

static void report_bad_rmap(struct pcache_meta *pcm, struct pcache_rmap *rmap,
			    unsigned long address, pte_t *ptep)
{
	pr_err("\n"
	       "****    ERROR: mismatched PTE and rmap\n"
	       "****    rmap->owner_process: %s uva: %#lx ptep: %p, "
	                                     "rmap->page_table: %p\n"
	       "****    pcache_pfn: %#lx, pte_pfn: %#lx\n\n",
		rmap->owner_process->comm, address, ptep, rmap->page_table,
		pcache_meta_to_pfn(pcm), pte_pfn(*ptep));
	dump_pcache_rmap(rmap, "Corrupted RMAP");
	dump_pcache_meta(pcm, "Corrupted RMAP");
}

/*
 * Check that @pcm is mapped at @rmap->address
 *
 * To that end, this function actually returns @rmap->page_table.
 * But for safety reasons, we add several checkings here.
 * Safety means we have to make sure the pte reallly exist.
 * We may found already-being-cleared ptes.
 *
 * Upon return, if pte is not NULL, then it is locked. We do this
 * because normally callers will modify or even invalidate the PTEs.
 * Those operations have to be serialized with pgfault routines.
 */
static __always_inline pte_t *
rmap_get_pte_locked(struct pcache_meta *pcm, struct pcache_rmap *rmap,
		    spinlock_t **ptlp)	__acquires(*ptlp)
{
	pte_t *ptep;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct mm_struct *mm = rmap->owner_mm;
	unsigned long address = rmap->address;

	pmd = rmap_get_pmd(mm, address);
	ptep = pte_offset(pmd, address);

	if (unlikely(ptep != rmap->page_table)) {
		report_bad_rmap(pcm, rmap, address, ptep);
		ptep = NULL;
		goto out;
	}

	if (unlikely(pcache_meta_to_pfn(pcm) != pte_pfn(*ptep))) {

		/*
		 * This can happen in two cases:
		 * 1) mremap: original pte is moved to new pte
		 * 2) munmap: original pte is cleared.
		 *
		 * Both of them have a small time frame before rmap got
		 * updated. We should not treat this as bug.
		 *
		 * XXX: How to distinguish it from real bug?
		 */
		if (unlikely(pte_pfn(*ptep) != 0))
			report_bad_rmap(pcm, rmap, address, ptep);

		ptep = NULL;
		goto out;
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	*ptlp = ptl;

out:
	return ptep;
}

/**
 * pcache_add_rmap
 * @pcm: pcache line in question
 * @page_table: the pointer to pte
 * @address: user virtual address mapped to this pcm
 *
 * This function add a reverse mapping to @pcm.
 * @pcm must NOT be locked on entry.
 */
int pcache_add_rmap(struct pcache_meta *pcm, pte_t *page_table,
		    unsigned long address, struct mm_struct *owner_mm,
		    struct task_struct *owner_process)
{
	struct pcache_rmap *rmap, *pos;
	int ret;

	PCACHE_BUG_ON_PCM(PcacheLocked(pcm), pcm);

	lock_pcache(pcm);

	rmap = alloc_pcache_rmap();
	if (!rmap) {
		ret = -ENOMEM;
		goto out;
	}
	rmap->page_table = page_table;
	rmap->address = address & PAGE_MASK;
	rmap->owner_mm = owner_mm;
	rmap->owner_process = owner_process;

	if (likely(list_empty(&pcm->rmap)))
		goto add;

	list_for_each_entry(pos, &pcm->rmap, next)
		BUG_ON(pos->page_table == page_table);

add:
	ret = 0;
	list_add(&rmap->next, &pcm->rmap);
	atomic_inc(&pcm->mapcount);
out:
	unlock_pcache(pcm);
	return ret;
}

/* Internal function to remove one rmap from pcm */
static inline void pcache_remove_rmap(struct pcache_meta *pcm,
				      struct pcache_rmap *rmap)
{
	list_del(&rmap->next);
	free_pcache_rmap(rmap);
	atomic_dec(&pcm->mapcount);
}

struct pcache_move_pte_control {
	struct mm_struct *mm;
	pte_t *old_pte;
	pte_t *new_pte;
	unsigned long old_addr;
	unsigned long new_addr;
	bool updated;
};

static inline bool matched_rmap_for_move(struct pcache_rmap *rmap,
					 struct pcache_move_pte_control *mpc)
{
	if (rmap->page_table == mpc->old_pte &&
	    rmap->owner_mm   == mpc->mm      &&
	    rmap->address    == mpc->old_addr)
		return true;
	return false;
}

static int __pcache_move_pte(struct pcache_meta *pcm,
			     struct pcache_rmap *rmap, void *arg)
{
	struct pcache_move_pte_control *mpc = arg;

	if (likely(matched_rmap_for_move(rmap, mpc))) {
		rmap_debug("tgid: %u [%#lx %p] -> [%#lx %p]",
			rmap->owner_process->tgid, rmap->address,
			rmap->page_table, mpc->new_addr, mpc->new_pte);

		rmap->page_table = mpc->new_pte;
		rmap->address = mpc->new_addr;
		mpc->updated = true;

		/* Break the rmap walk loop */
		return PCACHE_RMAP_SUCCEED;
	}
	return PCACHE_RMAP_AGAIN;
}

/*
 * Update the rmap that currently points to @old_pte, to @new_pte, within
 * address space @mm.
 *
 * Called from move_ptes(), when mremap() syscall is invoked. PTE content
 * has already been moved: *old_pte is empty, while *new_pte is assigned.
 * Both @old_pte and @new_pte are locked on entry.
 */
void pcache_move_pte(struct mm_struct *mm, pte_t *old_pte, pte_t *new_pte,
		     unsigned long old_addr, unsigned long new_addr)
{
	struct pcache_meta *pcm;
	struct pcache_move_pte_control mpc = {
		.mm = mm,
		.old_pte = old_pte,
		.new_pte = new_pte,
		.old_addr = old_addr & PAGE_MASK,
		.new_addr = new_addr & PAGE_MASK,
		.updated = false,
	};
	struct rmap_walk_control rwc = {
		.arg = &mpc,
		.rmap_one = __pcache_move_pte,
	};

	pcm = pte_to_pcache_meta(*new_pte);
	BUG_ON(!pcm);

	lock_pcache(pcm);
	rmap_walk(pcm, &rwc);
	unlock_pcache(pcm);

	/*
	 * In theory, this should always succeed.
	 * Failure is not an option.
	 */
	BUG_ON(!mpc.updated);
}

struct pcache_zap_pte_control {
	struct mm_struct *mm;
	unsigned long address;
	pte_t *pte;
	bool zapped;
};

static inline bool matched_rmap_for_zap(struct pcache_rmap *rmap,
					struct pcache_zap_pte_control *zpc)
{
	if (rmap->page_table == zpc->pte &&
	    rmap->owner_mm   == zpc->mm  &&
	    rmap->address    == zpc->address)
		return true;
	return false;
}

static int __pcache_zap_pte(struct pcache_meta *pcm,
			    struct pcache_rmap *rmap, void *arg)
{
	struct pcache_zap_pte_control *zpc = arg;

	if (likely(matched_rmap_for_zap(rmap, zpc))) {
		rmap_debug("tgid: %u [%#lx %p]",
			rmap->owner_process->tgid, rmap->address,
			rmap->page_table);

		pcache_remove_rmap(pcm, rmap);
		zpc->zapped = true;

		/* Break the rmap walk loop */
		return PCACHE_RMAP_SUCCEED;
	}
	return PCACHE_RMAP_AGAIN;
}

/*
 * Remove the rmap that currently points to @pte within @mm.
 *
 * Called from zap_pte_range() when the emulated page table is cleared.
 * When called, the pte is already cleared, thus @pte is already 0,
 * while @ptent holds the previous pte content.
 */
void pcache_zap_pte(struct mm_struct *mm, unsigned long address,
		    pte_t ptent, pte_t *pte)
{
	struct pcache_meta *pcm;
	struct pcache_zap_pte_control zpc = {
		.mm = mm,
		.address = address & PAGE_MASK,
		.pte = pte,
		.zapped = false,
	};
	struct rmap_walk_control rwc = {
		.arg = &zpc,
		.rmap_one = __pcache_zap_pte,
	};

	pcm = pte_to_pcache_meta(ptent);
	BUG_ON(!pcm);

	lock_pcache(pcm);
	rmap_walk(pcm, &rwc);
	unlock_pcache(pcm);

	/* Failure is not an option. */
	BUG_ON(!zpc.zapped);
}

static int pcache_try_to_unmap_one(struct pcache_meta *pcm,
				   struct pcache_rmap *rmap, void *arg)
{
	int ret = PCACHE_RMAP_AGAIN;
	spinlock_t *ptl = NULL;
	pte_t *pte;
	pte_t pteval;

	PCACHE_BUG_ON_RMAP(RmapReserved(rmap), rmap);

	pte = rmap_get_pte_locked(pcm, rmap, &ptl);
	if (unlikely(!pte))
		return ret;

	pteval = ptep_get_and_clear(0, pte);

	if (pte_present(pteval))
		flush_tlb_mm_range(rmap->owner_mm,
				   rmap->address,
				   rmap->address + PAGE_SIZE -1);

	pcache_remove_rmap(pcm, rmap);

	spin_unlock(ptl);
	return ret;
}

/* Clear PTE, but keep rmap in the list with Reserved flag set */
static int pcache_try_to_unmap_reserve_one(struct pcache_meta *pcm,
					   struct pcache_rmap *rmap, void *arg)
{
	int ret = PCACHE_RMAP_AGAIN;
	spinlock_t *ptl = NULL;
	pte_t *pte;
	pte_t pteval;

	PCACHE_BUG_ON_RMAP(RmapReserved(rmap), rmap);

	pte = rmap_get_pte_locked(pcm, rmap, &ptl);
	if (unlikely(!pte))
		return ret;

	pteval = ptep_get_and_clear(0, pte);

	if (pte_present(pteval))
		flush_tlb_mm_range(rmap->owner_mm,
				   rmap->address,
				   rmap->address + PAGE_SIZE -1);

	SetRmapReserved(rmap);
	atomic_dec(&pcm->mapcount);

	spin_unlock(ptl);
	return ret;
}

static int pcache_mapcount_is_zero(struct pcache_meta *pcm)
{
	return !pcache_mapcount(pcm);
}

/**
 * pcache_try_to_unmap
 * @pcm: the pcache to get unmapped
 *
 * Tries to remove all the page table entries which are mapping this pcache,
 * used in the pageout path. @pcm must be locked on entry.
 *
 * FAT NOTE:
 * All rmap data structures associcated with @pcm will be freed.
 * Any rmap_walk involved functions after this won't have any effect.
 *
 * Return:
 *	PCACHE_RMAP_SUCCEED	- we succeeded in removing all mappings
 *	PCACHE_RMAP_AGAIN	- we missed a mapping, try again later
 */
int pcache_try_to_unmap(struct pcache_meta *pcm)
{
	int ret;
	struct rmap_walk_control rwc = {
		.rmap_one = pcache_try_to_unmap_one,
		.done = pcache_mapcount_is_zero,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	ret = rmap_walk(pcm, &rwc);
	if (!pcache_mapcount(pcm))
		ret = PCACHE_RMAP_SUCCEED;
	return ret;
}

/**
 * pcache_try_to_unmap_reserve
 * @pcm: the pcache to get unmapped
 *
 * The only difference with pcache_try_to_unmap is:
 * 	All rmaps associcated with @pcm will NOT be freed.
 * Must be paired with pcache_free_reserved_rmap() at last.
 */
int pcache_try_to_unmap_reserve(struct pcache_meta *pcm)
{
	struct rmap_walk_control rwc = {
		.rmap_one = pcache_try_to_unmap_reserve_one,
		.done = pcache_mapcount_is_zero,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	rmap_walk(pcm, &rwc);
	return PCACHE_RMAP_SUCCEED;
}

static int pcache_free_reserved_rmap_one(struct pcache_meta *pcm,
					 struct pcache_rmap *rmap, void *arg)
{
	/* Must be paired with unmap_reserve */
	PCACHE_BUG_ON_RMAP(!RmapReserved(rmap), rmap);
	ClearRmapReserved(rmap);

	list_del(&rmap->next);
	free_pcache_rmap(rmap);

	return PCACHE_RMAP_AGAIN;
}

int pcache_free_reserved_rmap(struct pcache_meta *pcm)
{
	struct rmap_walk_control rwc = {
		.rmap_one = pcache_free_reserved_rmap_one,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	rmap_walk(pcm, &rwc);
	return PCACHE_RMAP_SUCCEED;
}

static int pcache_wrprotect_one(struct pcache_meta *pcm,
				struct pcache_rmap *rmap, void *arg)
{
	int *protected = arg;
	int ret = PCACHE_RMAP_AGAIN;
	spinlock_t *ptl = NULL;
	pte_t *pte;
	pte_t entry;

	pte = rmap_get_pte_locked(pcm, rmap, &ptl);
	if (unlikely(!pte))
		return ret;

	if (!pte_write(*pte))
		goto out;

	/*
	 * Note: These operations are protected by the pte lock.
	 * If other core has a pgfault after we clear the PTE,
	 * the pgfault will end up with pcache_fill_page(). This is
	 * okay because we still hold the pte lock. Inside pgfault
	 * function, it will check pte again after acquires the pte lock,
	 * the case where PTE is already set back by us.
	 *
	 * Or, if other core has a pgfault after we set the pte to
	 * read-only, it will also wait until we release the pte lock.
	 * After that it will also check the pte upon pgfault and the
	 * pte upon getting the lock. Just check pcache_handle_pte_fault().
	 */
	entry = ptep_get_and_clear(0, pte);
	entry = pte_wrprotect(entry);
	entry = pte_mkclean(entry);
	pte_set(pte, entry);

	if (pte_present(entry))
		flush_tlb_mm_range(rmap->owner_mm,
				   rmap->address,
				   rmap->address + PAGE_SIZE -1);

	(*protected)++;

out:
	spin_unlock(ptl);
	return ret;
}

/**
 * pcache_wrprotect
 * @pcm: pcache line to protect
 *
 * This function will write-protect PTEs mapped to @pcm.
 * Return the number of PTEs that have been marked read-only.
 * @pcm must be locked on entry.
 */
int pcache_wrprotect(struct pcache_meta *pcm)
{
	int protected = 0;
	struct rmap_walk_control rwc = {
		.arg = &protected,
		.rmap_one = pcache_wrprotect_one,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	if (!pcache_mapped(pcm))
		return 0;

	rmap_walk(pcm, &rwc);

	return protected;
}

struct pcache_referenced_control {
	int referenced;
	int mapcount;
};

static int pcache_referenced_one(struct pcache_meta *pcm,
				 struct pcache_rmap *rmap, void *arg)
{
	struct pcache_referenced_control *prc = arg;
	spinlock_t *ptl = NULL;
	pte_t *pte;

	pte = rmap_get_pte_locked(pcm, rmap, &ptl);
	if (unlikely(!pte))
		return PCACHE_RMAP_AGAIN;

	if (ptep_clear_flush_young(pte))
		prc->referenced++;
	spin_unlock(ptl);

	/*
	 * We are locking pcache, there will not be
	 * any rmap added during the walk anyway.
	 */
	prc->mapcount--;
	if (!prc->mapcount)
		return PCACHE_RMAP_SUCCEED;
	return PCACHE_RMAP_AGAIN;
}

/**
 * pcache_referenced
 * @pcm: pcache line to count references
 *
 * Quick test_and_clear_referenced() for all mappings to a page,
 * returns the number of ptes which referenced the page.
 */
int pcache_referenced(struct pcache_meta *pcm)
{
	struct pcache_referenced_control prc = {
		.mapcount = pcache_mapcount(pcm),
		.referenced = 0,
	};
	struct rmap_walk_control rwc = {
		.arg = (void *)&prc,
		.rmap_one = pcache_referenced_one,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	if (!pcache_mapped(pcm))
		return 0;

	rmap_walk(pcm, &rwc);

	return prc.referenced;
}

/*
 * Walk through pcache line's reverse mapping.
 * @pcm must be locked on entry.
 *
 * Be careful while using locks inside your rmap walk function.
 * Do not introduce deadlock here.
 */
int rmap_walk(struct pcache_meta *pcm, struct rmap_walk_control *rwc)
{
	struct pcache_rmap *rmap, *keeper;
	int ret = PCACHE_RMAP_AGAIN;

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	/*
	 * In case someone called rmap without checking mapcount.
	 * Otherwise we might end up looping forever below.
	 */
	if (unlikely(list_empty(&pcm->rmap)))
		return ret;

	list_for_each_entry_safe(rmap, keeper, &pcm->rmap, next) {
		ret = rwc->rmap_one(pcm, rmap, rwc->arg);
		if (ret != PCACHE_RMAP_AGAIN)
			break;

		if (rwc->done && rwc->done(pcm))
			break;
	}

	return ret;
}

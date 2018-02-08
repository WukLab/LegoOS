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
			    unsigned long address, pte_t *ptep, void *caller)
{
	unsigned long pcache_pfn, _pte_pfn;

	pcache_pfn = pcache_meta_to_pfn(pcm);
	_pte_pfn = pte_pfn(*ptep);

	pr_err("\n"
	       "****    ERROR:\n"
	       "***     current: %d:%s caller: %pS\n"
	       "****    [pte %s rmap->page_table] && [pcache_pfn %s pte_pfn]\n"
	       "****    rmap->owner_process: %s uva: %#lx ptep: %p, rmap->page_table: %p\n"
	       "****    pcache_pfn: %#lx, pte_pfn: %#lx\n\n",
	        current->pid, current->comm, caller,
	        (ptep == rmap->page_table) ? "==":"!=",
	        (pcache_pfn == _pte_pfn) ? "==":"!=",
		rmap->owner_process->comm, address, ptep, rmap->page_table,
		pcache_pfn, _pte_pfn);

	dump_pcache_rmap(rmap, "Corrupted RMAP");
	dump_pcache_meta(pcm, "Corrupted RMAP");
	BUG();
}

/*
 * We don't want to introduce the extra overhead of passing
 * return address down if DEBUG_PCACHE is not enabled.
 */
#ifdef CONFIG_DEBUG_PCACHE
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
__rmap_get_pte_locked(struct pcache_meta *pcm, struct pcache_rmap *rmap,
		      spinlock_t **ptlp, void *caller) __acquires(*ptlp)
{
	pte_t *ptep;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct mm_struct *mm = rmap->owner_mm;
	unsigned long address = rmap->address;

	pmd = rmap_get_pmd(mm, address);
	ptep = pte_offset(pmd, address);

	if (unlikely(ptep != rmap->page_table)) {
		report_bad_rmap(pcm, rmap, address, ptep, caller);
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
			report_bad_rmap(pcm, rmap, address, ptep, caller);

		ptep = NULL;
		goto out;
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	*ptlp = ptl;

out:
	return ptep;
}

static __always_inline pte_t *
rmap_get_pte_locked(struct pcache_meta *pcm, struct pcache_rmap *rmap,
		    spinlock_t **ptlp) __acquires(*ptlp)
{
	return __rmap_get_pte_locked(pcm, rmap, ptlp,
				     __builtin_return_address(0));
}

static int __dump_pcache_rmaps(struct pcache_meta *pcm,
			       struct pcache_rmap *rmap, void *arg)
{
	pte_t *ptep = rmap->page_table;

	pr_debug("rmap:%p flags:%#lx owner-tgid:%u user_va:%#lx ptep:%p\n",
		rmap, rmap->flags, rmap->owner_process->pid, rmap->address, ptep);
	dump_pte(ptep, NULL);

	return PCACHE_RMAP_AGAIN;
}

static void dump_pcache_rmaps(struct pcache_meta *pcm)
{
	struct rmap_walk_control rwc = {
		.rmap_one = __dump_pcache_rmaps,
	};

	/* pcm is already locked */
	rmap_walk(pcm, &rwc);
}

static void validate_pcache_mapcount(struct pcache_meta *pcm)
{
	if (unlikely(atomic_read(&pcm->mapcount) > 1)) {
		pr_warn("****\n"
			"****    WARNING:\n"
			"****    This is BUG if you are running _single-process_ application!\n"
			"****    Remove this checking after we are confident about pcache!\n"
			"****\n");
		dump_pcache_meta(pcm, NULL);
		dump_pcache_rmaps(pcm);
		pr_warn("****\n"
			"****    END WARNING\n"
			"****\n");
	}
}

static inline pte_t *
rmap_get_pte_unlocked(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, address);
	if (!pgd && !pgd_present(*pgd))
		return NULL;

	pud = pud_offset(pgd, address);
	if (!pud && !pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, address);
	if (!pmd && !pmd_present(*pmd));
		return NULL;

	pte = pte_offset(pmd, address);
	if (!pte && !pte_present(*pte))
		return NULL;
	return pte;
}

/*
 * Need to validate if:
 * - pte indexed by uva+mm matches the saved on in rmap
 * - pte really points this pcache line
 */
static inline void
validate_pcache_rmap(struct pcache_meta *pcm, struct pcache_rmap *rmap)
{
	unsigned long pcache_pfn, _pte_pfn;
	pte_t *pte;

	pte = rmap_get_pte_unlocked(rmap->owner_mm, rmap->address);
	if (!pte)
		goto out;

	if (pte != rmap->page_table)
		goto out;

	pcache_pfn = pcache_meta_to_pfn(pcm);
	_pte_pfn = pte_pfn(*pte);
	if (pcache_pfn != _pte_pfn)
		goto out;
	return;

out:
	dump_pcache_meta(pcm, NULL);
	dump_pcache_rmap(rmap, NULL);
	BUG();
}

#else
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
		    spinlock_t **ptlp) __acquires(*ptlp)
{
	pte_t *ptep;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct mm_struct *mm = rmap->owner_mm;
	unsigned long address = rmap->address;

	pmd = rmap_get_pmd(mm, address);
	ptep = pte_offset(pmd, address);

	if (unlikely(ptep != rmap->page_table)) {
		report_bad_rmap(pcm, rmap, address, ptep, NULL);
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
			report_bad_rmap(pcm, rmap, address, ptep, NULL);

		ptep = NULL;
		goto out;
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	*ptlp = ptl;

out:
	return ptep;
}

static inline void validate_pcache_mapcount(struct pcache_meta *pcm)
{

}

static inline void
validate_pcache_rmap(struct pcache_meta *pcm, struct pcache_rmap *rmap)
{

}

#endif /* CONFIG_DEBUG_PCACHE */

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

	validate_pcache_mapcount(pcm);
	validate_pcache_rmap(pcm, rmap);
out:
	unlock_pcache(pcm);
	return ret;
}

/*
 * Internal function to remove one rmap from pcm
 * @pcm is locked upon entry.
 */
static inline void pcache_remove_rmap(struct pcache_meta *pcm,
				      struct pcache_rmap *rmap)
{
	list_del(&rmap->next);
	free_pcache_rmap(rmap);
	atomic_dec(&pcm->mapcount);
}

struct pcache_move_pte_info {
	struct mm_struct *mm;
	pte_t *old_pte;
	pte_t *new_pte;
	unsigned long old_addr;
	unsigned long new_addr;
	struct pcache_meta *new_pcm;
	bool updated;
};

static inline bool matched_rmap_for_move(struct pcache_rmap *rmap,
					 struct pcache_move_pte_info *mpi)
{
	if (rmap->page_table == mpi->old_pte &&
	    rmap->owner_mm   == mpi->mm      &&
	    rmap->address    == mpi->old_addr)
		return true;
	return false;
}

static int __pcache_move_pte_fastpath(struct pcache_meta *pcm,
				      struct pcache_rmap *rmap, void *arg)
{
	struct pcache_move_pte_info *mpi = arg;

	if (likely(matched_rmap_for_move(rmap, mpi))) {
		rmap_debug("tgid: %u [%#lx %p] -> [%#lx %p]",
			rmap->owner_process->tgid, rmap->address,
			rmap->page_table, mpi->new_addr, mpi->new_pte);

		rmap->page_table = mpi->new_pte;
		rmap->address = mpi->new_addr;
		mpi->updated = true;

		validate_pcache_rmap(pcm, rmap);

		/* Break the rmap walk loop */
		return PCACHE_RMAP_SUCCEED;
	}
	return PCACHE_RMAP_AGAIN;
}

static void pcache_move_pte_fastpath(struct mm_struct *mm,
				     pte_t *old_pte, pte_t *new_pte,
				     unsigned long old_addr, unsigned long new_addr)
{
	struct pcache_move_pte_info mpi = {
		.mm = mm,
		.old_pte = old_pte,
		.new_pte = new_pte,
		.old_addr = old_addr,
		.new_addr = new_addr,
		.updated = false,
	};
	struct rmap_walk_control rwc = {
		.arg = &mpi,
		.rmap_one = __pcache_move_pte_fastpath,
	};
	struct pcache_meta *pcm;
	pte_t pte;

	/*
	 * The identity change of PTEs and update of rmap are
	 * divided into two steps. There exists a small time frame
	 * where the rmap associted with the pcache points to
	 * wrong pte. This case will be detected by rmap_get_pte_locked().
	 */
	pte = ptep_get_and_clear(old_addr, old_pte);

	pcm = pte_to_pcache_meta(pte);
	BUG_ON(!pcm);

	lock_pcache(pcm);
	rmap_walk(pcm, &rwc);
	unlock_pcache(pcm);

	/*
	 * In theory, this should always succeed.
	 * Failure is not an option.
	 */
	BUG_ON(!mpi.updated);

	/* At last we update new_pte */
	pte_set(new_pte, pte);
}

static int __pcache_move_pte_slowpath(struct pcache_meta *old_pcm,
				      struct pcache_rmap *rmap, void *arg)
{
	struct pcache_move_pte_info *mpi = arg;
	struct pcache_meta *new_pcm;
	void *old_line, *new_line;

	if (unlikely(!matched_rmap_for_move(rmap, mpi)))
		return PCACHE_RMAP_AGAIN;

	/*
	 * XXX:
	 * Copy the content from old pcache to new pcache.
	 * This is not write-protected from other concurrent threads.
	 * But I think well-writtened applications should not write
	 * to a going-to-be-remapped memory region.
	 */
	new_pcm = mpi->new_pcm;
	old_line = pcache_meta_to_pa(old_pcm);
	new_line = pcache_meta_to_pa(new_pcm);
	memcpy(new_line, old_line, PCACHE_LINE_SIZE);

	pcache_remove_rmap(old_pcm, rmap);

	mpi->updated = true;
	return PCACHE_RMAP_SUCCEED;
}

/* Copy pcache line content from one set to another set */
static void pcache_move_pte_slowpath(struct mm_struct *mm,
				     pte_t *old_pte, pte_t *new_pte,
				     unsigned long old_addr, unsigned long new_addr)
{
	struct pcache_move_pte_info mpi = {
		.mm = mm,
		.old_pte = old_pte,
		.new_pte = new_pte,
		.old_addr = old_addr,
		.new_addr = new_addr,
		.updated = false,
	};
	struct rmap_walk_control rwc = {
		.arg = &mpi,
		.rmap_one = __pcache_move_pte_slowpath,
	};
	struct pcache_meta *old_pcm, *new_pcm;
	pte_t pte;

	pte = ptep_get_and_clear(old_addr, old_pte);

	old_pcm = pte_to_pcache_meta(pte);
	BUG_ON(!old_pcm);

	/* Alloc a line in the new set */
	new_pcm = pcache_alloc(new_addr);
	BUG_ON(!new_pcm);
	mpi.new_pcm = new_pcm;

	lock_pcache(old_pcm);
	rmap_walk(old_pcm, &rwc);
	unlock_pcache(old_pcm);

	/* Failure is not an option */
	BUG_ON(!mpi.updated);

	/*
	 * TODO: racy
	 * What if another thread just tried to lock
	 * the pcache? If others always get_pcache first
	 * then it is okay.
	 */
	if (!pcache_mapped(old_pcm))
		put_pcache(old_pcm);

	/* Update new pcache, and establish PTE */
	pcache_add_rmap(new_pcm, new_pte, new_addr, mm, current->group_leader);
	pte_set(new_pte, pte);
}

/*
 * Callback for move_ptes().
 * Both @old_pte and @new_pte are locked when called.
 * Batched TLB flush is performed by caller.
 */
void pcache_move_pte(struct mm_struct *mm, pte_t *old_pte, pte_t *new_pte,
		     unsigned long old_addr, unsigned long new_addr)
{
	unsigned long old_index, new_index;

	old_index = user_vaddr_to_set_index(old_addr);
	new_index = user_vaddr_to_set_index(new_addr);

	if (old_index == new_index)
		pcache_move_pte_fastpath(mm, old_pte, new_pte, old_addr, new_addr);
	else
		pcache_move_pte_slowpath(mm, old_pte, new_pte, old_addr, new_addr);
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

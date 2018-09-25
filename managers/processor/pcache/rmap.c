/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <lego/memblock.h>
#include <lego/profile_point.h>
#include <processor/pcache.h>
#include <processor/processor.h>

#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_DEBUG_PCACHE_RMAP
#define rmap_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void rmap_debug(const char *fmt, ...) { }
#endif

/*
 * FAT NOTE:
 * Our rmap points to PTE directly, and rmap operations are carried out
 * with pcache locked. Thus the lock ordering is:
 * 	- lock pset (optional)
 * 	- lock pcache
 * 	- lock pte
 *
 * And due to the rmap design, the lock ordering of pcache and pte can NOT
 * be changed. Other code the breaks this ordering guarantee should be very
 * careful not to introduce deadlock.
 */

/*
 * This is a pre-allocated pcache_rmap array.
 * It has a one-to-one mapping to pcache_meta_map.
 * Both are referenced by the same index.
 *
 * What if one pcm requires multiple rmaps (e.g. fork)? We use kmalloc.
 * Do note commonly each pcm is only mapped to one single process.
 * Thus this should speed things up a lot.
 */
static struct pcache_rmap *rmap_map;

static inline struct pcache_rmap *index_to_pcache_rmap(unsigned long index)
{
	return &rmap_map[index];
}

static struct pcache_rmap *alloc_pcache_rmap(struct pcache_meta *pcm)
{
	struct pcache_rmap *rmap;
	unsigned long index;

	index = __pcache_meta_index(pcm);
	rmap = index_to_pcache_rmap(index);

	/* Atomic test-and-set is a sync point */
	if (unlikely(TestSetRmapUsed(rmap))) {
		rmap = kzalloc(sizeof(*rmap), GFP_KERNEL);
		if (unlikely(!rmap))
			goto out;

		SetRmapKmalloced(rmap);
		inc_pcache_event(PCACHE_RMAP_ALLOC_KMALLOC);
	}

	/*
	 * No need to clear other fields
	 * because it will soon be filled
	 */
	INIT_LIST_HEAD(&rmap->next);

out:
	inc_pcache_event(PCACHE_RMAP_ALLOC);
	return rmap;
}

static void free_pcache_rmap(struct pcache_rmap *rmap)
{
	PCACHE_BUG_ON_RMAP(RmapReserved(rmap), rmap);

	if (unlikely(RmapKmalloced(rmap))) {
		kfree(rmap);
		inc_pcache_event(PCACHE_RMAP_FREE_KMALLOC);
		goto out;
	}

	/*
	 * Otherwise it is from pr-allocated array.
	 * Just clear the Used flag.
	 */
	if (unlikely(!TestClearRmapUsed(rmap))) {
		dump_pcache_rmap(rmap, NULL);
		BUG();
	}
out:
	inc_pcache_event(PCACHE_RMAP_FREE);
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
	static bool warned = false;

	if (warned)
		return;

	pcache_pfn = pcache_meta_to_pfn(pcm);
	_pte_pfn = pte_pfn(*ptep);

	pr_err("\n"
	       "****    ERROR:\n"
	       "****    current: %d:%s caller: %pS\n"
	       "****    [pte %s rmap->page_table] && [pcache_pfn %s pte_pfn]\n"
	       "****    rmap->owner_process: %s rmap->address: %#lx rmap->page_table: %p\n"
	       "****    address: %#lx ptep: %p\n"
	       "****    pcache_pfn: %#lx, pte_pfn: %#lx\n\n",
	        current->pid, current->comm, caller,
	        (ptep == rmap->page_table) ? "==":"!=",
	        (pcache_pfn == _pte_pfn) ? "==":"!=",
		rmap->owner_process->comm, rmap->address, rmap->page_table,
		address, ptep,
		pcache_pfn, _pte_pfn);

	dump_pcache_rmap(rmap, "Corrupted RMAP");
	dump_pcache_meta(pcm, "Corrupted RMAP");
	dump_pcache_rmaps_locked(pcm);

	if (pcache_pfn != _pte_pfn) {
		struct pcache_meta *weirdo;

		weirdo = pfn_to_pcache_meta(_pte_pfn);
		if (weirdo) {
			dump_pcache_meta(weirdo, "The weirdo");
			dump_pcache_rmaps(weirdo);
		}
	}

	WARN_ON_ONCE(1);
	warned = true;
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

static inline pte_t *
rmap_get_pte_unlocked(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, address);
	BUG_ON(pgd && !pgd_present(*pgd));

	pud = pud_offset(pgd, address);
	BUG_ON(!pud && !pud_present(*pud));

	pmd = pmd_offset(pud, address);
	BUG_ON(!pmd && !pmd_present(*pmd));

	pte = pte_offset(pmd, address);
	BUG_ON(!pte && !pte_present(*pte));

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
	unsigned long pcache_pfn = 0, _pte_pfn = 0;
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
	pr_info("pte: %p rmap->page_table: %p\n", pte, rmap->page_table);
	pr_info("pcache_pfn: %#lx, pte_pfn: %#lx\n", pcache_pfn, _pte_pfn);
	dump_pcache_meta(pcm, NULL);
	dump_pcache_rmap(rmap, NULL);
	panic("Validate pcache rmap failed!");
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

static inline void
validate_pcache_rmap(struct pcache_meta *pcm, struct pcache_rmap *rmap)
{

}

#endif /* CONFIG_DEBUG_PCACHE */

/*
 * Only trylock pte, don't race with normal operations.
 */
static __always_inline pte_t *
rmap_get_pte_trylock(struct pcache_meta *pcm, struct pcache_rmap *rmap,
		     spinlock_t **ptlp, int *pte_contention) __acquires(*ptlp)
{
	pte_t *ptep;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct mm_struct *mm = rmap->owner_mm;
	unsigned long address = rmap->address;

	pmd = rmap_get_pmd(mm, address);
	ptep = pte_offset(pmd, address);

	if (unlikely(ptep != rmap->page_table)) {
		ptep = NULL;
		goto out;
	}

	if (unlikely(pcache_meta_to_pfn(pcm) != pte_pfn(*ptep))) {
		ptep = NULL;
		goto out;
	}

	ptl = pte_lockptr(mm, pmd);
	if (!spin_trylock(ptl)) {
		*pte_contention = 1;
		ptep = NULL;
		goto out;
	}

	*pte_contention = 0;
	*ptlp = ptl;

out:
	return ptep;
}

/**
 * pcache_add_rmap
 * @pcm: pcache line in question
 * @page_table: the pointer to pte
 * @address: user virtual address mapped to this pcm
 * @owner_mm: the mm that owns @page_table
 * @owner_process: the process that owns @owner_mm
 *
 * This function add a reverse mapping to @pcm.
 * @page_table is locked when called.
 * @pcm must NOT be locked on entry.
 */
int pcache_add_rmap(struct pcache_meta *pcm, pte_t *page_table,
		    unsigned long address, struct mm_struct *owner_mm,
		    struct task_struct *owner_process,
		    enum rmap_caller caller)
{
	struct pcache_rmap *rmap, *pos;
	int ret;

	PCACHE_BUG_ON_PCM(PcacheLocked(pcm), pcm);
	PCACHE_BUG_ON(caller >= NR_RMAP_CALLER);

	lock_pcache(pcm);

	rmap = alloc_pcache_rmap(pcm);
	if (!rmap) {
		ret = -ENOMEM;
		goto out;
	}

	rmap->page_table = page_table;
	rmap->address = address & PAGE_MASK;
	rmap->owner_mm = owner_mm;
	rmap->caller = caller;

	/* Must be thread group leader */
	BUG_ON(!thread_group_leader(owner_process));
	rmap->owner_process = owner_process;

	if (likely(list_empty(&pcm->rmap)))
		goto add;

	/* No duplication */
	list_for_each_entry(pos, &pcm->rmap, next) {
		BUG_ON(pos->page_table == page_table);
		BUG_ON(pos->owner_mm == owner_mm);
		BUG_ON(pos->owner_process == owner_process);
	}

add:
	ret = 0;
	list_add(&rmap->next, &pcm->rmap);
	atomic_inc(&pcm->mapcount);

	/*
	 * Also informs eviction code that we could be
	 * selected as the eviction candidate.
	 */
	PCACHE_BUG_ON_PCM(PcacheReclaim(pcm) && !PcacheValid(pcm), pcm);
	SetPcacheValid(pcm);

	validate_pcache_rmap(pcm, rmap);
out:
	unlock_pcache(pcm);
	return ret;
}

/*
 * Internal function to remove one rmap from pcm
 * @pcm is locked upon entry.
 */
static inline void __pcache_remove_rmap(struct pcache_meta *pcm,
				        struct pcache_rmap *rmap)
{
	list_del(&rmap->next);
	free_pcache_rmap(rmap);

	/*
	 * There is no PTE map to this pcache anymore
	 * Clear the Valid bit
	 */
	if (likely(pcache_mapcount_dec_and_test(pcm)))
		ClearPcacheValid(pcm);
}

struct pcache_remove_rmap_info {
	struct mm_struct *mm;
	unsigned long address;
	pte_t *pte;
	bool removed;
};

static inline bool matched_rmap_for_remove(struct pcache_rmap *rmap,
					   struct pcache_remove_rmap_info *rri)
{
	if (rmap->page_table == rri->pte &&
	    rmap->owner_mm   == rri->mm  &&
	    rmap->address    == rri->address)
		return true;
	return false;
}

static int __pcache_remove_rmap_one(struct pcache_meta *pcm,
				    struct pcache_rmap *rmap, void *arg)
{
	struct pcache_remove_rmap_info *rri = arg;

	if (likely(matched_rmap_for_remove(rmap, rri))) {
		rmap_debug("tgid: %u [%#lx %p]",
			rmap->owner_process->tgid, rmap->address,
			rmap->page_table);

		__pcache_remove_rmap(pcm, rmap);
		rri->removed = true;

		/* Break the rmap walk loop */
		return PCACHE_RMAP_SUCCEED;
	}
	return PCACHE_RMAP_AGAIN;
}

/*
 * @pcm is locked when called
 * Not consistent with pcache_add_rmap, I know.
 */
void pcache_remove_rmap(struct pcache_meta *pcm, pte_t *ptep, unsigned long address,
			struct mm_struct *owner_mm, struct task_struct *owner_process)
{
	struct pcache_remove_rmap_info rri = {
		.mm = owner_mm,
		.address = address & PAGE_MASK,
		.pte = ptep,
		.removed = false,
	};
	struct rmap_walk_control rwc = {
		.arg = &rri,
		.rmap_one = __pcache_remove_rmap_one,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);
	rmap_walk(pcm, &rwc);

	/* Well, failure is not an option */
	if (unlikely(!rri.removed)) {
		pr_info("pte: %p ptent: %#lx address: %#lx\n",
			ptep, (unsigned long)ptep->pte, address);
		dump_pte(ptep, "fail to remove");
		WARN_ON_ONCE(1);
		return;
	}

	/*
	 * Unlike pcache_zap_pte, we don't need to put_cache here.
	 * Caller will do so. And normally, this pcm should have
	 * multiple users if this function is called from wp handler.
	 */
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

/*
 * All @pcm, @new_pte, @old_pte are locked
 * If matched, rmap is updated, new_pte is installed, old_pte is cleared.
 */
static int __pcache_move_pte_fastpath(struct pcache_meta *pcm,
				      struct pcache_rmap *rmap, void *arg)
{
	struct pcache_move_pte_info *mpi = arg;

	if (likely(matched_rmap_for_move(rmap, mpi))) {
		pte_t old_ptent;

		rmap_debug("tgid: %u [%#lx %p] -> [%#lx %p]",
			rmap->owner_process->tgid, rmap->address,
			rmap->page_table, mpi->new_addr, mpi->new_pte);

		rmap->page_table = mpi->new_pte;
		rmap->address = mpi->new_addr;
		mpi->updated = true;

		old_ptent = ptep_get_and_clear(mpi->old_addr, mpi->old_pte);
		PCACHE_BUG_ON_PCM(pte_to_pcache_meta(old_ptent) != pcm, pcm);
		pte_set(mpi->new_pte, old_ptent);

		validate_pcache_rmap(pcm, rmap);

		/* Break the rmap walk loop */
		return PCACHE_RMAP_SUCCEED;
	}
	return PCACHE_RMAP_AGAIN;
}

/*
 * Reuse the existing pcache line since both @old_addr and @new_addr belong
 * to the same pcache set. We just need to *update* the rmap information.
 */
static int pcache_move_pte_fastpath(struct mm_struct *mm,
				    pte_t *old_pte, pte_t *new_pte,
				    unsigned long old_addr, unsigned long new_addr,
				    spinlock_t *old_ptl)
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
	pte_t old_ptent;

	old_ptent = *old_pte;
	pcm = pte_to_pcache_meta(old_ptent);
	BUG_ON(!pcm);

	/* See comments on pcache_zap_pte */
	if (unlikely(!trylock_pcache(pcm))) {
		get_pcache(pcm);
		spin_unlock(old_ptl);

		lock_pcache(pcm);
		spin_lock(old_ptl);

		if (!pte_same(*old_pte, old_ptent)) {
			unlock_pcache(pcm);
			put_pcache(pcm);
			return -EAGAIN;
		}
		put_pcache(pcm);
	}
	rmap_walk(pcm, &rwc);
	unlock_pcache(pcm);

	/* Failure is not an option. */
	BUG_ON(!mpi.updated);
	return 0;
}

static int __pcache_move_pte_slowpath(struct pcache_meta *old_pcm,
				      struct pcache_rmap *rmap, void *arg)
{
	struct pcache_move_pte_info *mpi = arg;
	struct pcache_meta *new_pcm;
	void *old_line, *new_line;
	pte_t *new_pte, *old_pte;
	pte_t old_pte_entry, new_pte_entry;
	int ret;

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
	old_line = pcache_meta_to_kva(old_pcm);
	new_line = pcache_meta_to_kva(new_pcm);
	memcpy(new_line, old_line, PCACHE_LINE_SIZE);

	/* Clear old_pte */
	old_pte = mpi->old_pte;
	old_pte_entry = ptep_get_and_clear(mpi->old_addr, old_pte);
	PCACHE_BUG_ON_PCM(pte_to_pcache_meta(old_pte_entry) != old_pcm, old_pcm);
	__pcache_remove_rmap(old_pcm, rmap);

	/*
	 * Set new_pte before adding rmap,
	 * cause rmap may need to validate pte.
	 */
	new_pte = mpi->new_pte;
	new_pte_entry = pcache_dup_pte_pgprot(new_pcm, old_pte_entry);
	pte_set(new_pte, new_pte_entry);

	/*
	 * Adding rmap will mark new_pcm PcacheValid
	 * Thus can be selected as an eviction candidate.
	 */
	ret = pcache_add_rmap(new_pcm, new_pte, mpi->new_addr,
			      current->mm, current->group_leader, RMAP_MREMAP_SLOWPATH);
	if (ret) {
		WARN_ON(1);
		return PCACHE_RMAP_AGAIN;
	}

	rmap_debug("tgid: %d [va pa]: [%#lx %p] -> [%#lx %p]",
		rmap->owner_process->tgid, mpi->old_addr, old_line,
		mpi->new_addr, new_line);

	mpi->updated = true;
	return PCACHE_RMAP_SUCCEED;
}

/*
 * Copy pcache line content from one set to another set, since @old_addr and @new_addr
 * belong to different set. We must remove the rmap from old_pcm, and setup a new pcm.
 *
 * Overall flow:
 * - allocate a new pcm
 * - rmap walk to find the old_pcm, and remove it
 *   - copy data
 *   - clear old pte
 *   - set pte to point to new pcm
 *   - add rmap for new pcm
 * - try to free old pcm
 */
static int pcache_move_pte_slowpath(struct mm_struct *mm,
				    pte_t *old_pte, pte_t *new_pte,
				    unsigned long old_addr, unsigned long new_addr,
				    spinlock_t *old_ptl)
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
	pte_t old_pte_entry;
	int ret;

	old_pte_entry = *old_pte;
	old_pcm = pte_to_pcache_meta(old_pte_entry);
	BUG_ON(!old_pcm);

	/* Alloc a line in the new set */
	new_pcm = pcache_alloc(new_addr, DISABLE_PIGGYBACK);
	if (unlikely(!new_pcm)) {
		ret = -ENOMEM;
		goto out;
	}
	mpi.new_pcm = new_pcm;

	/* See comments on pcache_zap_pte */
	if (unlikely(!trylock_pcache(old_pcm))) {
		get_pcache(old_pcm);
		spin_unlock(old_ptl);

		lock_pcache(old_pcm);
		spin_lock(old_ptl);

		if (unlikely(!pte_same(*old_pte, old_pte_entry))) {
			unlock_pcache(old_pcm);
			put_pcache(old_pcm);
			return -EAGAIN;
		}
		put_pcache(old_pcm);
	}
	rmap_walk(old_pcm, &rwc);
	unlock_pcache(old_pcm);

	/* Failure is not an option */
	BUG_ON(!mpi.updated);

	/*
	 * Try to free the old pcm.
	 * Similar to pcache_zap_pte's last step.
	 */
	put_pcache(old_pcm);

	ret = 0;
out:
	return ret;
}

/*
 * Callback for move_ptes(), from mremap().
 * Both @old_pte and @new_pte are locked when called.
 * When called, @old_pte remains unchanged.
 * Batched TLB flush is performed by caller.
 */
int pcache_move_pte(struct mm_struct *mm, pte_t *old_pte, pte_t *new_pte,
		    unsigned long old_addr, unsigned long new_addr, spinlock_t *old_ptl)
{
	unsigned long old_index, new_index;

	old_index = user_vaddr_to_set_index(old_addr);
	new_index = user_vaddr_to_set_index(new_addr);

	if (old_index == new_index) {
		inc_pcache_event(PCACHE_MREMAP_PSET_SAME);
		return pcache_move_pte_fastpath(mm, old_pte, new_pte,
						old_addr, new_addr, old_ptl);
	} else {
		inc_pcache_event(PCACHE_MREMAP_PSET_DIFF);
		return pcache_move_pte_slowpath(mm, old_pte, new_pte,
						old_addr, new_addr, old_ptl);
	}
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

/*
 * Called with both @pcache and @pte locked
 * If matched, pte is cleared, rmap is removed
 */
static int __pcache_zap_pte(struct pcache_meta *pcm,
			    struct pcache_rmap *rmap, void *arg)
{
	struct pcache_zap_pte_control *zpc = arg;

	if (likely(matched_rmap_for_zap(rmap, zpc))) {
		rmap_debug("tgid: %u [%#lx %p]",
			rmap->owner_process->tgid, rmap->address,
			rmap->page_table);

		/* TLB batch flush is performed by caller */
		pte_clear(rmap->page_table);
		__pcache_remove_rmap(pcm, rmap);
		zpc->zapped = true;

		/* Break the rmap walk loop */
		return PCACHE_RMAP_SUCCEED;
	}
	return PCACHE_RMAP_AGAIN;
}

/*
 * Zap the rmap that currently points to @pte within @mm.
 *
 * Called from zap_pte_range() when the pgtable is going to be cleared.
 * When called, @pte remains untouched, and @ptent is @pte content.
 *
 * The higher level caller can be: munmap() and exit().
 * We might race with pcache_do_wp_page(), concurrent eviction.
 * We enter with @pte locked, return with @pte still locked.
 */
int pcache_zap_pte(struct mm_struct *mm, unsigned long address,
		   pte_t ptent, pte_t *pte, spinlock_t *ptl)
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
	if (unlikely(!pcm)) {
		pr_info("pte: %p ptent: %#lx address: %#lx\n",
			pte, (unsigned long)ptent.pte, address);
		dump_pte(pte, "corrupted");
		WARN_ON_ONCE(1);
		return 0;
	}

	/*
	 * We have a strict lock ordering everyone should obey:
	 * 	lock pcache
	 * 	lock pte
	 * The caller already locked pte, thus we should avoid deadlock here
	 * by droping pte lock first and then acquire both of them in order.
	 */
	if (unlikely(!trylock_pcache(pcm))) {
		/* in case it got evicted and @pcm becomes invalid */
		get_pcache(pcm);
		spin_unlock(ptl);

		lock_pcache(pcm);
		spin_lock(ptl);

		/*
		 * Since we dropped the lock, the pcache line might
		 * be got evicted in the middle.
		 */
		if (!pte_same(*pte, ptent)) {
			unlock_pcache(pcm);
			/*
			 * This put maybe decreases the ref to 0
			 * and eventually free the pcache line.
			 * This happens if the @pcm was selected
			 * to be evicted at the same time.
			 */
			put_pcache(pcm);
			return -EAGAIN;
		}
		put_pcache(pcm);
	}

	rmap_walk(pcm, &rwc);
	unlock_pcache(pcm);

	/*
	 * Failure is not an option!
	 * Why? You ask. Well, the above few lines of code make sure if we are
	 * here, then @pcm: 1) has not been selected as eviction candidate,
	 * cos we checked pte content after releasing the ptl lock.
	 * 2) will not be selected as condidate cos we locked pcache.
	 */
	if (unlikely(!zpc.zapped)) {
		pr_info("pte: %p ptent: %#lx address: %#lx\n",
			pte, (unsigned long)ptent.pte, address);
		dump_pte(pte, "corrupted");
		WARN_ON_ONCE(1);
		return 0;
	}

	/*
	 * Last step, try to free this pcache line
	 * Each rmap counts one refcount. If we are the
	 * only rmap, then this pcm will be freed.
	 */
	put_pcache(pcm);

	return 0;
}

static int pcache_try_to_unmap_one(struct pcache_meta *pcm,
				   struct pcache_rmap *rmap, void *arg)
{
	int ret = PCACHE_RMAP_AGAIN;
	bool *dirty = arg;
	spinlock_t *ptl = NULL;
	pte_t *pte;
	pte_t pteval;

	PCACHE_BUG_ON_RMAP(RmapReserved(rmap), rmap);

	pte = rmap_get_pte_locked(pcm, rmap, &ptl);
	if (unlikely(!pte))
		return ret;

	pteval = ptep_get_and_clear(0, pte);

	if (likely(pte_present(pteval))) {
		/*
		 * Dirty checking is only valid if present.
		 * Otherwise it is undefined behaviour.
		 */
		if (pte_dirty(pteval))
			*dirty = true;

		/*
		 * Flush any stale TLB entries.
		 * After this, pgfault on other cores will
		 * follow immediately, if they access this page.
		 */
		flush_tlb_mm_range(rmap->owner_mm,
				   rmap->address,
				   rmap->address + PAGE_SIZE -1);
	}

	__pcache_remove_rmap(pcm, rmap);

	spin_unlock(ptl);
	return ret;
}

/* Clear PTE, but keep rmap in the list with Reserved flag set */
static int pcache_try_to_unmap_reserve_one(struct pcache_meta *pcm,
					   struct pcache_rmap *rmap, void *arg)
{
	int ret = PCACHE_RMAP_AGAIN;
	bool *dirty = arg;
	spinlock_t *ptl = NULL;
	pte_t *pte;
	pte_t pteval;

	PCACHE_BUG_ON_RMAP(RmapReserved(rmap), rmap);

	pte = rmap_get_pte_locked(pcm, rmap, &ptl);
	if (unlikely(!pte))
		return ret;

	pteval = ptep_get_and_clear(0, pte);

	if (likely(pte_present(pteval))) {
		/*
		 * Dirty checking is only valid if present.
		 * Otherwise it is undefined behaviour.
		 */
		if (pte_dirty(pteval))
			*dirty = true;

		/*
		 * Flush any stale TLB entries.
		 * After this, pgfault on other cores will
		 * follow immediately, if they access this page.
		 */
		flush_tlb_mm_range(rmap->owner_mm,
				   rmap->address,
				   rmap->address + PAGE_SIZE -1);
	}

	SetRmapReserved(rmap);

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
	bool dirty = false;
	struct rmap_walk_control rwc = {
		.rmap_one = pcache_try_to_unmap_one,
		.done = pcache_mapcount_is_zero,
		.arg = &dirty,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	ret = rmap_walk(pcm, &rwc);
	if (!pcache_mapcount(pcm))
		ret = PCACHE_RMAP_SUCCEED;
	return ret;
}

/*
 * Try to remvoe all page table entries. In addition to that,
 * return true if any of them was dirty, otherwise return false.
 */
bool pcache_try_to_unmap_check_dirty(struct pcache_meta *pcm)
{
	bool dirty = false;
	struct rmap_walk_control rwc = {
		.rmap_one = pcache_try_to_unmap_one,
		.done = pcache_mapcount_is_zero,
		.arg = &dirty,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	/*
	 * No need to check return value though.
	 * Caller cares about dirty value more..
	 */
	rmap_walk(pcm, &rwc);
	return dirty;
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
	bool dirty = false;
	struct rmap_walk_control rwc = {
		.rmap_one = pcache_try_to_unmap_reserve_one,
		.done = pcache_mapcount_is_zero,
		.arg = &dirty,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	rmap_walk(pcm, &rwc);
	return PCACHE_RMAP_SUCCEED;
}

/*
 * The only difference with pcache_try_to_unmap_reserve() is that
 * we return if the @pcm is dirty or not. Caller may have different
 * actions depends on dirty status.
 */
bool pcache_try_to_unmap_reserve_check_dirty(struct pcache_meta *pcm)
{
	bool dirty = false;
	struct rmap_walk_control rwc = {
		.rmap_one = pcache_try_to_unmap_reserve_one,
		.done = pcache_mapcount_is_zero,
		.arg = &dirty,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	rmap_walk(pcm, &rwc);
	return dirty;
}

static int pcache_free_reserved_rmap_one(struct pcache_meta *pcm,
					 struct pcache_rmap *rmap, void *arg)
{
	/* Must be paired with unmap_reserve */
	PCACHE_BUG_ON_RMAP(!RmapReserved(rmap), rmap);
	ClearRmapReserved(rmap);

	__pcache_remove_rmap(pcm, rmap);
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
	int pte_contention;
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

static int pcache_referenced_trylock_one(struct pcache_meta *pcm,
					 struct pcache_rmap *rmap, void *arg)
{
	struct pcache_referenced_control *prc = arg;
	spinlock_t *ptl = NULL;
	pte_t *pte;
	int pte_contention;

	pte = rmap_get_pte_trylock(pcm, rmap, &ptl, &pte_contention);
	if (!pte) {
		prc->pte_contention = 1;
		goto out;
	}

	/*
	 * pte lock contention?
	 * Break the rmap walk and return.
	 */
	if (pte_contention) {
		prc->pte_contention = 1;
		goto out;
	}

	if (unlikely(!pte))
		return PCACHE_RMAP_AGAIN;

	if (ptep_clear_flush_young(pte))
		prc->referenced = 1;
	spin_unlock(ptl);

	/*
	 * We don't need to walk through the whole rmap list
	 * Once found one referenced rmap, we are good to go.
	 */
	if (prc->referenced)
		goto out;

	prc->mapcount--;
	if (!prc->mapcount)
		return PCACHE_RMAP_SUCCEED;
	return PCACHE_RMAP_AGAIN;

out:
	return PCACHE_RMAP_SUCCEED;
}

/*
 * Differences with pcache_referenced():
 *  - this function will only *trylock* the pte.
 *  - this function will return once one referenced pte is found
 */
void pcache_referenced_trylock(struct pcache_meta *pcm,
			       int *pte_referenced, int *pte_contention)
{
	struct pcache_referenced_control prc = {
		.mapcount = pcache_mapcount(pcm),
		.referenced = 0,
		.pte_contention = 0,
	};
	struct rmap_walk_control rwc = {
		.arg = (void *)&prc,
		.rmap_one = pcache_referenced_trylock_one,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	if (!pcache_mapped(pcm))
		goto out;

	rmap_walk(pcm, &rwc);

out:
	*pte_referenced = prc.referenced;
	*pte_contention = prc.pte_contention;
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

/*
 * Called during early boot
 * where we want to use memblock to reserve large map..
 */
void __init alloc_pcache_rmap_map(void)
{
	size_t size, total;

	size = sizeof(struct pcache_rmap);
	total = size * nr_cachelines;

	rmap_map = memblock_virt_alloc(total, PAGE_SIZE);
	if (!rmap_map)
		panic("Unable to allocate rmap map!");

	pr_info("%s(): rmap size: %zu B, total reserved: %zu B, at %p - %p\n",
		__func__, size, total, rmap_map, rmap_map + total);
}

/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes pcache callbacks for low-level architecture page faults.
 * Our responsibility here is to fill the PTE and pcache line, or report error
 * gracefully back to caller.
 *
 * Locking ordering:
 *	pcache_lok
 *	pte_lock
 *
 * RMAP operations will lock in this order. Pgfault code below will probably
 * acquire pte_lock first, then it must NOT call lock_pcache() anymore.
 */

#include <lego/mm.h>
#include <lego/smp.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/ratelimit.h>
#include <lego/checksum.h>
#include <lego/profile.h>
#include <lego/fit_ibapi.h>

#include <asm/io.h>
#include <asm/tlbflush.h>

#include <processor/pcache.h>
#include <processor/distvm.h>
#include <processor/zerofill.h>
#include <processor/processor.h>
#include <processor/replication.h>

#ifdef CONFIG_DEBUG_PCACHE_FILL
#ifdef CONFIG_DEBUG_PCACHE_FILL_UNLIMITED
#define pcache_fill_debug(fmt, ...)					\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
/* 4 msg/sec at most? */
static DEFINE_RATELIMIT_STATE(pcache_fill_debug_rs, 1, 4);

#define pcache_fill_debug(fmt, ...)					\
({									\
	if (__ratelimit(&pcache_fill_debug_rs))				\
		pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__);	\
})
#endif
#else
#define pcache_fill_debug(fmt, ...)	do { } while (0)
#endif

static void print_bad_pte(struct mm_struct *mm, unsigned long addr, pte_t pte,
			  struct pcache_meta *pcm)
{
	pgd_t *pgd = pgd_offset(mm, addr);
	pud_t *pud = pud_offset(pgd, addr);
	pmd_t *pmd = pmd_offset(pud, addr);

	pr_err("BUG: Bad page map in process %s pte:%08llx pmd:%08llx\n",
		current->comm, (long long)pte_val(pte), (long long)pmd_val(*pmd));

	if (pcm)
		dump_pcache_meta(pcm, "bad pte");
	dump_stack();
}

/*
 * @pcm is just newly allocated and untouched
 * Similar to what we do at __pcache_do_fill_page.
 */
static void piggyback_fallback(struct pcache_meta *pcm)
{
	struct pcache_set *pset;
	struct piggyback_info *pb = &pcm->pb;
	void *va_cache = pcache_meta_to_kva(pcm);

	__clflush_one(pb->tgid, pb->user_addr, pb->memory_nid,
		      pb->replication_nid, va_cache);

	pset = pcache_meta_to_pcache_set(pcm);
	pset_remove_eviction(pset, pcm, 1);
	ClearPcachePiggyback(pcm);

	inc_pcache_event(PCACHE_CLFLUSH_PIGGYBACK_FB);
}

/*
 * This is a shared common function to setup PTE.
 * The pcache line allocation and post-setup are standard.
 * But the specific fill_func may differ:
 *   1) fill from remote memory
 *   2) fill from victim cache
 *   3) zerofill, async req to remote memory.
 *
 * Return 0 on success, otherwise VM_FAULT_XXX on failures.
 */
int common_do_fill_page(struct mm_struct *mm, unsigned long address,
			pte_t *page_table, pte_t orig_pte, pmd_t *pmd,
			unsigned long flags, fill_func_t fill_func, void *arg,
			enum rmap_caller caller, enum piggyback_options piggyback)
{
	struct pcache_meta *pcm;
	spinlock_t *ptl;
	pte_t entry;
	int ret;

	pcm = pcache_alloc(address, piggyback);
	if (unlikely(!pcm))
		return VM_FAULT_OOM;

	/* TODO: Need right permission bits */
	entry = pcache_mk_pte(pcm, PAGE_SHARED_EXEC);

	/*
	 * Concurrent faults are serialized by this lock
	 * Once acquired lock, check if orig_pte is still the way we remembered.
	 */
	page_table = pte_offset_lock(mm, pmd, address, &ptl);
	if (unlikely(!pte_same(*page_table, orig_pte))) {
		/*
		 * Concurrent faults, and all of them tried to
		 * piggyback-capable pcache_alloc. Only one of
		 * them will do the actual net. So the other
		 * guys need to manually flush the dirty cache back.
		 */
		if (PcachePiggyback(pcm))
			piggyback_fallback(pcm);

		ret = 0;
		goto out;
	}

	/*
	 * Callback to specific fill function, which can be
	 * 1) remote memory
	 * 2) victim cache
	 * 3) zerofill
	 */
	ret = fill_func(address, flags, pcm, arg);
	if (unlikely(ret)) {
		ret = VM_FAULT_SIGSEGV;
		goto out;
	}

	/*
	 * Set pte before adding rmap,
	 * cause rmap may need to validate pte.
	 */
	pte_set(page_table, entry);

	/* which will also mark PcacheValid */
	ret = pcache_add_rmap(pcm, page_table, address,
			      mm, current->group_leader, caller);
	if (unlikely(ret)) {
		pte_clear(page_table);
		ret = VM_FAULT_OOM;
		goto out;
	}

	spin_unlock(ptl);
	return 0;

out:
	put_pcache(pcm);
	spin_unlock(ptl);
	return ret;
}

DEFINE_PROFILE_POINT(__pcache_fill_remote_net)
DEFINE_PROFILE_POINT(__pcache_fill_remote_piggyback_net)

static DEFINE_PER_CPU(struct p2m_pcache_miss_flush_combine_msg, pb_msg_array);

/*
 * Callback for common fill code
 * Fill the pcache line from remote memory.
 */
static int
__pcache_do_fill_page(unsigned long address, unsigned long flags,
		      struct pcache_meta *pcm, void *unused)
{
	int ret, len, dst_nid;
	struct pcache_set *pset;
	void *va_cache = pcache_meta_to_kva(pcm);
	struct p2m_pcache_miss_msg msg;
	PROFILE_POINT_TIME(__pcache_fill_remote_net)
	PROFILE_POINT_TIME(__pcache_fill_remote_piggyback_net)

	pset = pcache_meta_to_pcache_set(pcm);
	dst_nid = get_memory_node(current, address);

	/*
	 * Piggyback was set by perset eviction only.
	 * And we are very strict on this. This dirty line
	 * can only be mapped into one address space. All the
	 * necessary information has been saved into piggyback_info.
	 */
	if (PcachePiggyback(pcm)) {
		struct p2m_pcache_miss_flush_combine_msg *pb_msg;
		struct piggyback_info *pb = &pcm->pb;

		/*
		 * Okay. Flush and miss belong to different nodes.
		 * There have to be two network requests.
		 * fallback will clear Piggyback inside.
		 */
		if (unlikely(pb->memory_nid != dst_nid)) {
			piggyback_fallback(pcm);
			inc_pcache_event(PCACHE_FAULT_FILL_FROM_MEMORY_PIGGYBACK_FB);
			goto fallback;
		}

		/*
		 * Yes, Virginia. We need to replicate it.
		 * This used to be done within __clflush_one().
		 * Since we skipped it, we need to manually replicate.
		 *
		 * Used if CONFIG_REPLICATION_MEMORY is enabled.
		 */
		replicate(pb->tgid, pb->user_addr, pb->memory_nid,
			  pb->replication_nid, va_cache);

		pb_msg = this_cpu_ptr(&pb_msg_array);

		/* The pcache miss part */
		fill_common_header(&pb_msg->miss, P2M_PCACHE_MISS);
		pb_msg->miss.has_flush_msg = 1;
		pb_msg->miss.pid = current->pid;
		pb_msg->miss.tgid = current->tgid;
		pb_msg->miss.flags = flags;
		pb_msg->miss.missing_vaddr = address;

		/* The piggyback flush part */
		pb_msg->flush.pid = pb->tgid;
		pb_msg->flush.user_va = pb->user_addr;
		memcpy(pb_msg->flush.pcacheline, va_cache, PCACHE_LINE_SIZE);
		smp_wmb();

		PROFILE_START(__pcache_fill_remote_piggyback_net);
		len = ibapi_send_reply_timeout(dst_nid, pb_msg, sizeof(*pb_msg),
					       va_cache, PCACHE_LINE_SIZE, false,
					       DEF_NET_TIMEOUT);
		PROFILE_LEAVE(__pcache_fill_remote_piggyback_net);

		/*
		 * Remove the eviction entries from the pset
		 * also clear the piggyback flag
		 *
		 * Optimization is good for performance. But usually end up
		 * making the code much more complex. And we need to use
		 * APIs that are used to internal.
		 */
		pset_remove_eviction(pset, pcm, 1);
		ClearPcachePiggyback(pcm);
		inc_pcache_event(PCACHE_FAULT_FILL_FROM_MEMORY_PIGGYBACK);
	} else {
fallback:
		fill_common_header(&msg, P2M_PCACHE_MISS);
		msg.has_flush_msg = 0;
		msg.pid = current->pid;
		msg.tgid = current->tgid;
		msg.flags = flags;
		msg.missing_vaddr = address;

		PROFILE_START(__pcache_fill_remote_net);
		len = ibapi_send_reply_timeout(dst_nid, &msg, sizeof(msg),
					       va_cache, PCACHE_LINE_SIZE, false,
					       DEF_NET_TIMEOUT);
		PROFILE_LEAVE(__pcache_fill_remote_net);
	}

	if (unlikely(len < (int)PCACHE_LINE_SIZE)) {
		if (likely(len == sizeof(int))) {
			/* remote reported error */
			ret = -EFAULT;
			goto out;
		} else if (len < 0) {
			/*
			 * Network error:
			 * EIO: IB is not available
			 * ETIMEDOUT: timeout for reply
			 */
			ret = len;
			WARN_ON_ONCE(1);
			goto out;
		} else {
			WARN(1, "Invalid reply length: %d\n", len);
			ret = -EFAULT;
			goto out;
		}
	}

	ret = 0;
out:
	inc_pset_event(pset, PSET_FILL_MEMORY);
	inc_pcache_event(PCACHE_FAULT_FILL_FROM_MEMORY);
	return ret;
}

/*
 * This function handles normal cache line misses.
 * We enter with pte unlocked, we return with pte unlocked.
 */
static inline int
pcache_do_fill_page(struct mm_struct *mm, unsigned long address,
		    pte_t *page_table, pte_t orig_pte, pmd_t *pmd, unsigned long flags)
{
	return common_do_fill_page(mm, address, page_table, orig_pte, pmd, flags,
			__pcache_do_fill_page, NULL, RMAP_FILL_PAGE_REMOTE,
			ENABLE_PIGGYBACK);
}

#ifdef CONFIG_PCACHE_ZEROFILL
DEFINE_PROFILE_POINT(__pcache_fill_zerofill)

static int
__pcache_do_zerofill_page(unsigned long address, unsigned long flags,
			  struct pcache_meta *pcm, void *unused)
{
	void *pcache_kva;
	PROFILE_POINT_TIME(__pcache_fill_zerofill)

	PROFILE_START(__pcache_fill_zerofill);

	pcache_kva = pcache_meta_to_kva(pcm);
	memset(pcache_kva, 0, PCACHE_LINE_SIZE);

	/*
	 * Notify remote memory about this zerofill.
	 * This is disabled by default. Because it is not
	 * necessary to notify remote memory.
	 * Check PCACHE_ZEROFILL_NOTIFY_MEMORY Kconfig.
	 */
	submit_zerofill_notify_work(current, address, flags);

	inc_pcache_event(PCACHE_FAULT_FILL_ZEROFILL);
	PROFILE_LEAVE(__pcache_fill_zerofill);
	return 0;
}

/*
 * This function handles Anonymous Zero Fill page.
 * - Clear the pcache line
 * - Async send pcache miss request to remote memory
 */
static inline int
pcache_do_zerofill_page(struct mm_struct *mm, unsigned long address,
		    pte_t *page_table, pte_t orig_pte, pmd_t *pmd, unsigned long flags)
{
	if (unlikely(!pte_zerofill(orig_pte))) {
		dump_pte(page_table, "bad pte");
		print_bad_pte(mm, address, orig_pte, NULL);
		return VM_FAULT_SIGBUS;
	}
	return common_do_fill_page(mm, address, page_table, orig_pte, pmd, flags,
			__pcache_do_zerofill_page, NULL, RMAP_ZEROFILL,
			DISABLE_PIGGYBACK);
}
#else
/*
 * If ZeroFill is not configured, Lego will not fill any extra information into PTE.
 * Thus anything falls in here will be BUG indeed.
 */
static inline int
pcache_do_zerofill_page(struct mm_struct *mm, unsigned long address,
		    pte_t *page_table, pte_t orig_pte, pmd_t *pmd, unsigned long flags)
{
	BUG();
	return 0;
}
#endif

static inline void cow_pcache(struct pcache_meta *dst_pcm, struct pcache_meta *src_pcm)
{
	void *dst_vaddr, *src_vaddr;

	dst_vaddr = pcache_meta_to_kva(dst_pcm);
	src_vaddr = pcache_meta_to_kva(src_pcm);
	memcpy(dst_vaddr, src_vaddr, PCACHE_LINE_SIZE);
}

/*
 * This function handles present write-protected cache lines.
 *
 * We enter wirh pte *locked*, we return with pte *unlocked*.
 */
static int pcache_do_wp_page(struct mm_struct *mm, unsigned long address,
			     pte_t *page_table, pmd_t *pmd, spinlock_t *ptl,
			     pte_t orig_pte) __releases(ptl)
{
	struct pcache_meta *old_pcm;
	int ret;

	inc_pcache_event(PCACHE_FAULT_WP);

	old_pcm = pte_to_pcache_meta(orig_pte);
	if (!old_pcm) {
		print_bad_pte(mm, address, orig_pte, NULL);
		ret = VM_FAULT_SIGBUS;
		goto unlock_pte;
	}

	/*
	 * It is 100% impossible to see an invalid pcm here.
	 * We are holding pte lock. Even if this pcm was selected
	 * to be evicted, that thread will be blocked at
	 * pcache_try_to_unmap(). Thus must be valid.
	 */
	PCACHE_BUG_ON_PCM(!PcacheValid(old_pcm), old_pcm);
	PCACHE_BUG_ON_PCM(!pcache_mapped(old_pcm), old_pcm);

	/*
	 * pcache might be under flush back if pcache eviction is using
	 * write-protect mechanism to guarantee clflush atomicity.
	 *
	 * If this happens, pcache must have PcacheReclaim set. And it
	 * will be unmapped soon. But we are holding pte lock here, we
	 * should just release the lock and return. If a pgfault immediately
	 * follows after we return, it will: either comes here again,
	 * or it will fetch the page from remote (already unmapped).
	 */
#ifdef CONFIG_PCACHE_EVICTION_WRITE_PROTECT
	if (unlikely(PcacheReclaim(old_pcm))) {
		ret = 0;
		inc_pcache_event(PCACHE_FAULT_CONCUR_EVICTION)
		goto unlock_pte;
	}
#endif

	/* See comments on pcache_zap_pte */
	if (unlikely(!trylock_pcache(old_pcm))) {
		get_pcache(old_pcm);
		spin_unlock(ptl);

		lock_pcache(old_pcm);
		spin_lock(ptl);

		if (!pte_same(*page_table, orig_pte)) {
			unlock_pcache(old_pcm);
			spin_unlock(ptl);
			put_pcache(old_pcm);
			return 0;
		}
		put_pcache(old_pcm);
	}

	/*
	 * COW should only happen to fork()-ed pcache lines.
	 * But when the wp fault happens, some processes may already exit(),
	 * or did munmap to this shared mapping. Thus it is possible to have
	 * the mapcount == 1 case, where we can simply upgrade pte permission
	 * to RW, since we are the only user left.
	 *
	 * Do note, after fork(), any rmap pcache related operations will
	 * race with this function: exit(), mremap(), munmap(), or another fork().
	 * Since mapcount is always updated with pcm locked, we are stable here
	 */
	if (pcache_mapcount(old_pcm) == 1) {
		pte_t entry;

		entry = pte_mkyoung(orig_pte);
		entry = pte_mkdirty(entry);
		entry = pte_mkwrite(entry);
		*page_table = entry;

		inc_pcache_event(PCACHE_FAULT_WP_REUSE);
		ret = 0;
	} else {
		/* We need to make a copy */
		struct pcache_meta *new_pcm;
		pte_t entry;

		new_pcm = pcache_alloc(address, DISABLE_PIGGYBACK);
		if (!new_pcm) {
			ret = VM_FAULT_OOM;
			goto unlock_all;
		}
		cow_pcache(new_pcm, old_pcm);

		/* TODO: need right permission */
		entry = pcache_mk_pte(new_pcm, PAGE_SHARED_EXEC);
		entry = pte_mkdirty(entry);
		entry = pte_mkwrite(entry);

		pte_set(page_table, entry);
		flush_tlb_mm_range(mm, address, address + PAGE_SIZE);

		/* which will also mark new_pcm PcacheValid */
		ret = pcache_add_rmap(new_pcm, page_table, address,
				      current->mm, current->group_leader, RMAP_COW);
		if (unlikely(ret)) {
			put_pcache(new_pcm);
			pte_clear(page_table);
			ret = VM_FAULT_OOM;
			goto unlock_all;
		}

		/*
		 * Remove rmap from old_pcm and dec its refcount
		 * old_pcm must still be alive since there are
		 * other processes mapped to it.
		 */
		pcache_remove_rmap(old_pcm, page_table, address,
				   current->mm, current->group_leader);
		put_pcache(old_pcm);

		inc_pcache_event(PCACHE_FAULT_WP_COW);
		ret = 0;
	}

unlock_all:
	unlock_pcache(old_pcm);
unlock_pte:
	spin_unlock(ptl);
	return ret;
}

/*
 * Hack!!! Page fault may caused by many reasons. Besides, by the time we reach
 * here, the condition that caused this fault, may already been changed by
 * another CPU that has the same fault. Keep in mind that we are in a SMP system.
 *
 * pte lock can gurantee a lot things. We can check if the pte has been chanegd
 * after we acquire the lock. But pte lock can not gurantee us spurious TLB fault:
 * the case where TLB entries have different permission from page table entries.
 */
static int pcache_handle_pte_fault(struct mm_struct *mm, unsigned long address,
				   pte_t *pte, pmd_t *pmd, unsigned long flags)
{
	pte_t entry;
	spinlock_t *ptl;

	entry = *pte;
	if (likely(!pte_present(entry))) {
		if (pte_none(entry)) {
#ifdef CONFIG_PCACHE_EVICTION_PERSET_LIST
			/*
			 * Check per-set's current eviction list.
			 * Wait until cache line is fully flushed
			 * back to memory.
			 */
			while (pset_find_eviction(address, current)) {
				cpu_relax();
				inc_pcache_event(PCACHE_PSET_LIST_LOOKUP);
			}
#elif defined(CONFIG_PCACHE_EVICTION_VICTIM)
			/*
			 * Check victim cache
			 */
			if (victim_may_hit(address)) {
				if (!victim_try_fill_pcache(mm, address, pte, entry, pmd, flags))
					return 0;
			}
#endif
			/*
			 * write-protect
			 * per-set eviction list (flush finished)
			 * victim cache (miss)
			 *
			 * All of them fall-back and merge into this:
			 */
			return pcache_do_fill_page(mm, address, pte, entry, pmd, flags);
		}
		return pcache_do_zerofill_page(mm, address, pte, entry, pmd, flags);
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (unlikely(!pte_same(*pte, entry)))
		goto unlock;

	if (flags & FAULT_FLAG_WRITE) {
		if (likely(!pte_write(entry)))
			return pcache_do_wp_page(mm, address, pte, pmd, ptl, entry);
		else {
			/*
			 * HACK!!!
			 * We have cases that lead to here:
			 *
			 * 1) This will happen due to stale TLB entries. The page table
			 * entries are upgraded by remote CPUs. But they have not flush
			 * this CPU's TLB yet. This is a very small time window. But
			 * we've seen this during real testing.
			 *
			 * In x86, this is an empty function. I think this is valid.
			 * Because whenever permission upgrade happen, there will be
			 * TLB shootdown follows. We should just let this thread retry.
			 * Checkout https://lkml.org/lkml/2012/11/22/952
			 *
			 * 2) Two CPU fault into the same address concurrently, and both
			 * of them are Write. One CPU is faster than the other to establish
			 * the PTE, even before the slow CPU reaches the first line of this
			 * function. Thus the slow CPU will just saw a valid writeable PTE.
			 */
			flush_tlb_fix_spurious_fault(vma, address);
		}
	}

unlock:
	spin_unlock(ptl);
	return 0;
}

/**
 * pcache_handle_fault		-	Emulate DRAM cache miss
 * @mm: address space in question
 * @address: the missing virtual address
 * @flags: how the page fault happens
 *
 * This function emulate a DRAM cache miss. This function will
 * look up the mapping, send LLC miss request to corresponding
 * memory component, and establish the pgtable mapping at last.
 * This function is synchronous, and will involve network.
 *
 * Return 0 on success, otherwise return VM_FAULT_XXX flags.
 */
int pcache_handle_fault(struct mm_struct *mm,
			unsigned long address, unsigned long flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, address);
	pud = pud_alloc(mm, pgd, address);
	if (!pud)
		return VM_FAULT_OOM;
	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		return VM_FAULT_OOM;
	pte = pte_alloc(mm, pmd, address);
	if (!pte)
		return VM_FAULT_OOM;

	inc_pcache_event(PCACHE_FAULT);
	inc_pcache_event_cond(PCACHE_FAULT_CODE, !!(flags & FAULT_FLAG_INSTRUCTION));

	return pcache_handle_pte_fault(mm, address, pte, pmd, flags);
}

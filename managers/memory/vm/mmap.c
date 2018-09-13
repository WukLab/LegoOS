/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Virtual memory map management code
 * Based on mm/mmap.c and mm/mremap.c
 */

#include <lego/mm.h>
#include <lego/rwsem.h>
#include <lego/slab.h>
#include <lego/rbtree.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/netmacro.h>
#include <lego/fit_ibapi.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/vm-pgtable.h>
#include <memory/distvm.h>
#include <memory/file_types.h>

int sysctl_max_map_count __read_mostly = DEFAULT_MAX_MAP_COUNT;

static unsigned long
arch_get_unmapped_area(struct lego_task_struct *p, struct lego_file *filp,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	struct vm_area_struct *vma = NULL;
	struct lego_mm_struct *mm = p->mm;
	struct vm_unmapped_area_info info;
	unsigned long begin, end;

	vma_trace("%s, addr: %lx, len: %lx, pgoff: %lx, flag: %lx\n",
			__func__, addr, len, pgoff, flags);

	if (flags & MAP_FIXED)
		return addr;

	begin = mm->mmap_legacy_base;
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	end = mm->mmap_base;
#else
	end = TASK_SIZE;
#endif

	if (len > end)
		return -ENOMEM;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	if (addr && VMR_ALIGN(addr) != addr) {
#else
	if (addr) {
#endif
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (end - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}

	info.flags = 0;
	info.length = len;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = 0;
	info.align_offset = pgoff << PAGE_SHIFT;

	return vm_unmapped_area(p, &info);
}

static unsigned long
arch_get_unmapped_area_topdown(struct lego_task_struct *p, struct lego_file *filp,
		const unsigned long addr0, const unsigned long len,
		const unsigned long pgoff, const unsigned long flags)
{
	struct vm_area_struct *vma = NULL;
	struct lego_mm_struct *mm = p->mm;
	unsigned long addr = addr0;
	struct vm_unmapped_area_info info;

	vma_trace("%s, addr: %lx, len: %lx, pgoff: %lx, flag: %lx\n",
			__func__, addr, len, pgoff, flags);

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	/* requesting a specific address */
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	if (addr && VMR_ALIGN(addr) != addr) {
#else
	if (addr) {
#endif
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
				(!vma || addr + len <= vma->vm_start))
			return addr;
	}

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	info.low_limit = mm->mmap_legacy_base;
#else
	info.low_limit = PAGE_SIZE;
#endif
	info.high_limit = mm->mmap_base;
	info.align_mask = 0;
	info.align_offset = pgoff << PAGE_SHIFT;

	addr = vm_unmapped_area(p, &info);
	if (!(addr & ~PAGE_MASK))
		return addr;
	BUG_ON(addr != -ENOMEM);

	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	return arch_get_unmapped_area(p, filp, addr0, len, pgoff, flags);
}

/*
 * Top of mmap area (just below the process stack).
 *
 * Leave an at least 128 MB hole.
 */
#define MIN_GAP	(128*1024*1024UL)
#define MAX_GAP	(TASK_SIZE/6*5)

static unsigned long mmap_base(void)
{
	unsigned long gap = 0; /* TODO: rlimit */

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(TASK_SIZE - gap);
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct lego_mm_struct *lego_mm)
{
	lego_mm->mmap_legacy_base = TASK_UNMAPPED_BASE;
	lego_mm->mmap_base = mmap_base();
	lego_mm->get_unmapped_area = arch_get_unmapped_area_topdown;
}

static long vma_compute_subtree_gap(struct vm_area_struct *vma)
{
	unsigned long max, subtree_gap;

	max = vma->vm_start;
	if (vma->vm_prev)
		max -= vma->vm_prev->vm_end;
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	else {
		struct vma_tree *root = get_vmatree_by_addr(vma->vm_mm, vma->vm_start);
		max -= root->begin;
	}
#endif
	if (vma->vm_rb.rb_left) {
		subtree_gap = rb_entry(vma->vm_rb.rb_left,
				struct vm_area_struct, vm_rb)->rb_subtree_gap;
		if (subtree_gap > max)
			max = subtree_gap;
	}
	if (vma->vm_rb.rb_right) {
		subtree_gap = rb_entry(vma->vm_rb.rb_right,
				struct vm_area_struct, vm_rb)->rb_subtree_gap;
		if (subtree_gap > max)
			max = subtree_gap;
	}
	return max;
}

#ifdef CONFIG_DEBUG_VM_RB
static int browse_rb(struct lego_mm_struct *mm)
{
	struct rb_root *root = &mm->mm_rb;
	int i = 0, j, bug = 0;
	struct rb_node *nd, *pn = NULL;
	unsigned long prev = 0, pend = 0;

	for (nd = rb_first(root); nd; nd = rb_next(nd)) {
		struct vm_area_struct *vma = NULL;
		vma = rb_entry(nd, struct vm_area_struct, vm_rb);
		if (vma->vm_start < prev) {
			pr_emerg("vm_start %lx < prev %lx\n",
				  vma->vm_start, prev);
			bug = 1;
		}
		if (vma->vm_start < pend) {
			pr_emerg("vm_start %lx < pend %lx\n",
				  vma->vm_start, pend);
			bug = 1;
		}
		if (vma->vm_start > vma->vm_end) {
			pr_emerg("vm_start %lx > vm_end %lx\n",
				  vma->vm_start, vma->vm_end);
			bug = 1;
		}
		spin_lock(&mm->lego_page_table_lock);
		if (vma->rb_subtree_gap != vma_compute_subtree_gap(vma)) {
			pr_emerg("free gap %lx, correct %lx\n",
			       vma->rb_subtree_gap,
			       vma_compute_subtree_gap(vma));
			bug = 1;
		}
		spin_unlock(&mm->lego_page_table_lock);
		i++;
		pn = nd;
		prev = vma->vm_start;
		pend = vma->vm_end;
	}
	j = 0;
	for (nd = pn; nd; nd = rb_prev(nd))
		j++;
	if (i != j) {
		pr_emerg("backwards %d, forwards %d\n", j, i);
		bug = 1;
	}
	return bug ? -1 : i;
}

static void validate_mm_rb(struct rb_root *root, struct vm_area_struct *ignore)
{
	struct rb_node *nd = NULL;

	for (nd = rb_first(root); nd; nd = rb_next(nd)) {
		struct vm_area_struct *vma;
		vma = rb_entry(nd, struct vm_area_struct, vm_rb);
		VM_BUG_ON_VMA(vma != ignore &&
			vma->rb_subtree_gap != vma_compute_subtree_gap(vma),
			vma);
	}
}

static void validate_mm(struct lego_mm_struct *mm)
{
	int bug = 0;
	int i = 0;
	unsigned long highest_address = 0;
	struct vm_area_struct *vma = mm->mmap;

	while (vma) {
		highest_address = vma->vm_end;
		vma = vma->vm_next;
		i++;
	}
	if (i != mm->map_count) {
		pr_emerg("map_count %d vm_next %d\n", mm->map_count, i);
		bug = 1;
	}
	if (highest_address != mm->highest_vm_end) {
		pr_emerg("mm->highest_vm_end %lx, found %lx\n",
			  mm->highest_vm_end, highest_address);
		bug = 1;
	}
	i = browse_rb(mm);
	if (i != mm->map_count) {
		if (i != -1)
			pr_emerg("map_count %d rb %d\n", mm->map_count, i);
		bug = 1;
	}
	VM_BUG_ON_MM(bug, mm);
}
#else
#define validate_mm_rb(root, ignore) do { } while (0)
#define validate_mm(mm) do { } while (0)
#endif


/* description of effects of mapping type and prot in current implementation.
 * this is due to the limited x86 page protection hardware.  The expected
 * behavior is in parens:
 *
 * map_type	prot
 *		PROT_NONE	PROT_READ	PROT_WRITE	PROT_EXEC
 * MAP_SHARED	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (yes) yes	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *
 * MAP_PRIVATE	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (copy) copy	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *
 * On arm64, PROT_EXEC has the following behaviour for both MAP_SHARED and
 * MAP_PRIVATE:
 *								r: (no) no
 *								w: (no) no
 *								x: (yes) yes
 */
pgprot_t protection_map[16] = {
	__P000, __P001, __P010, __P011, __P100, __P101, __P110, __P111,
	__S000, __S001, __S010, __S011, __S100, __S101, __S110, __S111
};

pgprot_t vm_get_page_prot(unsigned long vm_flags)
{
	return __pgprot(pgprot_val(protection_map[vm_flags &
				(VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)]));
}

static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
{
	pgprotval_t preservebits = pgprot_val(oldprot) & _PAGE_CHG_MASK;
	pgprotval_t addbits = pgprot_val(newprot);
	return __pgprot(preservebits | addbits);
}

static pgprot_t vm_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
{
	return pgprot_modify(oldprot, vm_get_page_prot(vm_flags));
}

/* Update vma->vm_page_prot to reflect vma->vm_flags. */
void vma_set_page_prot(struct vm_area_struct *vma)
{
	unsigned long vm_flags = vma->vm_flags;
	pgprot_t vm_page_prot;

	vm_page_prot = vm_pgprot_modify(vma->vm_page_prot, vm_flags);

	/* remove_protection_ptes reads vma->vm_page_prot without mmap_sem */
	WRITE_ONCE(vma->vm_page_prot, vm_page_prot);
}

RB_DECLARE_CALLBACKS(static, vma_gap_callbacks, struct vm_area_struct, vm_rb,
		     unsigned long, rb_subtree_gap, vma_compute_subtree_gap)

/*
 * Update augmented rbtree rb_subtree_gap values after vma->vm_start or
 * vma->vm_prev->vm_end values changed, without modifying the vma's position
 * in the rbtree.
 */

void vma_gap_update(struct vm_area_struct *vma)
{
	/*
	 * As it turns out, RB_DECLARE_CALLBACKS() already created a callback
	 * function that does exacltly what we want.
	 */
	vma_gap_callbacks_propagate(&vma->vm_rb, NULL);
}

static inline void vma_rb_insert(struct vm_area_struct *vma,
				 struct rb_root *root)
{
	/* All rb_subtree_gap values must be consistent prior to insertion */
	validate_mm_rb(root, NULL);

	rb_insert_augmented(&vma->vm_rb, root, &vma_gap_callbacks);
}

static void __vma_rb_erase(struct vm_area_struct *vma, struct rb_root *root)
{
	/*
	 * Note rb_erase_augmented is a fairly large inline function,
	 * so make sure we instantiate it only once with our desired
	 * augmented rbtree callbacks.
	 */
	rb_erase_augmented(&vma->vm_rb, root, &vma_gap_callbacks);
}

static __always_inline void vma_rb_erase_ignore(struct vm_area_struct *vma,
						struct rb_root *root,
						struct vm_area_struct *ignore)
{
	/*
	 * All rb_subtree_gap values must be consistent prior to erase,
	 * with the possible exception of the "next" vma being erased if
	 * next->vm_start was reduced.
	 */
	validate_mm_rb(root, ignore);

	__vma_rb_erase(vma, root);
}

static __always_inline void vma_rb_erase(struct vm_area_struct *vma,
					 struct rb_root *root)
{
	/*
	 * All rb_subtree_gap values must be consistent prior to erase,
	 * with the possible exception of the vma being erased.
	 */
	validate_mm_rb(root, vma);

	__vma_rb_erase(vma, root);
}

/* Find the first VMA which satisfies  addr < vm_end,  NULL if none. */
struct vm_area_struct *find_vma(struct lego_mm_struct *mm, unsigned long addr)
{
	struct rb_node *rb_node = NULL;
	struct vm_area_struct *vma = NULL;
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	struct vma_tree *root = get_vmatree_by_addr(mm, addr);

	if (!root || !is_local(root->mnode))
		return NULL;

	rb_node = root->vm_rb.rb_node;
#else
	rb_node = mm->mm_rb.rb_node;
#endif
	while (rb_node) {
		struct vm_area_struct *tmp;

		tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

		if (tmp->vm_end > addr) {
			vma = tmp;
			if (tmp->vm_start <= addr) {
				break;
			}
			rb_node = rb_node->rb_left;
		} else {
			rb_node = rb_node->rb_right;
		}
	}

	return vma;
}

void __vma_link_rb(struct lego_mm_struct *mm, struct vm_area_struct *vma,
		struct rb_node **rb_link, struct rb_node *rb_parent)
{
	/* Update tracking information for the gap following the new vma. */
	if (vma->vm_next)
		vma_gap_update(vma->vm_next);
	else
		mm->highest_vm_end = vma->vm_end;

	/*
	 * vma->vm_prev wasn't known when we followed the rbtree to find the
	 * correct insertion point for that vma. As a result, we could not
	 * update the vma vm_rb parents rb_subtree_gap values on the way down.
	 * So, we first insert the vma with a zero rb_subtree_gap value
	 * (to be consistent with what we did on the way down), and then
	 * immediately update the gap to the correct value. Finally we
	 * rebalance the rbtree after all augmented values have been set.
	 */
	rb_link_node(&vma->vm_rb, rb_parent, rb_link);
	vma->rb_subtree_gap = 0;
	vma_gap_update(vma);
	vma_rb_insert(vma, &mm->mm_rb);
}

void __vma_link_list(struct lego_mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev, struct rb_node *rb_parent)
{
	struct vm_area_struct *next = NULL;

	vma->vm_prev = prev;
	if (prev) {
		next = prev->vm_next;
		prev->vm_next = vma;
	} else {
		mm->mmap = vma;
		if (rb_parent)
			next = rb_entry(rb_parent,
					struct vm_area_struct, vm_rb);
		else
			next = NULL;
	}
	vma->vm_next = next;
	if (next)
		next->vm_prev = vma;
}

static void
__vma_link(struct lego_mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, struct rb_node **rb_link,
	struct rb_node *rb_parent)
{
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
}

static void vma_link(struct lego_mm_struct *mm, struct vm_area_struct *vma,
			struct vm_area_struct *prev, struct rb_node **rb_link,
			struct rb_node *rb_parent)
{
	__vma_link(mm, vma, prev, rb_link, rb_parent);

	mm->map_count++;
	validate_mm(mm);
}

static int find_vma_links(struct lego_mm_struct *mm, unsigned long addr,
		unsigned long end, struct vm_area_struct **pprev,
		struct rb_node ***rb_link, struct rb_node **rb_parent)
{
	struct rb_node **__rb_link, *__rb_parent, *rb_prev;

	vma_trace("%s, addr: %lx, end: %lx\n", __func__, addr, end);

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			/* Fail if an existing vma overlaps the area */
			if (vma_tmp->vm_start < end)
				return -ENOMEM;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return 0;
}

/*
 * Helper for vma_adjust() in the split_vma insert case: insert a vma into the
 * mm's list and rbtree.  It has already been inserted into the interval tree.
 */
static void __insert_vm_struct(struct lego_mm_struct *mm, struct vm_area_struct *vma)
{
	struct vm_area_struct *prev;
	struct rb_node **rb_link, *rb_parent;

	if (find_vma_links(mm, vma->vm_start, vma->vm_end,
			   &prev, &rb_link, &rb_parent))
		BUG();
	__vma_link(mm, vma, prev, rb_link, rb_parent);
	mm->map_count++;
}

/*
 * Insert vm structure into process list sorted by address
 * and into the inode's i_mmap tree.  If vm_file is non-NULL
 * then i_mmap_rwsem is taken here.
 */
int insert_vm_struct(struct lego_mm_struct *mm, struct vm_area_struct *vma)
{
	struct vm_area_struct *prev;
	struct rb_node **rb_link, *rb_parent;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	struct vma_tree *root = NULL;
	u64 addr = vmpool_alloc(&mm->vmpool_rb, vma->vm_start,
				vma->vm_end - vma->vm_start, MAP_FIXED);

	vma_trace("%s, addr: %Lx\n", __func__, addr);
	if (IS_ERR((void*)addr))
		return addr;

	if (map_vmatrees(mm, LEGO_LOCAL_NID, addr, TASK_SIZE - addr, 0))
		return -ENOMEM;

	root = get_vmatree_by_addr(mm, addr);
	load_vma_context(mm, root);
#endif

	if (find_vma_links(mm, vma->vm_start, vma->vm_end,
			   &prev, &rb_link, &rb_parent))
		return -ENOMEM;

	/*
	 * The vm_pgoff of a purely anonymous vma should be irrelevant
	 * until its first write fault, when page's anon_vma and index
	 * are set.  But now set the vm_pgoff it will almost certainly
	 * end up with (unless mremap moves it elsewhere before that
	 * first wfault), so /proc/pid/maps tells a consistent story.
	 *
	 * By setting it to reflect the virtual start address of the
	 * vma, merges and splits can happen in a seamless way, just
	 * using the existing file pgoff checks and manipulations.
	 * Similarly in do_mmap_pgoff and in do_brk.
	 */
	if (vma_is_anonymous(vma)) {
		vma->vm_pgoff = vma->vm_start >> PAGE_SHIFT;
	}

	vma_link(mm, vma, prev, rb_link, rb_parent);

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	save_update_vma_context(mm, root);
	sort_node_gaps(mm, root);
#endif
	return 0;
}

static __always_inline void __vma_unlink_common(struct lego_mm_struct *mm,
						struct vm_area_struct *vma,
						struct vm_area_struct *prev,
						bool has_prev,
						struct vm_area_struct *ignore)
{
	struct vm_area_struct *next;

	vma_rb_erase_ignore(vma, &mm->mm_rb, ignore);
	next = vma->vm_next;
	if (has_prev)
		prev->vm_next = next;
	else {
		prev = vma->vm_prev;
		if (prev)
			prev->vm_next = next;
		else
			mm->mmap = next;
	}
	if (next)
		next->vm_prev = prev;
}

static inline void __vma_unlink_prev(struct lego_mm_struct *mm,
				     struct vm_area_struct *vma,
				     struct vm_area_struct *prev)
{
	__vma_unlink_common(mm, vma, prev, true, vma);
}

/*
 * We cannot adjust vm_start, vm_end, vm_pgoff fields of a vma that
 * is already present in an i_mmap tree without adjusting the tree.
 * The following helper function should be used when such adjustments
 * are necessary.  The "insert" vma (if any) is to be inserted
 * before we drop the necessary locks.
 */
int __vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert,
	struct vm_area_struct *expand)
{
	struct lego_mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *next = vma->vm_next;
	struct lego_file *file = vma->vm_file;
	bool start_changed = false, end_changed = false;
	long adjust_next = 0;
	int remove_next = 0;

	vma_trace("%s, start: %lx, end: %lx\n", __func__, start, end);
	if (next && !insert) {
		struct vm_area_struct *exporter = NULL, *importer = NULL;

		if (end >= next->vm_end) {
			/*
			 * vma expands, overlapping all the next, and
			 * perhaps the one after too (mprotect case 6).
			 * The only other cases that gets here are
			 * case 1, case 7 and case 8.
			 */
			if (next == expand) {
				/*
				 * The only case where we don't expand "vma"
				 * and we expand "next" instead is case 8.
				 */
				VM_WARN_ON(end != next->vm_end);
				/*
				 * remove_next == 3 means we're
				 * removing "vma" and that to do so we
				 * swapped "vma" and "next".
				 */
				remove_next = 3;
				VM_WARN_ON(file != next->vm_file);
				swap(vma, next);
			} else {
				VM_WARN_ON(expand != vma);
				/*
				 * case 1, 6, 7, remove_next == 2 is case 6,
				 * remove_next == 1 is case 1 or 7.
				 */
				remove_next = 1 + (end > next->vm_end);
				VM_WARN_ON(remove_next == 2 &&
					   end != next->vm_next->vm_end);
				VM_WARN_ON(remove_next == 1 &&
					   end != next->vm_end);
				/* trim end to next, for case 6 first pass */
				end = next->vm_end;
			}

			exporter = next;
			importer = vma;

			/*
			 * If next doesn't have anon_vma, import from vma after
			 * next, if the vma overlaps with it.
			 */
#if 0
			if (remove_next == 2 && !next->anon_vma)
				exporter = next->vm_next;
#else
			if (remove_next == 2) {
				WARN_ONCE(1, "Not sure if this change is correct");
				exporter = next->vm_next;
			}
#endif

		} else if (end > next->vm_start) {
			/*
			 * vma expands, overlapping part of the next:
			 * mprotect case 5 shifting the boundary up.
			 */
			adjust_next = (end - next->vm_start) >> PAGE_SHIFT;
			exporter = next;
			importer = vma;
			VM_WARN_ON(expand != importer);
		} else if (end < vma->vm_end) {
			/*
			 * vma shrinks, and !insert tells it's not
			 * split_vma inserting another: so it must be
			 * mprotect case 4 shifting the boundary down.
			 */
			adjust_next = -((vma->vm_end - end) >> PAGE_SHIFT);
			exporter = vma;
			importer = next;
			VM_WARN_ON(expand != importer);
		}
	}
again:
	if (start != vma->vm_start) {
		vma->vm_start = start;
		start_changed = true;
	}
	if (end != vma->vm_end) {
		vma->vm_end = end;
		end_changed = true;
	}
	vma->vm_pgoff = pgoff;
	if (adjust_next) {
		next->vm_start += adjust_next << PAGE_SHIFT;
		next->vm_pgoff += adjust_next;
	}

	if (remove_next) {
		/*
		 * vma_merge has merged next into vma, and needs
		 * us to remove next before dropping the locks.
		 */
		if (remove_next != 3)
			__vma_unlink_prev(mm, next, vma);
		else
			/*
			 * vma is not before next if they've been
			 * swapped.
			 *
			 * pre-swap() next->vm_start was reduced so
			 * tell validate_mm_rb to ignore pre-swap()
			 * "next" (which is stored in post-swap()
			 * "vma").
			 */
			__vma_unlink_common(mm, next, NULL, false, vma);
	} else if (insert) {
		/*
		 * split_vma has split insert from vma, and needs
		 * us to insert it before dropping the locks
		 * (it may either follow vma or precede it).
		 */
		__insert_vm_struct(mm, insert);
	} else {
		if (start_changed)
			vma_gap_update(vma);
		if (end_changed) {
			if (!next)
				mm->highest_vm_end = end;
			else if (!adjust_next)
				vma_gap_update(next);
		}
	}

	if (remove_next) {
		mm->map_count--;
		kfree(next);
		/*
		 * In mprotect's case 6 (see comments on vma_merge),
		 * we must remove another next too. It would clutter
		 * up the code too much to do both in one go.
		 */
		if (remove_next != 3) {
			/*
			 * If "next" was removed and vma->vm_end was
			 * expanded (up) over it, in turn
			 * "next->vm_prev->vm_end" changed and the
			 * "vma->vm_next" gap must be updated.
			 */
			next = vma->vm_next;
		} else {
			/*
			 * For the scope of the comment "next" and
			 * "vma" considered pre-swap(): if "vma" was
			 * removed, next->vm_start was expanded (down)
			 * over it and the "next" gap must be updated.
			 * Because of the swap() the post-swap() "vma"
			 * actually points to pre-swap() "next"
			 * (post-swap() "next" as opposed is now a
			 * dangling pointer).
			 */
			next = vma;
		}
		if (remove_next == 2) {
			remove_next = 1;
			end = next->vm_end;
			goto again;
		}
		else if (next)
			vma_gap_update(next);
		else {
			/*
			 * If remove_next == 2 we obviously can't
			 * reach this path.
			 *
			 * If remove_next == 3 we can't reach this
			 * path because pre-swap() next is always not
			 * NULL. pre-swap() "next" is not being
			 * removed and its next->vm_end is not altered
			 * (and furthermore "end" already matches
			 * next->vm_end in remove_next == 3).
			 *
			 * We reach this only in the remove_next == 1
			 * case if the "next" vma that was removed was
			 * the highest vma of the mm. However in such
			 * case next->vm_end == "end" and the extended
			 * "vma" has vma->vm_end == next->vm_end so
			 * mm->highest_vm_end doesn't need any update
			 * in remove_next == 1 case.
			 */
			VM_WARN_ON(mm->highest_vm_end != end);
		}
	}

	validate_mm(mm);

	return 0;
}

/*
 * Anonymous vma is only mergeable with anonymous vma
 * File-backed vma is only mergeable with file-backed vma
 */
static inline int is_mergeable_vma(struct vm_area_struct *vma,
				   struct lego_file *file, unsigned long vm_flags)
{
	if (vma->vm_file != file)
		return 0;
	return 1;
}

/*
 * Return true if we can merge this (vm_flags,file,vm_pgoff)
 * in front of (at a lower virtual address and file offset than) the vma.
 */
static int
can_vma_merge_before(struct vm_area_struct *vma, unsigned long vm_flags,
		     struct lego_file *file, pgoff_t vm_pgoff)
{
	if (is_mergeable_vma(vma, file, vm_flags)) {
		/*
		 * Anonymous vmas can merge no matter what
		 */
		if (vma_is_anonymous(vma)) {
			return 1;
		} else {
			/* File-backed VMA */
			if (vma->vm_pgoff == vm_pgoff)
				return 1;
		}
	}
	return 0;
}

/*
 * Return true if we can merge this (vm_flags,file,vm_pgoff)
 * beyond (at a higher virtual address and file offset than) the vma.
 */
static int
can_vma_merge_after(struct vm_area_struct *vma, unsigned long vm_flags,
		    struct lego_file *file, pgoff_t vm_pgoff)
{
	if (is_mergeable_vma(vma, file, vm_flags)) {
		/*
		 * Anonymous vmas can merge no matter what
		 */
		if (vma_is_anonymous(vma)) {
			return 1;
		} else {
			/* File-backed VMA */
			pgoff_t vm_pglen;
			vm_pglen = vma_pages(vma);
			if (vma->vm_pgoff + vm_pglen == vm_pgoff)
				return 1;
		}
	}
	return 0;
}

/*
 * Given a mapping request (addr,end,vm_flags,file,pgoff), figure out
 * whether that can be merged with its predecessor or its successor.
 * Or both (it neatly fills a hole).
 *
 * In most cases - when called for mmap, brk or mremap - [addr,end) is
 * certain not to be mapped by the time vma_merge is called; but when
 * called for mprotect, it is certain to be already mapped (either at
 * an offset within prev, or at the start of next), and the flags of
 * this area are about to be changed to vm_flags - and the no-change
 * case has already been eliminated.
 *
 * The following mprotect cases have to be considered, where AAAA is
 * the area passed down from mprotect_fixup, never extending beyond one
 * vma, PPPPPP is the prev vma specified, and NNNNNN the next vma after:
 *
 *     AAAA             AAAA                AAAA          AAAA
 *    PPPPPPNNNNNN    PPPPPPNNNNNN    PPPPPPNNNNNN    PPPPNNNNXXXX
 *    cannot merge    might become    might become    might become
 *                    PPNNNNNNNNNN    PPPPPPPPPPNN    PPPPPPPPPPPP 6 or
 *    mmap, brk or    case 4 below    case 5 below    PPPPPPPPXXXX 7 or
 *    mremap move:                                    PPPPXXXXXXXX 8
 *        AAAA
 *    PPPP    NNNN    PPPPPPPPPPPP    PPPPPPPPNNNN    PPPPNNNNNNNN
 *    might become    case 1 below    case 2 below    case 3 below
 *
 * It is important for case 8 that the the vma NNNN overlapping the
 * region AAAA is never going to extended over XXXX. Instead XXXX must
 * be extended in region AAAA and NNNN must be removed. This way in
 * all cases where vma_merge succeeds, the moment vma_adjust drops the
 * rmap_locks, the properties of the merged vma will be already
 * correct for the whole merged range. Some of those properties like
 * vm_page_prot/vm_flags may be accessed by rmap_walks and they must
 * be correct for the whole merged range immediately after the
 * rmap_locks are released. Otherwise if XXXX would be removed and
 * NNNN would be extended over the XXXX range, remove_migration_ptes
 * or other rmap walkers (if working on addresses beyond the "end"
 * parameter) may establish ptes with the wrong permissions of NNNN
 * instead of the right permissions of XXXX.
 */
struct vm_area_struct *vma_merge(struct lego_mm_struct *mm,
			struct vm_area_struct *prev, unsigned long addr,
			unsigned long end, unsigned long vm_flags,
			struct lego_file *file, pgoff_t pgoff)
{
	pgoff_t pglen = (end - addr) >> PAGE_SHIFT;
	struct vm_area_struct *area, *next;
	int err;

	vma_trace("%s, addr: %lx, end: %lx\n", __func__, addr, end);
	/*
	 * We later require that vma->vm_flags == vm_flags,
	 * so this tests vma->vm_flags & VM_SPECIAL, too.
	 */
	if (WARN_ON(vm_flags & VM_SPECIAL))
		return NULL;

	if (prev)
		next = prev->vm_next;
	else
		next = mm->mmap;
	area = next;
	if (area && area->vm_end == end)		/* cases 6, 7, 8 */
		next = next->vm_next;

	/* verify some invariant that must be enforced by the caller */
	VM_WARN_ON(prev && addr <= prev->vm_start);
	VM_WARN_ON(area && end > area->vm_end);
	VM_WARN_ON(addr >= end);

	/*
	 * Can it merge with the predecessor?
	 */
	if (prev && prev->vm_end == addr &&
	    can_vma_merge_after(prev, vm_flags, file, pgoff)) {
		/*
		 * OK, it can.  Can we now merge in the successor as well?
		 */
		if (next && end == next->vm_start &&
		    can_vma_merge_before(next, vm_flags, file, pgoff+pglen)) {
							/* cases 1, 6 */
			err = __vma_adjust(prev, prev->vm_start,
					 next->vm_end, prev->vm_pgoff, NULL, prev);
		} else					/* cases 2, 5, 7 */
			err = __vma_adjust(prev, prev->vm_start,
					 end, prev->vm_pgoff, NULL, prev);
		if (err)
			return NULL;
		return prev;
	}

	/*
	 * Can this new request be merged in front of next?
	 */
	if (next && end == next->vm_start &&
	    can_vma_merge_before(next, vm_flags, file, pgoff+pglen)) {
		if (prev && addr < prev->vm_end)	/* case 4 */
			err = __vma_adjust(prev, prev->vm_start,
					 addr, prev->vm_pgoff, NULL, next);
		else {					/* cases 3, 8 */
			err = __vma_adjust(area, addr, next->vm_end,
					 next->vm_pgoff - pglen, NULL, next);
			/*
			 * In case 3 area is already equal to next and
			 * this is a noop, but in case 8 "area" has
			 * been removed and next was expanded over it.
			 */
			area = next;
		}
		if (err)
			return NULL;
		return area;
	}

	return NULL;
}

/*
 * __split_vma() bypasses sysctl_max_map_count checking.  We use this on the
 * munmap path where it doesn't make sense to fail.
 */
static int __split_vma(struct lego_mm_struct *mm, struct vm_area_struct *vma,
	      unsigned long addr, int new_below)
{
	struct vm_area_struct *new;
	int err = 0;

	vma_trace("%s, addr: %lx, new_below: %d\n", __func__, addr, new_below);
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	/* most fields are the same, copy all, and then fixup */
	*new = *vma;

	if (new_below)
		new->vm_end = addr;
	else {
		new->vm_start = addr;
		new->vm_pgoff += ((addr - vma->vm_start) >> PAGE_SHIFT);
	}

	if (new->vm_file)
		get_lego_file(new->vm_file);

	if (new->vm_ops && new->vm_ops->open)
		new->vm_ops->open(new);

	if (new_below)
		err = vma_adjust(vma, addr, vma->vm_end, vma->vm_pgoff +
			((addr - new->vm_start) >> PAGE_SHIFT), new);
	else
		err = vma_adjust(vma, vma->vm_start, addr, vma->vm_pgoff, new);

	/* Success. */
	if (!err)
		return 0;

	/* Clean everything up if vma_adjust failed. */
	if (new->vm_ops && new->vm_ops->close)
		new->vm_ops->close(new);
	if (new->vm_file)
		put_lego_file(new->vm_file);

	kfree(new);
	return err;
}

/*
 * Get rid of page table information in the indicated region.
 *
 * Called with the mm semaphore held.
 */
static void unmap_region(struct lego_mm_struct *mm,
		struct vm_area_struct *vma, struct vm_area_struct *prev,
		unsigned long start, unsigned long end)
{
	struct vm_area_struct *next = prev ? prev->vm_next : mm->mmap;

	vma_trace("%s, start: %lx, end: %lx\n", __func__, start, end);
	unmap_vmas(vma, start, end);
	lego_free_pgtables(vma, prev ? prev->vm_end : FIRST_USER_ADDRESS,
				next ? next->vm_start : USER_PGTABLES_CEILING);
}

/*
 * Create a list of vma's touched by the unmap, removing them from the mm's
 * vma list as we go..
 */
static void
detach_vmas_to_be_unmapped(struct lego_mm_struct *mm, struct vm_area_struct *vma,
	struct vm_area_struct *prev, unsigned long end)
{
	struct vm_area_struct **insertion_point;
	struct vm_area_struct *tail_vma = NULL;

	insertion_point = (prev ? &prev->vm_next : &mm->mmap);
	vma->vm_prev = NULL;
	do {
		vma_rb_erase(vma, &mm->mm_rb);
		mm->map_count--;
		tail_vma = vma;
		vma = vma->vm_next;
	} while (vma && vma->vm_start < end);
	*insertion_point = vma;
	if (vma) {
		vma->vm_prev = prev;
		vma_gap_update(vma);
	} else
		mm->highest_vm_end = prev ? prev->vm_end : 0;
	tail_vma->vm_next = NULL;
}

/*
 * Close a vm structure and free it, returning the next.
 */
static struct vm_area_struct *remove_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *next = vma->vm_next;

	if (vma->vm_ops && vma->vm_ops->close)
		vma->vm_ops->close(vma);
	if (vma->vm_file)
		put_lego_file(vma->vm_file);
	kfree(vma);
	return next;
}

/*
 * Ok - we have the memory areas we should free on the vma list,
 * so release them, and do the vma updates.
 *
 * Called with the mm semaphore held.
 */
static void remove_vma_list(struct lego_mm_struct *mm, struct vm_area_struct *vma)
{
	do {
		vma = remove_vma(vma);
	} while (vma);
	validate_mm(mm);
}

/*
 * Munmap is split into 2 main parts -- this part which finds
 * what needs doing, and the areas themselves, which do the
 * work.  This now handles partial unmappings.
 */
int do_munmap(struct lego_mm_struct *mm, unsigned long start, size_t len)
{
	unsigned long end;
	struct vm_area_struct *vma, *prev, *last;

	vma_trace("%s, start: %lx, len: %lx\n", __func__, start, len);
	if ((offset_in_page(start)) || start > TASK_SIZE || len > TASK_SIZE-start)
		return -EINVAL;

	len = PAGE_ALIGN(len);
	if (len == 0)
		return -EINVAL;

	/* Find the first overlapping VMA */
	vma = find_vma(mm, start);
	if (!vma)
		return 0;
	prev = vma->vm_prev;
	/* we have  start < vma->vm_end  */

	/* if it doesn't overlap, we have nothing.. */
	end = start + len;
	if (vma->vm_start >= end)
		return 0;

	/* If we need to split any vma, do it now to save pain later */
	if (start > vma->vm_start) {
		int error;

		/*
		 * Make sure that map_count on return from munmap() will
		 * not exceed its limit; but let map_count go just above
		 * its limit temporarily, to help free resources as expected.
		 */
		if (end < vma->vm_end && mm->map_count >= sysctl_max_map_count)
			return -ENOMEM;

		error = __split_vma(mm, vma, start, 0);
		if (error)
			return error;
		prev = vma;
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
		save_vma_context(mm, mm->vmrange_map[vmr_idx(start)]);
#endif
	}

	/* Does it split the last one? */
	last = find_vma(mm, end);
	if (last && end > last->vm_start) {
		int error = __split_vma(mm, last, end, 1);
		if (error)
			return error;
	}
	vma = prev ? prev->vm_next : mm->mmap;

	/*
	 * Remove the vma's, and unmap the actual pages
	 */
	detach_vmas_to_be_unmapped(mm, vma, prev, end);
	unmap_region(mm, vma, prev, start, end);

	/* Fix up all other VM information */
	remove_vma_list(mm, vma);

	return 0;
}

int vm_munmap(struct lego_task_struct *p, unsigned long start, size_t len)
{
	int ret;
	struct lego_mm_struct *mm = p->mm;

	if (down_write_killable(&mm->mmap_sem))
		return -EINTR;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	ret = distvm_munmap_homenode(mm, start, len);
#else
	ret = do_munmap(mm, start, len);
#endif
	up_write(&mm->mmap_sem);

	return ret;
}

int vma_expandable(struct lego_task_struct *tsk,
		   struct vm_area_struct *vma, unsigned long delta)
{
	unsigned long end = vma->vm_end + delta;
	if (end < vma->vm_end) /* overflow */
		return 0;
	if (vma->vm_next && vma->vm_next->vm_start < end) /* intersection */
		return 0;
	if (get_unmapped_area(tsk, NULL, vma->vm_start, end - vma->vm_start,
			      0, MAP_FIXED) & ~PAGE_MASK)
		return 0;
	return 1;
}

struct vm_area_struct *
vma_to_resize(unsigned long addr, unsigned long old_len,
	      unsigned long new_len, struct lego_task_struct *tsk)
{
	struct lego_mm_struct *mm = tsk->mm;
	struct vm_area_struct *vma;
	unsigned long pgoff;

	vma_trace("%s, addr: %lx, old_len: %lx, new_len: %lx\n",
			__func__, addr, old_len, new_len);

	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr)
		return ERR_PTR(-EFAULT);

	/* We can't remap across vm area boundaries */
	if (old_len > vma->vm_end - addr)
		return ERR_PTR(-EFAULT);

	if (new_len == old_len)
		return vma;

	/* Overflowed? */
	pgoff = (addr - vma->vm_start) >> PAGE_SHIFT;
	pgoff += vma->vm_pgoff;
	if (pgoff + (new_len >> PAGE_SHIFT) < pgoff)
		return ERR_PTR(-EINVAL);

	/* Can it have more memory? */
	if (!may_expand_vm(mm, vma->vm_flags,
				(new_len - old_len) >> PAGE_SHIFT))
		return ERR_PTR(-ENOMEM);

	return vma;
}

/*
 * Copy the vma structure to a new location in the same mm,
 * prior to moving page table entries, to effect an mremap move.
 */
static struct vm_area_struct *copy_vma(struct vm_area_struct **vmap,
	unsigned long addr, unsigned long len, pgoff_t pgoff)
{
	struct vm_area_struct *vma = *vmap;
	unsigned long vma_start = vma->vm_start;
	struct lego_mm_struct *mm = vma->vm_mm;
	struct vm_area_struct *new_vma, *prev;
	struct rb_node **rb_link, *rb_parent;
	bool faulted_in_anon_vma = true;

	vma_trace("%s, addr: %lx, len: %lx, pgoff: %Lx\n",
			__func__, addr, len, pgoff);
	/*
	 * If it is anonymous, pgoff really does not matter
	 * vma_merge does not rely on it.
	 */
	if (unlikely(vma_is_anonymous(vma))) {
		pgoff = addr >> PAGE_SHIFT;
		faulted_in_anon_vma = false;
	}

	if (find_vma_links(mm, addr, addr + len, &prev, &rb_link, &rb_parent))
		return NULL;	/* should never get here */
	new_vma = vma_merge(mm, prev, addr, addr + len, vma->vm_flags,
			    vma->vm_file, pgoff);
	if (new_vma) {
		/*
		 * Source vma may have been merged into new_vma
		 */
		if (unlikely(vma_start >= new_vma->vm_start &&
			     vma_start < new_vma->vm_end)) {
			/*
			 * The only way we can get a vma_merge with
			 * self during an mremap is if the vma hasn't
			 * been faulted in yet and we were allowed to
			 * reset the dst vma->vm_pgoff to the
			 * destination address of the mremap to allow
			 * the merge to happen. mremap must change the
			 * vm_pgoff linearity between src and dst vmas
			 * (in turn preventing a vma_merge) to be
			 * safe. It is only safe to keep the vm_pgoff
			 * linear if there are no pages mapped yet.
			 */
			VM_BUG_ON_VMA(faulted_in_anon_vma, new_vma);
			*vmap = vma = new_vma;
		}
	} else {
		new_vma = kmalloc(sizeof(*new_vma), GFP_KERNEL);
		if (!new_vma)
			return NULL;
		*new_vma = *vma;
		new_vma->vm_start = addr;
		new_vma->vm_end = addr + len;
		new_vma->vm_pgoff = pgoff;
		if (new_vma->vm_file)
			get_lego_file(new_vma->vm_file);
		if (new_vma->vm_ops && new_vma->vm_ops->open)
			new_vma->vm_ops->open(new_vma);
		vma_link(mm, new_vma, prev, rb_link, rb_parent);
	}
	return new_vma;
}

/* Called by mremap() */
unsigned long move_vma(struct lego_task_struct *tsk, struct vm_area_struct *vma,
		unsigned long old_addr, unsigned long old_len,
		unsigned long new_len, unsigned long new_addr)
{
#ifndef CONFIG_DISTRIBUTED_VMA_MEMORY
	struct lego_mm_struct *mm = vma->vm_mm;
#endif
	struct vm_area_struct *new_vma;
	unsigned long new_pgoff;
	unsigned long moved_len;
	int err = 0;

	vma_trace("%s, old_addr: %lx, old_len: %lx, new_addr: %lx, new_len: %lx\n",
			__func__, old_addr, old_len, new_addr, new_len);

	new_pgoff = vma->vm_pgoff + ((old_addr - vma->vm_start) >> PAGE_SHIFT);
	new_vma = copy_vma(&vma, new_addr, new_len, new_pgoff);
	if (!new_vma)
		return -ENOMEM;

	moved_len = lego_move_page_tables(vma, old_addr, new_vma, new_addr, old_len);
	if (moved_len < old_len)
		err = -ENOMEM;

	if (unlikely(err)) {
		/*
		 * On error, move entries back from new area to old,
		 * which will succeed since page tables still there,
		 * and then proceed to unmap new area instead of old.
		 */
		lego_move_page_tables(new_vma, new_addr, vma, old_addr, moved_len);
		vma = new_vma;
		old_len = new_len;
		old_addr = new_addr;
		new_addr = err;
	}
#ifndef CONFIG_DISTRIBUTED_VMA_MEMORY
	/* for keeping API unchanged, unmap part move to function caller */
	do_munmap(mm, old_addr, old_len);
#endif
	return new_addr;
}

unsigned long unmapped_area(struct lego_task_struct *p,
			    struct vm_unmapped_area_info *info)
{
	/*
	 * We implement the search by looking for an rbtree node that
	 * immediately follows a suitable gap. That is,
	 * - gap_start = vma->vm_prev->vm_end <= info->high_limit - length;
	 * - gap_end   = vma->vm_start        >= info->low_limit  + length;
	 * - gap_end - gap_start >= length
	 */

	struct lego_mm_struct *mm = p->mm;
	struct vm_area_struct *vma;
	unsigned long length, low_limit, high_limit, gap_start, gap_end;

	/* Adjust search length to account for worst case alignment overhead */
	length = info->length + info->align_mask;
	if (length < info->length)
		return -ENOMEM;

	/* Adjust search limits by the desired length */
	if (info->high_limit < length)
		return -ENOMEM;
	high_limit = info->high_limit - length;

	if (info->low_limit > high_limit)
		return -ENOMEM;
	low_limit = info->low_limit + length;

	/* Check if rbtree root looks promising */
	if (RB_EMPTY_ROOT(&mm->mm_rb))
		goto check_highest;
	vma = rb_entry(mm->mm_rb.rb_node, struct vm_area_struct, vm_rb);
	if (vma->rb_subtree_gap < length)
		goto check_highest;

	while (true) {
		/* Visit left subtree if it looks promising */
		gap_end = vma->vm_start;
		if (gap_end >= low_limit && vma->vm_rb.rb_left) {
			struct vm_area_struct *left =
				rb_entry(vma->vm_rb.rb_left,
					 struct vm_area_struct, vm_rb);
			if (left->rb_subtree_gap >= length) {
				vma = left;
				continue;
			}
		}

		gap_start = vma->vm_prev ? vma->vm_prev->vm_end : 0;
check_current:
		/* Check if current node has a suitable gap */
		if (gap_start > high_limit)
			return -ENOMEM;
		if (gap_end >= low_limit && gap_end - gap_start >= length)
			goto found;

		/* Visit right subtree if it looks promising */
		if (vma->vm_rb.rb_right) {
			struct vm_area_struct *right =
				rb_entry(vma->vm_rb.rb_right,
					 struct vm_area_struct, vm_rb);
			if (right->rb_subtree_gap >= length) {
				vma = right;
				continue;
			}
		}

		/* Go back up the rbtree to find next candidate node */
		while (true) {
			struct rb_node *prev = &vma->vm_rb;
			if (!rb_parent(prev))
				goto check_highest;
			vma = rb_entry(rb_parent(prev),
				       struct vm_area_struct, vm_rb);
			if (prev == vma->vm_rb.rb_left) {
				gap_start = vma->vm_prev->vm_end;
				gap_end = vma->vm_start;
				goto check_current;
			}
		}
	}

check_highest:
	/* Check highest gap, which does not precede any rbtree node */
	gap_start = mm->highest_vm_end;
	gap_end = ULONG_MAX;  /* Only for VM_BUG_ON below */
	if (gap_start > high_limit)
		return -ENOMEM;

found:
	/* We found a suitable gap. Clip it with the original low_limit. */
	if (gap_start < info->low_limit)
		gap_start = info->low_limit;

	/* Adjust gap address to the desired alignment */
	gap_start += (info->align_offset - gap_start) & info->align_mask;

	VM_BUG_ON(gap_start + info->length > info->high_limit);
	VM_BUG_ON(gap_start + info->length > gap_end);
	return gap_start;
}

unsigned long unmapped_area_topdown(struct lego_task_struct *p,
				    struct vm_unmapped_area_info *info)
{
	struct lego_mm_struct *mm = p->mm;
	struct vm_area_struct *vma;
	unsigned long length, low_limit, high_limit, gap_start, gap_end;

	/* Adjust search length to account for worst case alignment overhead */
	length = info->length + info->align_mask;
	if (length < info->length)
		return -ENOMEM;

	/*
	 * Adjust search limits by the desired length.
	 * See implementation comment at top of unmapped_area().
	 */
	gap_end = info->high_limit;
	if (gap_end < length)
		return -ENOMEM;
	high_limit = gap_end - length;

	if (info->low_limit > high_limit)
		return -ENOMEM;
	low_limit = info->low_limit + length;

	/* Check highest gap, which does not precede any rbtree node */
	gap_start = mm->highest_vm_end;
	if (gap_start <= high_limit)
		goto found_highest;

	/* Check if rbtree root looks promising */
	if (RB_EMPTY_ROOT(&mm->mm_rb))
		return -ENOMEM;
	vma = rb_entry(mm->mm_rb.rb_node, struct vm_area_struct, vm_rb);
	if (vma->rb_subtree_gap < length)
		return -ENOMEM;

	while (true) {
		/* Visit right subtree if it looks promising */
		gap_start = vma->vm_prev ? vma->vm_prev->vm_end : 0;
		if (gap_start <= high_limit && vma->vm_rb.rb_right) {
			struct vm_area_struct *right =
				rb_entry(vma->vm_rb.rb_right,
					 struct vm_area_struct, vm_rb);
			if (right->rb_subtree_gap >= length) {
				vma = right;
				continue;
			}
		}

check_current:
		/* Check if current node has a suitable gap */
		gap_end = vma->vm_start;
		if (gap_end < low_limit)
			return -ENOMEM;
		if (gap_start <= high_limit && gap_end - gap_start >= length)
			goto found;

		/* Visit left subtree if it looks promising */
		if (vma->vm_rb.rb_left) {
			struct vm_area_struct *left =
				rb_entry(vma->vm_rb.rb_left,
					 struct vm_area_struct, vm_rb);
			if (left->rb_subtree_gap >= length) {
				vma = left;
				continue;
			}
		}

		/* Go back up the rbtree to find next candidate node */
		while (true) {
			struct rb_node *prev = &vma->vm_rb;
			if (!rb_parent(prev))
				return -ENOMEM;
			vma = rb_entry(rb_parent(prev),
				       struct vm_area_struct, vm_rb);
			if (prev == vma->vm_rb.rb_right) {
				gap_start = vma->vm_prev ?
					vma->vm_prev->vm_end : 0;
				goto check_current;
			}
		}
	}

found:
	/* We found a suitable gap. Clip it with the original high_limit. */
	if (gap_end > info->high_limit)
		gap_end = info->high_limit;

found_highest:
	/* Compute highest gap address at the desired alignment */
	gap_end -= info->length;
	gap_end -= (gap_end - info->align_offset) & info->align_mask;

	BUG_ON(gap_end < info->low_limit);
	BUG_ON(gap_end < gap_start);
	return gap_end;
}

unsigned long
get_unmapped_area(struct lego_task_struct *p, struct lego_file *file,
		  unsigned long addr, unsigned long len, unsigned long pgoff,
		  unsigned long flags)
{
	unsigned long (*get_area)(struct lego_task_struct *, struct lego_file *, unsigned long,
				  unsigned long, unsigned long, unsigned long);

	vma_trace("%s, addr: %lx, len: %lx, pgoff: %lx, flags: %lx\n",
			__func__, addr, len, pgoff, flags);

	/* Careful about overflows.. */
	if (len > TASK_SIZE)
		return -ENOMEM;

	/* XXX: may have different impls of get_area */

	/* chosen by arch_pick_mmap_layout */
	get_area = p->mm->get_unmapped_area;
	BUG_ON(!get_area);

	addr = get_area(p, file, addr, len, pgoff, flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	if (addr > TASK_SIZE - len)
		return -ENOMEM;
	if (offset_in_page(addr))
		return -EINVAL;
	return addr;
}

unsigned long
mmap_region(struct lego_task_struct *p, struct lego_file *file,
	    unsigned long addr, unsigned long len, vm_flags_t vm_flags,
	    unsigned long pgoff)
{
	struct lego_mm_struct *mm = p->mm;
	struct vm_area_struct *vma, *prev;
	struct rb_node **rb_link, *rb_parent;
	int error;

	vma_trace("%s, addr: %lx, len: %lx, pgoff: %lx, vm_flags: %lx\n",
			__func__, addr, len, pgoff, vm_flags);

	/* Clear old maps */
	while (find_vma_links(mm, addr, addr + len, &prev, &rb_link,
			      &rb_parent)) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
	}

	/* Can we just expand an old mapping? */
	vma = vma_merge(mm, prev, addr, addr + len, vm_flags,
			file, pgoff);
	if (vma)
		goto out;

	vma = kzalloc(sizeof(*vma), GFP_KERNEL);
	if (!vma)
		return -ENOMEM;

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
	vma->vm_page_prot = vm_get_page_prot(vm_flags);
	vma->vm_pgoff = pgoff;

	/*
	 * If we have a back-store, invoke the mmap() callback
	 * it must setup the vma->vm_ops!
	 */
	if (file) {
		/*
		 * Each VMA should hold an extra reference
		 */
		get_lego_file(file);

		vma->vm_file = file;
		error = file->f_op->mmap(p, file, vma);
		if (WARN_ON(error))
			goto unmap_and_free_vma;

		/* Must install vm_ops for pgfault */
		BUG_ON(!vma->vm_ops);

		/*
		 * Bug: If addr is changed, prev, rb_link, rb_parent should
		 *      be updated for vma_link()
		 */
		BUG_ON(addr != vma->vm_start);
	} else if (vm_flags & VM_SHARED) {
		WARN(1, "MAP_SHARED here, check if we are OKAY.");
	}

	vma_link(mm, vma, prev, rb_link, rb_parent);

out:
	vma_set_page_prot(vma);
	return addr;

unmap_and_free_vma:
	vma->vm_file = NULL;
	unmap_region(mm, vma, prev, vma->vm_start, vma->vm_end);
	kfree(vma);
	return error;
}

/* minimum virtual address that a process is allowed to mmap */
static unsigned long sysctl_mmap_min_addr = PAGE_SIZE;

/*
 * If a hint addr is less than mmap_min_addr change hint to be as
 * low as possible but still greater than mmap_min_addr
 */
static inline unsigned long round_hint_to_min(unsigned long hint)
{
	hint &= PAGE_MASK;
	if (((void *)hint != NULL) &&
	    (hint < sysctl_mmap_min_addr))
		return PAGE_ALIGN(sysctl_mmap_min_addr);
	return hint;
}

/*
 * File-backed mmap and anonymous mmap merge into this function.
 * The caller must hold down_write(&current->mm->mmap_sem).
 */
unsigned long do_mmap(struct lego_task_struct *p, struct lego_file *file,
	unsigned long addr, unsigned long len, unsigned long prot,
	unsigned long flags, vm_flags_t vm_flags, unsigned long pgoff)
{
	struct lego_mm_struct *mm = p->mm;

	vma_trace("%s, addr: %lx, len: %lx, pgoff: %lx, flags: %lx, vm_flags: %lx\n",
			__func__, addr, len, pgoff, flags, vm_flags);

#ifndef CONFIG_DISTRIBUTED_VMA_MEMORY

	if (!(flags & MAP_FIXED))
		addr = round_hint_to_min(addr);

	if (!len)
		return -EINVAL;

#else

	if (!len)
		return 0;

#endif

	/* Careful about overflows.. */
	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	/*
	 * Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	addr = get_unmapped_area(p, file, addr, len, pgoff, flags);
	if (unlikely(offset_in_page(addr))) /* which means error */
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vm_flags |= calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
			mm->def_flags;

	if (file) {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			WARN(1, "MAP_SHARED file: %s(%d). Permission: %s\n",
				file->filename, atomic_read(&file->f_count),
				(vm_flags & (VM_MAYWRITE|VM_WRITE)) ? "RW" : "RO");

			vm_flags |= VM_SHARED | VM_MAYSHARE;
			/* fall through */
		case MAP_PRIVATE:
			if (!file->f_op->mmap)
				return -ENODEV;
			if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP)) {
				WARN(1, "stack flag mis-used\n");
				return -EINVAL;
			}
			break;
		default:
			return -EINVAL;
		}
	} else {
		switch (flags & MAP_TYPE) {
		case MAP_SHARED:
			if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP)) {
				WARN(1, "stack flag mis-used\n");
				return -EINVAL;
			}

			WARN(1, "MAP_SHARED used for anonymous mmap! Permission: %s\n",
				(vm_flags & (VM_MAYWRITE|VM_WRITE)) ? "RW" : "RO");

			/*
			 * Ignore pgoff.
			 */
			pgoff = 0;
			vm_flags |= VM_SHARED;
			break;
		case MAP_PRIVATE:

			/*
			 *
			 */
			pgoff = addr >> PAGE_SHIFT;
			break;
		default:
			return -EINVAL;
		}
	}

	addr = mmap_region(p, file, addr, len, vm_flags, pgoff);
	return addr;
}

static inline unsigned long
do_mmap_pgoff(struct lego_task_struct *p, struct lego_file *file,
	unsigned long addr, unsigned long len, unsigned long prot,
	unsigned long flags, unsigned long pgoff)
{
	return do_mmap(p, file, addr, len, prot, flags, 0, pgoff);
}

unsigned long vm_mmap_pgoff(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;

	if (down_write_killable(&p->mm->mmap_sem))
		return -EINTR;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	ret = distvm_mmap_homenode(p->mm, file, addr, len, prot, flag, pgoff);
#else
	ret = do_mmap_pgoff(p, file, addr, len, prot, flag, pgoff);
#endif

	up_write(&p->mm->mmap_sem);
	return ret;
}

unsigned long vm_mmap(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long offset)
{
	if (unlikely(offset + PAGE_ALIGN(len) < offset))
		return -EINVAL;
	if (unlikely(offset_in_page(offset)))
		return -EINVAL;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	return distvm_mmap_homenode_noconsult(p->mm, file, addr, len, prot,
						flag, offset >> PAGE_SHIFT);
#else
	return vm_mmap_pgoff(p, file, addr, len, prot, flag, offset >> PAGE_SHIFT);
#endif
}

/*
 * This is really a simplified "do_mmap". It only handles
 * anonymous maps. Eventually we may be able to do some
 * brk-specific accounting here.
 *
 * Must enter with mmap_sem held
 */
int do_brk(struct lego_task_struct *p, unsigned long addr,
	   unsigned long request)
{
	struct lego_mm_struct *mm = p->mm;
	struct vm_area_struct *vma, *prev;
	unsigned long flags, len;
	struct rb_node **rb_link, *rb_parent;
	pgoff_t pgoff = addr >> PAGE_SHIFT;
	int error;

	vma_trace("%s, addr: %lx, request: %lx\n", __func__, addr, request);

	len = PAGE_ALIGN(request);
	if (len < request)
		return -ENOMEM;
	if (!len)
		return 0;

	flags = VM_READ | VM_WRITE | mm->def_flags;

	error = get_unmapped_area(p, NULL, addr, len, 0, MAP_FIXED);
	if (offset_in_page(error))
		return error;

	/*
	 * Clear old maps.  this also does some error checking for us
	 */
	while (find_vma_links(mm, addr, addr + len, &prev, &rb_link,
			      &rb_parent)) {
		if (do_munmap(mm, addr, len))
			return -ENOMEM;
	}

	/* Can we just expand an old private anonymous mapping? */
	vma = vma_merge(mm, prev, addr, addr + len, flags,
			NULL, pgoff);
	if (vma)
		goto out;

	/*
	 * create a vma struct for an anonymous mapping
	 */
	vma = kzalloc(sizeof(*vma), GFP_KERNEL);
	if (!vma)
		return -ENOMEM;

	vma->vm_mm = mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_pgoff = pgoff;
	vma->vm_flags = flags;
	vma->vm_page_prot = vm_get_page_prot(flags);
	vma_link(mm, vma, prev, rb_link, rb_parent);

out:
	mm->total_vm += len >> PAGE_SHIFT;
	mm->data_vm += len >> PAGE_SHIFT;
	return 0;
}

/*
 * This function is called by loader when setting
 * up the ".bss+.brk" vma. At this point, brk's size is 0.
 * So the whole vma is effectively starting with .bss.
 * We must get zeroed pages for .bss.
 */
int vm_brk(struct lego_task_struct *tsk,
	   unsigned long start, unsigned long len)
{
	int ret;
	struct lego_mm_struct *mm = tsk->mm;

	if (down_write_killable(&mm->mmap_sem))
		return -EINTR;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	ret = distvm_brk_homenode(tsk->mm, start, len);
#else
	ret = do_brk(tsk, start, len);
#endif
	up_write(&mm->mmap_sem);

	/* Prepopulate brk pages */
	if (!ret)
		lego_mm_populate(mm, start, len);

	return ret;
}

#define LEGO_PGALLOC_GFP     (GFP_KERNEL | __GFP_ZERO)

static pgd_t *lego_pgd_alloc(struct lego_mm_struct *mm)
{
	return (pgd_t *)__get_free_page(LEGO_PGALLOC_GFP);
}

static void lego_pgd_free(struct lego_mm_struct *mm)
{
	free_page((unsigned long)mm->pgd);
}

/**
 * Setup a new lego_mm_struct
 * Especially do not forget to initialize locks, counters etc.
 */
struct lego_mm_struct *
lego_mm_init(struct lego_mm_struct *mm, struct lego_task_struct *p)
{
	BUG_ON(!mm || !p);

	mm->task = p;
	mm->mmap = NULL;
	mm->mm_rb = RB_ROOT;
	atomic_set(&mm->mm_users, 1);
	atomic_set(&mm->mm_count, 1);
	init_rwsem(&mm->mmap_sem);
	spin_lock_init(&mm->lego_page_table_lock);
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	if (is_homenode(p))
		distvm_init_homenode(mm, false);
	else
		distvm_init(mm);
#endif

	mm->pgd = lego_pgd_alloc(mm);
	if (unlikely(!mm->pgd)) {
		kfree(mm);
		return NULL;
	}
	return mm;
}

struct lego_mm_struct *lego_mm_alloc(struct lego_task_struct *p,
				     struct lego_task_struct *parent)
{
	struct lego_mm_struct *mm;

	mm = kzalloc(sizeof(*mm), GFP_KERNEL);
	if (!mm)
		return NULL;

	if (parent)
		memcpy(mm, parent->mm, sizeof(*mm));
	return lego_mm_init(mm, p);
}

/*
 * Called when the last reference to the mm
 * is dropped: either by a lazy thread or by
 * mmput. Free the page directory and the mm.
 */
void __lego_mmdrop(struct lego_mm_struct *mm)
{
	lego_pgd_free(mm);
	kfree(mm);
}

void __lego_mmput(struct lego_mm_struct *mm)
{
	BUG_ON(atomic_read(&mm->mm_users));
	exit_lego_mmap(mm);
	lego_mmdrop(mm);
}

void vm_stat_account(struct lego_mm_struct *mm, vm_flags_t flags, long npages)
{
	mm->total_vm += npages;

	if (is_exec_mapping(flags))
		mm->exec_vm += npages;
	else if (is_stack_mapping(flags))
		mm->stack_vm += npages;
	else if (is_data_mapping(flags))
		mm->data_vm += npages;
}

/*
 * Return true if the calling process may expand its vm space by the passed
 * number of pages
 */
bool may_expand_vm(struct lego_mm_struct *mm, vm_flags_t flags, unsigned long npages)
{
	/* TODO: check if the process can have more memory! */
	return true;
}

/*
 * Verify that the stack growth is acceptable and
 * update accounting. This is shared with both the
 * grow-up and grow-down cases.
 */
/*
 * we currently assign stack to only homenode
 * and assume stack won't grow up to VM_GRANULARTY
 */
static int acct_stack_growth(struct vm_area_struct *vma, unsigned long size, unsigned long grow)
{
	unsigned long actual_size;

	vma_trace("%s, size: %lx, grow: %lx\n", __func__, size, grow);

	/* address space limit tests */
	if (!may_expand_vm(vma->vm_mm, vma->vm_flags, grow))
		return -ENOMEM;

	/* Stack limit test */
	actual_size = size;
	if (size && (vma->vm_flags & (VM_GROWSUP | VM_GROWSDOWN)))
		actual_size -= PAGE_SIZE;

	if (actual_size > _STK_LIM)
		return -ENOMEM;

	return 0;
}

/* enforced gap between the expanding stack and other mappings. */
unsigned long stack_guard_gap = 256UL<<PAGE_SHIFT;

/*
 * vma is the first one with address < vma->vm_start.  Have to extend vma.
 */
int expand_downwards(struct vm_area_struct *vma, unsigned long address)
{
	struct lego_mm_struct *mm = vma->vm_mm;
	unsigned long gap_addr;
	int error;

	vma_trace("%s, address: %lx\n", __func__, address);

	address &= PAGE_MASK;

	/* Enforce stack_guard_gap */
	gap_addr = address - stack_guard_gap;
	if (WARN_ON(gap_addr > address))
		return -ENOMEM;

	/* Somebody else might have raced and expanded it already */
	if (address < vma->vm_start) {
		unsigned long size, grow;

		size = vma->vm_end - address;
		grow = (vma->vm_start - address) >> PAGE_SHIFT;

		error = -ENOMEM;
		if (grow <= vma->vm_pgoff) {
			/* Check if we can grow that much */
			error = acct_stack_growth(vma, size, grow);
			if (error)
				goto out;

			/*
			 * vma_gap_update() doesn't support concurrent
			 * updates, but we only hold a shared mmap_sem
			 * lock here, so we need to protect against
			 * concurrent vma expansions.
			 *
			 * So, we reuse mm->page_table_lock to guard
			 * against concurrent vma expansions.
			 */
			spin_lock(&mm->lego_page_table_lock);
			vm_stat_account(mm, vma->vm_flags, grow);
			vma->vm_start = address;
			vma->vm_pgoff -= grow;
			vma_gap_update(vma);
			spin_unlock(&mm->lego_page_table_lock);
		}
	}
out:
	validate_mm(mm);
	return error;
}

/*
 * We only support stack that grows down.
 */
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
int expand_stack(struct vm_area_struct *vma, unsigned long address)
{
	int ret;
	struct lego_mm_struct *mm = vma->vm_mm;
	struct vma_tree *root = get_vmatree_by_addr(mm, address);
	load_vma_context(mm, root);
	ret = expand_downwards(vma, address);
	save_update_vma_context(mm, root);
	return ret;
}
#else
int expand_stack(struct vm_area_struct *vma, unsigned long address)
{
	return expand_downwards(vma, address);
}
#endif

/*
 * The returned VMA satisfy:
 *	[vm_start < addr < vm_end]
 *
 * If NULL is returned, it is because
 *	1) vm_start <= addr, and VMA does not GROWSDOWN
 *	2) VMA GROWSDOWN, but expand_stack fails
 */
struct vm_area_struct *
find_extend_vma(struct lego_mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma;

	addr &= PAGE_MASK;
	vma = find_vma(mm, addr);
	if (!vma)
		return NULL;
	if (vma->vm_start <= addr)
		return vma;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		return NULL;
	if (expand_stack(vma, addr))
		return NULL;
	return vma;
}

/* TODO */
int mprotect_fixup(struct lego_task_struct *tsk, struct vm_area_struct *vma,
		struct vm_area_struct **pprev, unsigned long start,
		unsigned long end, unsigned long newflags)
{
	*pprev = vma;
	return 0;
}

static void unmap_single_vma(struct vm_area_struct *vma, unsigned long start_addr,
			     unsigned long end_addr)
{
	unsigned long start;
	unsigned long end;

	vma_trace("%s, start_addr: %lx, end_addr: %lx\n",
			__func__, start_addr, end_addr);
	start = max(vma->vm_start, start_addr);
	if (start >= vma->vm_end)
		return;

	end = min(vma->vm_end, end_addr);
	if (end <= vma->vm_start)
		return;

	if (start != end)
		lego_unmap_page_range(vma, start, end);
}

/**
 * unmap_vmas - unmap a range of memory covered by a list of vma's
 * @vma: the starting vma
 * @start_addr: virtual address at which to start unmapping
 * @end_addr: virtual address at which to end unmapping
 *
 * Unmap all pages in the vma list.
 *
 * Only addresses between `start' and `end' will be unmapped.
 *
 * The VMA list must be sorted in ascending virtual address order.
 *
 * unmap_vmas() assumes that the caller will flush the whole unmapped address
 * range after unmap_vmas() returns.  So the only responsibility here is to
 * ensure that any thus-far unmapped pages are flushed before unmap_vmas()
 * drops the lock and schedules.
 */
void unmap_vmas(struct vm_area_struct *vma, unsigned long start_addr,
		unsigned long end_addr)
{
	vma_trace("%s, start_addr: %lx, end_addr: %lx\n",
			__func__, start_addr, end_addr);
	for ( ; vma && vma->vm_start < end_addr; vma = vma->vm_next)
		unmap_single_vma(vma, start_addr, end_addr);
}

/*
 * This function is called when a user-process exit.
 * Release all mmap resources.
 */
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
void exit_lego_mmap(struct lego_mm_struct *mm)
{
	distvm_exit_homenode(mm);
}
#else
void exit_lego_mmap(struct lego_mm_struct *mm)
{
	struct vm_area_struct *vma;

	vma = mm->mmap;

	/*
	 * This may happen if the first user-program
	 * run fork() and execve() in a row.
	 *
	 * Since the first user-program does not have parent
	 * in memory-component yet, it can not inherit any mmap.
	 */
	if (!vma)
		return;

	/* Use -1 here to ensure all VMAs in the mm are unmapped */
	unmap_vmas(vma, 0, -1);

	lego_free_pgtables(vma, FIRST_USER_ADDRESS, USER_PGTABLES_CEILING);

	/*
	 * Walk the list again, actually closing and freeing it,
	 * with preemption enabled, without holding any MM locks.
	 */
	while (vma)
		vma = remove_vma(vma);
}
#endif

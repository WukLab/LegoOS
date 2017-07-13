#ifndef _LEGO_MEMORY_VM_H_
#define _LEGO_MEMORY_VM_H_

#include <lego/comp_memory.h>

/*
 * mmap flags
 */
#define PROT_READ	0x01		/* page can be read */
#define PROT_WRITE	0x02		/* page can be written */
#define PROT_EXEC	0x04		/* page can be executed */
#define PROT_SEM	0x08		/* page may be used for atomic ops */
#define PROT_NONE	0x00		/* page can not be accessed */

#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked */

/*
 * vm_flags in vm_area_struct
 */
#define VM_NONE		0x00000000
#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_GROWSUP	VM_NONE
#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_UFFD_MISSING	0x00000200	/* missing pages tracking */
#define VM_PFNMAP	0x00000400	/* Page-ranges managed without "struct page", just pure PFN */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */

#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

/*
 * Special vmas that are non-mergable, non-mlock()able.
 */
#define VM_SPECIAL		(VM_IO | VM_PFNMAP)

#define VM_DATA_DEFAULT_FLAGS	(VM_READ | VM_WRITE) 

#define VM_STACK		VM_GROWSDOWN
#define VM_STACK_DEFAULT_FLAGS	VM_DATA_DEFAULT_FLAGS
#define VM_STACK_FLAGS		(VM_STACK | VM_STACK_DEFAULT_FLAGS)

/* Bits set in the VMA until the stack is in its final location */
#define VM_STACK_INCOMPLETE_SETUP	(VM_RAND_READ | VM_SEQ_READ)

/*
 * Optimisation macro.  It is equivalent to:
 *      (x & bit1) ? bit2 : 0
 * but this version is faster.
 * ("bit1" and "bit2" must be single bits)
 */
#define _calc_vm_trans(x, bit1, bit2) \
  ((bit1) <= (bit2) ? ((x) & (bit1)) * ((bit2) / (bit1)) \
   : ((x) & (bit1)) / ((bit1) / (bit2)))

/*
 * This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(PAGE_ALIGN(TASK_SIZE / 3))

/*
 * Combine the mmap "prot" argument into "vm_flags" used internally.
 */
static inline unsigned long
calc_vm_prot_bits(unsigned long prot)
{
	return _calc_vm_trans(prot, PROT_READ,  VM_READ ) |
	       _calc_vm_trans(prot, PROT_WRITE, VM_WRITE) |
	       _calc_vm_trans(prot, PROT_EXEC,  VM_EXEC);
}

/*
 * Combine the mmap "flags" argument into "vm_flags" used internally.
 */
static inline unsigned long
calc_vm_flag_bits(unsigned long flags)
{
	return _calc_vm_trans(flags, MAP_GROWSDOWN,  VM_GROWSDOWN ) |
	       _calc_vm_trans(flags, MAP_DENYWRITE,  VM_DENYWRITE ) |
	       _calc_vm_trans(flags, MAP_LOCKED,     VM_LOCKED    );
}

/* Is the vma a continuation of the stack vma above it? */
static inline int vma_growsdown(struct vm_area_struct *vma, unsigned long addr)
{
	return vma && (vma->vm_end == addr) && (vma->vm_flags & VM_GROWSDOWN);
}

static inline bool vma_is_anonymous(struct vm_area_struct *vma)
{
	/*TODO*/
	return true;
}

struct vm_unmapped_area_info {
#define VM_UNMAPPED_AREA_TOPDOWN 1
	unsigned long flags;
	unsigned long length;
	unsigned long low_limit;
	unsigned long high_limit;
	unsigned long align_mask;
	unsigned long align_offset;
};

unsigned long
unmapped_area(struct lego_task_struct *p, struct vm_unmapped_area_info *info);
unsigned long
unmapped_area_topdown(struct lego_task_struct *p, struct vm_unmapped_area_info *info);

/*
 * Search for an unmapped address range.
 *
 * We are looking for a range that:
 * - does not intersect with any VMA;
 * - is contained within the [low_limit, high_limit) interval;
 * - is at least the desired size.
 * - satisfies (begin_addr & align_mask) == (align_offset & align_mask)
 */
static inline unsigned long
vm_unmapped_area(struct lego_task_struct *p, struct vm_unmapped_area_info *info)
{
	if (info->flags & VM_UNMAPPED_AREA_TOPDOWN)
		return unmapped_area_topdown(p, info);
	else
		return unmapped_area(p, info);
}

pgprot_t vm_get_page_prot(unsigned long vm_flags);

/* arch-hook for loader */
void arch_pick_mmap_layout(struct lego_mm_struct *mm);

int insert_vm_struct(struct lego_mm_struct *, struct vm_area_struct *);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
struct vm_area_struct *find_vma(struct lego_mm_struct *mm, unsigned long addr);

int vm_munmap(struct lego_task_struct *p, unsigned long start, size_t len);
unsigned long vm_mmap(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long offset);

unsigned long vm_mmap_pgoff(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff);

int vm_brk(struct lego_task_struct *tsk,
	   unsigned long start, unsigned long len);

struct lego_mm_struct *lego_mm_alloc(struct lego_task_struct *p);

/* lego_mmdrop drops the mm and the page tables */
void __lego_mmdrop(struct lego_mm_struct *);
static inline void lego_mmdrop(struct lego_mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_count)))
		__lego_mmdrop(mm);
}

/* Decrement the use count and release all resources for an mm */
void __lego_mmput(struct lego_mm_struct *);
static inline void lego_mmput(struct lego_mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_users)))
		__lego_mmput(mm);
}
void lego_mm_release(struct lego_task_struct *tsk, struct lego_mm_struct *mm);

static inline unsigned long vma_pages(struct vm_area_struct *vma)
{
	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}

int expand_stack(struct vm_area_struct *vma, unsigned long address);

int mprotect_fixup(struct lego_task_struct *tsk, struct vm_area_struct *vma,
		struct vm_area_struct **pprev, unsigned long start,
		unsigned long end, unsigned long newflags);

#endif /* _LEGO_MEMORY_VM_H_ */

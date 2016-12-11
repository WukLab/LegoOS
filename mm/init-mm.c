#include <lego/mm_types.h>
#include <lego/spinlock.h>
#include <lego/list.h>

#include <asm/pgtable.h>

struct mm_struct init_mm = {
	.pgd		= swapper_pg_dir,
	.page_table_lock =  __SPIN_LOCK_UNLOCKED(init_mm.page_table_lock),
	.mmlist		= LIST_HEAD_INIT(init_mm.mmlist),
};

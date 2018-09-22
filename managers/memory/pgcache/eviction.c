/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/list.h>
#include <lego/spinlock.h>
#include <memory/pgcache.h>

#define MAX_LIR_CACHELINES		((1 << 14) - (1 << 9))
#define MAX_HIR_CACHELINES		(1 << 9)
#define MAX_CACHELINES			(MAX_LIR_CACHELINES + MAX_HIR_CACHELINES)
static atomic_t lir_credit = ATOMIC_INIT(0);
static atomic_t hir_credit = ATOMIC_INIT(0);

/* lock to protect 2 LIRS queue */
static DEFINE_SPINLOCK(pgcache_lirs_lock);

static LIST_HEAD(lirs_stack_s); /* list of stack s of access history */
static LIST_HEAD(lirs_stack_q); /* list of stack q of victim candidate */

#define IN_QUEUE(pgc, member)					\
((pgc->member.next != &pgc->member)				\
	&& (pgc->member.prev != &pgc->member))

/* When accessing a page cacheline, the cacheline is moved to list tail of stack s
 * and cacheline will be come a LIR cacheline, and need to be removed for stack q also
 */
void move_to_stack_s_top_locked(struct lego_pgcache_struct *pgc)
{
	if (IN_QUEUE(pgc, stack_s)) {
		list_del_init(&pgc->stack_s);
	}

	list_add_tail(&pgc->stack_s, &lirs_stack_s);
}

void remove_from_stack_q_locked(struct lego_pgcache_struct *pgc)
{
	list_del_init(&pgc->stack_q);
	//INIT_LIST_HEAD(&pgc->stack_q);
}

void add_to_stack_q_top_locked(struct lego_pgcache_struct *pgc)
{
	if (IN_QUEUE(pgc, stack_q)) {
		list_del_init(&pgc->stack_q);
	}
	list_add_tail(&pgc->stack_q, &lirs_stack_q);
}


#define head_entry(pgc, head, member)				\
	list_entry((head)->next, typeof(*pgc), member)

#define HIR(pgc)		((pgc)->hir)
#define set_pgcache_hir(pgc)	((pgc)->hir = true)
#define set_pgcache_lir(pgc)	((pgc)->hir = false)


void cut_stack_s_bottom(void)
{
	struct lego_pgcache_struct *s_bottom;

retry:
	/* list is empty */
	if (lirs_stack_s.next == &lirs_stack_s)
		return;

	s_bottom = head_entry(s_bottom, &lirs_stack_s, stack_s);
	if (!HIR(s_bottom))
		return;

	list_del_init(&s_bottom->stack_s);
	//INIT_LIST_HEAD(&s_bottom->stack_s);
	/* TODO:
	 * Free no-residental blocks will cutting stack S
	 */
	goto retry;
}

/* TODO: Mark lock sequence, adjust lock range */
void pgcache_evict_one(void)
{
	struct lego_pgcache_struct *victim;

	victim = head_entry(victim, &lirs_stack_q, stack_q);

	pgcache_debug("victim: %p, filepath: %s, pos: %Lx",		\
		victim, victim->filepath, victim->pos);

	/* flush the dirty cacheline */
	make_lego_pgcache_clean(victim);

	/* free the cached pages
	 * remove from pgcache HIRS stack Q
	 * the victim still marked as HIR in
	 * Stack S before accessed or cut
	 */
	__free_pgcache_locked(victim);
	remove_from_stack_q_locked(victim);
}

void update_lirs_structure(struct lego_pgcache_struct *pgc)
{
	struct lego_pgcache_struct *cur_bottom_s;

	spin_lock(&pgcache_lirs_lock);

	/* page blocks that are not in stack S now
	 */
	if (!IN_QUEUE(pgc, stack_s)) {
		/* the number of LIR blocks in stack S
		 * has not reach the LIR blocks limit
		 */
		if (atomic_read(&lir_credit) != MAX_LIR_CACHELINES) {
			atomic_inc(&lir_credit);
			set_pgcache_lir(pgc);
			move_to_stack_s_top_locked(pgc);
			goto unlock;
		}

		/* LIR queue reach the limit
		 * treat all non stack S reference as HIR */
		set_pgcache_hir(pgc);
		move_to_stack_s_top_locked(pgc);

		if (IN_QUEUE(pgc, stack_q)) {
			remove_from_stack_q_locked(pgc);
			atomic_dec(&hir_credit);
		}

		add_to_stack_q_top_locked(pgc);
		atomic_inc(&hir_credit);
		goto eviction;
	}

	/* An HIR access need to downgrade the bottom of stack S to
	 * an HIR block, and move it to HIR stack Q, then cut the bottom
	 * of stack S
	 */

	if (HIR(pgc)) {
		/* residental HIR cacheline*/
		if (IN_QUEUE(pgc, stack_q)) {
			remove_from_stack_q_locked(pgc);
			atomic_dec(&hir_credit);
		}

		/* mark current cacheline as LIR */
		set_pgcache_lir(pgc);
		move_to_stack_s_top_locked(pgc);

		/* premote another LIR cacheline to HIR */
		cur_bottom_s = head_entry(pgc, &lirs_stack_s, stack_s);
		set_pgcache_hir(cur_bottom_s);
		add_to_stack_q_top_locked(cur_bottom_s);
		atomic_inc(&hir_credit);

		cut_stack_s_bottom();
		goto eviction;
	}

	/* accessing an LIR page, just move to stack S top
	 * no need for eviction
	 */
	move_to_stack_s_top_locked(pgc);
	cut_stack_s_bottom();
	goto unlock;

eviction:
	if (atomic_read(&hir_credit) > MAX_HIR_CACHELINES) {
		pgcache_evict_one();
		atomic_dec(&hir_credit);
	}
unlock:
	spin_unlock(&pgcache_lirs_lock);
	return;
}

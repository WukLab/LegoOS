/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Nodemasks provide a bitmap suitable for representing the
 * set of Node's in a system, one bit position per Node number.
 */

#ifndef _LEGO_NODEMASK_H_
#define _LEGO_NODEMASK_H_

#include <lego/numa.h>
#include <lego/bitops.h>
#include <lego/bitmap.h>
#include <lego/kernel.h>

typedef struct nodemask {
	DECLARE_BITMAP(bits, MAX_NUMNODES);
} nodemask_t;

/*
 * The inline keyword gives the compiler room to decide to inline, or
 * not inline a function as it sees best.  However, as these functions
 * are called in both __init and non-__init functions, if they are not
 * inlined we will end up with a section mis-match error (of the type of
 * freeable items not being freed).  So we must use __always_inline here
 * to fix the problem.  If other functions in the future also end up in
 * this situation they will also need to be annotated as __always_inline
 */
#define node_set(node, dst) __node_set((node), &(dst))
static __always_inline void __node_set(int node, volatile nodemask_t *dstp)
{
	set_bit(node, dstp->bits);
}

#define node_clear(node, dst) __node_clear((node), &(dst))
static inline void __node_clear(int node, volatile nodemask_t *dstp)
{
	clear_bit(node, dstp->bits);
}

/* No static inline type checking */
#define node_isset(node, nodemask) test_bit((node), (nodemask).bits)

#define node_test_and_set(node, nodemask) \
			__node_test_and_set((node), &(nodemask))
static inline int __node_test_and_set(int node, nodemask_t *addr)
{
	return test_and_set_bit(node, addr->bits);
}

#define nodes_empty(src) __nodes_empty(&(src), MAX_NUMNODES)
static inline int __nodes_empty(const nodemask_t *srcp, unsigned int nbits)
{
	return bitmap_empty(srcp->bits, nbits);
}

#define nodes_full(nodemask) __nodes_full(&(nodemask), MAX_NUMNODES)
static inline int __nodes_full(const nodemask_t *srcp, unsigned int nbits)
{
	return bitmap_full(srcp->bits, nbits);
}

#define nodes_weight(nodemask) __nodes_weight(&(nodemask), MAX_NUMNODES)
static inline int __nodes_weight(const nodemask_t *srcp, unsigned int nbits)
{
	return bitmap_weight(srcp->bits, nbits);
}

#define nodes_setall(dst) __nodes_setall(&(dst), MAX_NUMNODES)
static inline void __nodes_setall(nodemask_t *dstp, unsigned int nbits)
{
	bitmap_fill(dstp->bits, nbits);
}

#define nodes_clear(dst) __nodes_clear(&(dst), MAX_NUMNODES)
static inline void __nodes_clear(nodemask_t *dstp, unsigned int nbits)
{
	bitmap_zero(dstp->bits, nbits);
}

#define first_unset_node(mask) __first_unset_node(&(mask))
static inline int __first_unset_node(const nodemask_t *maskp)
{
	return min_t(int,MAX_NUMNODES,
			find_first_zero_bit(maskp->bits, MAX_NUMNODES));
}

#define first_node(src) __first_node(&(src))
static inline int __first_node(const nodemask_t *srcp)
{
	return min_t(int, MAX_NUMNODES, find_first_bit(srcp->bits, MAX_NUMNODES));
}

#define next_node(n, src) __next_node((n), &(src))
static inline int __next_node(int n, const nodemask_t *srcp)
{
	return min_t(int,MAX_NUMNODES,find_next_bit(srcp->bits, MAX_NUMNODES, n+1));
}

#define NODE_MASK_LAST_WORD	BITMAP_LAST_WORD_MASK(MAX_NUMNODES)

#if MAX_NUMNODES <= BITS_PER_LONG

#define NODE_MASK_ALL							\
{ {									\
	[BITS_TO_LONGS(MAX_NUMNODES)-1] = NODE_MASK_LAST_WORD		\
} }

#else

#define NODE_MASK_ALL							\
{ {									\
	[0 ... BITS_TO_LONGS(MAX_NUMNODES)-2] = ~0UL,			\
	[BITS_TO_LONGS(MAX_NUMNODES)-1] = NODE_MASK_LAST_WORD		\
} }

#endif

#define NODE_MASK_NONE							\
((nodemask_t) { {							\
	[0 ... BITS_TO_LONGS(MAX_NUMNODES)-1] =  0UL			\
} })

#if MAX_NUMNODES > 1
#define for_each_node_mask(node, mask)			\
	for ((node) = first_node(mask);			\
		(node) < MAX_NUMNODES;			\
		(node) = next_node((node), (mask)))
#else /* MAX_NUMNODES == 1 */
#define for_each_node_mask(node, mask)			\
	if (!nodes_empty(mask))				\
		for ((node) = 0; (node) < 1; (node)++)
#endif /* MAX_NUMNODES */

/*
 * Bitmasks that are kept for all the nodes.
 */
enum node_states {
	N_POSSIBLE,		/* The node could become online at some point */
	N_ONLINE,		/* The node is online */
	N_NORMAL_MEMORY,	/* The node has regular memory */
	N_CPU,			/* The node has one or more cpus */

	NR_NODE_STATES
};

/*
 * The following particular system nodemasks and operations
 * on them manage all possible and online nodes.
 */

extern nodemask_t node_states[NR_NODE_STATES];

#if MAX_NUMNODES > 1
static inline int node_state(int node, enum node_states state)
{
	return node_isset(node, node_states[state]);
}

static inline void node_set_state(int node, enum node_states state)
{
	__node_set(node, &node_states[state]);
}

static inline void node_clear_state(int node, enum node_states state)
{
	__node_clear(node, &node_states[state]);
}

static inline void node_set_online(int nid)
{
	node_set_state(nid, N_ONLINE);
}

static inline void node_set_offline(int nid)
{
	node_clear_state(nid, N_ONLINE);
}

static inline int num_node_state(enum node_states state)
{
	return nodes_weight(node_states[state]);
}

#define for_each_node_state(__node, __state) \
	for_each_node_mask((__node), node_states[__state])

#define first_online_node	first_node(node_states[N_ONLINE])
#define first_memory_node	first_node(node_states[N_NORMAL_MEMORY])

extern int nr_node_ids;
extern int nr_online_nodes;

#else /* MAX_NUMNODES > 1 */

static inline int node_state(int node, enum node_states state)
{
	return node == 0;
}

static inline void node_set_state(int node, enum node_states state)
{
}

static inline void node_clear_state(int node, enum node_states state)
{
}

static inline int num_node_state(enum node_states state)
{
	return 1;
}

#define for_each_node_state(node, __state) \
	for ( (node) = 0; (node) == 0; (node) = 1)

#define first_online_node	0
#define first_memory_node	0
#define nr_online_nodes		1
#define nr_node_ids		1

#define node_set_online(node)	   node_set_state((node), N_ONLINE)
#define node_set_offline(node)	   node_clear_state((node), N_ONLINE)

#endif /* MAX_NUMNODES > 1 */

#define node_online_map			node_states[N_ONLINE]
#define node_possible_map		node_states[N_POSSIBLE]

#define num_online_nodes()		num_node_state(N_ONLINE)
#define num_possible_nodes()		num_node_state(N_POSSIBLE)
#define node_online(node)		node_state((node), N_ONLINE)
#define node_possible(node)		node_state((node), N_POSSIBLE)

#define for_each_node(node)		for_each_node_state(node, N_POSSIBLE)
#define for_each_online_node(node)	for_each_node_state(node, N_ONLINE)

#if MAX_NUMNODES > 1
void __init setup_nr_node_ids(void);
#else
static inline void setup_nr_node_ids(void) { }
#endif

#endif /* _LEGO_NODEMASK_H_ */

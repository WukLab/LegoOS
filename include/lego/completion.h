/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Completion is actually a user of <wait.h>
 */

#ifndef _LEGO_COMPLETION_H_
#define _LEGO_COMPLETION_H_

#include <lego/wait.h>

/*
 * struct completion - structure used to maintain state for a "completion"
 *
 * This is the opaque structure used to maintain the state for a "completion".
 * Completions currently use a FIFO to queue threads that have to wait for
 * the "completion" event.
 *
 * See also:  complete(), wait_for_completion() (and friends _timeout,
 * _interruptible, _interruptible_timeout, and _killable), init_completion(),
 * reinit_completion(), and macros DECLARE_COMPLETION(),
 * DECLARE_COMPLETION_ONSTACK().
 */
struct completion {
	unsigned int done;
	wait_queue_head_t wait;
};

#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }

/**
 * DEFINE_COMPLETION - define and initialize a completion structure
 * @work:  identifier for the completion structure
 *
 * This macro defines and initializes a completion structure. Generally used
 * for static declarations. You should use the _ONSTACK variant for automatic
 * variables.
 */
#define DEFINE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)

/**
 * init_completion - Initialize a dynamically allocated completion
 * @x:  pointer to completion structure that is to be initialized
 *
 * This inline function will initialize a dynamically created completion
 * structure.
 */
static inline void init_completion(struct completion *x)
{
	x->done = 0;
	init_waitqueue_head(&x->wait);
}

/**
 * reinit_completion - reinitialize a completion structure
 * @x:  pointer to completion structure that is to be reinitialized
 *
 * This inline function should be used to reinitialize a completion structure so it can
 * be reused. This is especially important after complete_all() is used.
 */
static inline void reinit_completion(struct completion *x)
{
	x->done = 0;
}

void wait_for_completion(struct completion *);
int wait_for_completion_interruptible(struct completion *x);
int wait_for_completion_killable(struct completion *x);
unsigned long wait_for_completion_timeout(struct completion *x, unsigned long timeout);
long wait_for_completion_interruptible_timeout(struct completion *x, unsigned long timeout);
long wait_for_completion_killable_timeout(struct completion *x, unsigned long timeout);
bool try_wait_for_completion(struct completion *x);
bool completion_done(struct completion *x);

void complete(struct completion *);
void complete_all(struct completion *);

#endif /* _LEGO_COMPLETION_H_ */

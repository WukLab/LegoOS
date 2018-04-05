/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file implements all epoll syscalls:
 * 	epoll_create
 * 	epoll_wait
 * 	epoll_ctl
 * and epoll file ops
 */

#include <lego/syscalls.h>
#include <lego/socket.h>
#include <lego/atomic.h>
#include <processor/processor.h>
#include <lego/net.h>
#include <lego/fit_ibapi.h>
#include <lego/files.h>
#include <processor/fs.h>
#include <lego/spinlock.h>
#include <lego/hashtable.h>
#include <lego/comp_storage.h>
#include <lego/delay.h>
#include <lego/time.h>
#include <lego/timer.h>
#include <lego/jiffies.h>

#ifdef CONFIG_DEBUG_EPOLL
#define epoll_debug(fmt, ...) \
	pr_debug("%s():%d " fmt, __func__, __LINE__, __VA_ARGS__)
#else
static inline void epoll_debug(const char *fmt, ...) { }
#endif

#define EP_MAX_EVENTS (INT_MAX / sizeof(struct epoll_event))

#define EP_UNACTIVE_PTR ((void *) -1L)

/* Epoll private bits inside the event mask */
#define EP_PRIVATE_BITS (EPOLLWAKEUP | EPOLLONESHOT | EPOLLET)

/* Maximum msec timeout value storeable in a long int */
#define EP_MAX_MSTIMEO min(1000ULL * MAX_SCHEDULE_TIMEOUT / HZ, (LONG_MAX - 999ULL) / HZ)

struct epoll_filefd {
	struct file *file;
	int fd;
} __packed;

/*
 * Each file descriptor added to the lego_eventpoll interface will
 * have an entry of this type linked to the "rbr" RB tree.
 * Avoid increasing the size of this struct, there can be many thousands
 * of these on a server and we do not want this to take another cache line.
 */
struct epitem {
	/* RB tree node used to link this structure to the lego_eventpoll RB tree */
	struct rb_node rbn;

	/* List header used to link this structure to the lego_eventpoll ready list */
	struct list_head rdllink;

	/*
	 * Works together "struct lego_eventpoll"->ovflist in keeping the
	 * single linked chain of items.
	 */
	struct epitem *next;

	/* The file descriptor information this item refers to */
	struct epoll_filefd ffd;

	/* Number of active wait queue attached to poll operations */
	int nwait;

	/* List containing poll wait queues */
//	struct list_head pwqlist;

	/* The "container" of this item */
	struct lego_eventpoll *ep;

	/* List header used to link this item to the "struct file" items list */
	struct list_head fllink;

	/* The structure that describe the interested events and the source fd */
	struct epoll_event event;
};

/*
 * This structure is stored inside the "private_data" member of the file
 * structure and represents the main data structure for the lego_eventpoll
 * interface.
 */
struct lego_eventpoll {
	/* Protect the access to this structure */
	spinlock_t lock;

	/*
	 * This mutex is used to ensure that files are not removed
	 * while epoll is using them. This is held during the event
	 * collection loop, the file cleanup path, the epoll file exit
	 * code and the ctl operations.
	 */
	struct mutex mtx;

	/* Wait queue used by sys_epoll_wait() */
	wait_queue_head_t wq;

	/* Wait queue used by file->poll() */
//	wait_queue_head_t poll_wait;

	/* List of ready file descriptors */
	struct list_head rdllist;

	/* RB tree root used to store monitored fd structs */
	struct rb_root rbr;

	/*
	 * This is a single linked list that chains all the "struct epitem" that
	 * happened while transferring ready events to userspace w/out
	 * holding ->lock.
	 */
	struct epitem *ovflist;

	struct file *file;

	/* used to optimize loop detection check */
//	int visited;
//	struct list_head visited_list_link;
};

/*
 * This mutex is used to serialize ep_free() and eventpoll_release_file().
 */
static DEFINE_MUTEX(epmutex);

static ssize_t sock_ep_read(struct file *f, char __user *ubuf, size_t len, loff_t *offset)
{
}

static ssize_t sock_ep_write(struct file *f, const char __user *ubuf, size_t len, loff_t *offset)
{
}

/* File callbacks that implement the lego_eventpoll file behaviour */
static const struct file_operations eventpoll_fops = {
	.read		= sock_ep_read,
	.write		= sock_ep_write,
};

/* Tells if the epoll_ctl(2) operation needs an event copy from userspace */
static inline int ep_op_has_event(int op)
{
	return op != EPOLL_CTL_DEL;
}


static inline int is_file_epoll(struct file *f)
{
	return f->f_op == &eventpoll_fops;
}

static inline void ep_set_ffd(struct epoll_filefd *ffd,
			      struct file *file, int fd)
{
	ffd->file = file;
	ffd->fd = fd;
}

/* Compare RB tree keys */
static inline int ep_cmp_ffd(struct epoll_filefd *p1,
			     struct epoll_filefd *p2)
{
	return (p1->file > p2->file ? +1:
	        (p1->file < p2->file ? -1 : p1->fd - p2->fd));
}

/* Tells us if the item is currently linked */
static inline int ep_is_linked(struct list_head *p)
{
	return !list_empty(p);
}

/* Used by the ep_send_events() function as callback private data */
struct ep_send_events_data {
	int maxevents;
	struct epoll_event __user *events;
};

static void ep_rbtree_insert(struct lego_eventpoll *ep, struct epitem *epi)
{
	int kcmp;
	struct rb_node **p = &ep->rbr.rb_node, *parent = NULL;
	struct epitem *epic;

	while (*p) {
		parent = *p;
		epic = rb_entry(parent, struct epitem, rbn);
		kcmp = ep_cmp_ffd(&epi->ffd, &epic->ffd);
		if (kcmp > 0)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}
	rb_link_node(&epi->rbn, parent, p);
	rb_insert_color(&epi->rbn, &ep->rbr);
}

/*
 * Must be called with "mtx" held.
 */
static int ep_insert(struct lego_eventpoll *ep, struct epoll_event *event,
		     struct file *tfile, int fd)
{
	int error = 0, revents, pwake = 0;
	unsigned long flags;
	struct epitem *epi;

	//if (!(epi = kmem_cache_alloc(epi_cache, GFP_KERNEL)))
	if (!(epi = (struct epitem *)kmalloc(sizeof(struct epitem), GFP_KERNEL)))
		return -ENOMEM;

	epoll_debug("%s\n", __func__);

	/* Item initialization follow here ... */
	INIT_LIST_HEAD(&epi->rdllink);
	INIT_LIST_HEAD(&epi->fllink);
	epi->ep = ep;
	ep_set_ffd(&epi->ffd, tfile, fd);
	epi->event = *event;
	epi->nwait = 0;
	epi->next = EP_UNACTIVE_PTR;

	/* Add the current item to the list of active epoll hook for this file */
	/* XXX add lock back if seeing multithreaded epoll */
	//spin_lock(&tfile->f_lock);
	list_add_tail(&epi->fllink, &tfile->f_epi_links);
	//spin_unlock(&tfile->f_lock);

	/*
	 * Add the current item to the RB tree. All RB tree operations are
	 * protected by "mtx", and ep_insert() is called with "mtx" held.
	 */
	ep_rbtree_insert(ep, epi);

	/* We have to drop the new item inside our item list to keep track of it */
	spin_lock_irqsave(&ep->lock, flags);

	/* If the file is already "ready" we drop it inside the ready list */
	revents = tfile->ready_state;
	if ((revents & event->events) && !ep_is_linked(&epi->rdllink)) {
		list_add_tail(&epi->rdllink, &ep->rdllist);

		/* Notify waiting tasks that events are available */
		if (waitqueue_active(&ep->wq))
			wake_up_locked(&ep->wq);
	}

	spin_unlock_irqrestore(&ep->lock, flags);

	/* We have to call this outside the lock */
	//if (pwake)
	//	ep_poll_safewake(&ep->poll_wait);

	return 0;

error_remove_epi:
	rb_erase(&epi->rbn, &ep->rbr);

error_unregister:
//	ep_unregister_pollwait(ep, epi);

	/*
	 * We need to do this because an event could have been arrived on some
	 * allocated wait queue. Note that we don't care about the ep->ovflist
	 * list, since that is used/cleaned only inside a section bound by "mtx".
	 * And ep_insert() is called with "mtx" held.
	 */
	spin_lock_irqsave(&ep->lock, flags);
	if (ep_is_linked(&epi->rdllink))
		list_del_init(&epi->rdllink);
	spin_unlock_irqrestore(&ep->lock, flags);

//	wakeup_source_unregister(ep_wakeup_source(epi));

error_create_wakeup_source:
	//kmem_cache_free(epi_cache, epi);
	kfree(epi);

	return error;
}

/*
 * Search the file inside the lego_eventpoll tree. The RB tree operations
 * are protected by the "mtx" mutex, and ep_find() must be called with
 * "mtx" held.
 */
static struct epitem *ep_find(struct lego_eventpoll *ep, struct file *file, int fd)
{
	int kcmp;
	struct rb_node *rbp;
	struct epitem *epi, *epir = NULL;
	struct epoll_filefd ffd;

	ep_set_ffd(&ffd, file, fd);
	for (rbp = ep->rbr.rb_node; rbp; ) {
		epi = rb_entry(rbp, struct epitem, rbn);
		kcmp = ep_cmp_ffd(&ffd, &epi->ffd);
		if (kcmp > 0)
			rbp = rbp->rb_right;
		else if (kcmp < 0)
			rbp = rbp->rb_left;
		else {
			epir = epi;
			break;
		}
	}

	return epir;
}

static inline unsigned int ep_item_poll(struct epitem *epi)
{
	return epi->ffd.file->f_op->poll(epi->ffd.file) & epi->event.events;
}

/**
 * ep_scan_ready_list - Scans the ready list in a way that makes possible for
 *                      the scan code, to call f_op->poll(). Also allows for
 *                      O(NumReady) performance.
 *
 * @ep: Pointer to the epoll private data structure.
 * @sproc: Pointer to the scan callback.
 * @priv: Private opaque data passed to the @sproc callback.
 * @depth: The current depth of recursive f_op->poll calls.
 *
 * Returns: The same integer error code returned by the @sproc callback.
 */
static int ep_scan_ready_list(struct lego_eventpoll *ep,
			      int (*sproc)(struct lego_eventpoll *,
					   struct list_head *, void *),
			      void *priv,
			      int depth)
{
	int error, pwake = 0;
	unsigned long flags;
	struct epitem *epi, *nepi;
	LIST_HEAD(txlist);

	epoll_debug("%s\n", __func__);

	/*
	 * We need to lock this because we could be hit by
	 * eventpoll_release_file() and epoll_ctl().
	 */
	mutex_lock(&ep->mtx);

	/*
	 * Steal the ready list, and re-init the original one to the
	 * empty list. Also, set ep->ovflist to NULL so that events
	 * happening while looping w/out locks, are not lost. We cannot
	 * have the poll callback to queue directly on ep->rdllist,
	 * because we want the "sproc" callback to be able to do it
	 * in a lockless way.
	 */
	spin_lock_irqsave(&ep->lock, flags);
	list_splice_init(&ep->rdllist, &txlist);
	ep->ovflist = NULL;
	spin_unlock_irqrestore(&ep->lock, flags);

	/*
	 * Now call the callback function.
	 */
	error = (*sproc)(ep, &txlist, priv);

	spin_lock_irqsave(&ep->lock, flags);
	/*
	 * During the time we spent inside the "sproc" callback, some
	 * other events might have been queued by the poll callback.
	 * We re-insert them inside the main ready-list here.
	 */
	for (nepi = ep->ovflist; (epi = nepi) != NULL;
	     nepi = epi->next, epi->next = EP_UNACTIVE_PTR) {
		/*
		 * We need to check if the item is already in the list.
		 * During the "sproc" callback execution time, items are
		 * queued into ->ovflist but the "txlist" might already
		 * contain them, and the list_splice() below takes care of them.
		 */
		if (!ep_is_linked(&epi->rdllink)) {
			list_add_tail(&epi->rdllink, &ep->rdllist);
		}
	}
	/*
	 * We need to set back ep->ovflist to EP_UNACTIVE_PTR, so that after
	 * releasing the lock, events will be queued in the normal way inside
	 * ep->rdllist.
	 */
	ep->ovflist = EP_UNACTIVE_PTR;

	/*
	 * Quickly re-inject items left on "txlist".
	 */
	list_splice(&txlist, &ep->rdllist);

	if (!list_empty(&ep->rdllist)) {
		/*
		 * Wake up (if active) both the lego_eventpoll wait list and
		 * the ->poll() wait list (delayed after we release the lock).
		 */
		if (waitqueue_active(&ep->wq))
			wake_up_locked(&ep->wq);
	}
	spin_unlock_irqrestore(&ep->lock, flags);

	mutex_unlock(&ep->mtx);

	return error;
}

static int ep_send_events_proc(struct lego_eventpoll *ep, struct list_head *head,
			       void *priv)
{
	struct ep_send_events_data *esed = priv;
	int eventcnt;
	unsigned int revents;
	struct epitem *epi;
	struct epoll_event __user *uevent;

	epoll_debug("%s\n", __func__);

	/*
	 * We can loop without lock because we are passed a task private list.
	 * Items cannot vanish during the loop because ep_scan_ready_list() is
	 * holding "mtx" during this call.
	 */
	for (eventcnt = 0, uevent = esed->events;
	     !list_empty(head) && eventcnt < esed->maxevents;) {
		epi = list_first_entry(head, struct epitem, rdllink);

		list_del_init(&epi->rdllink);
		epoll_debug("%s: got ready epi %p\n", __func__, epi);

		revents = ep_item_poll(epi);

		/*
		 * If the event mask intersect the caller-requested one,
		 * deliver the event to userspace. Again, ep_scan_ready_list()
		 * is holding "mtx", so no operations coming from userspace
		 * can change the item.
		 */
		if (revents) {
			if (__put_user(revents, &uevent->events) ||
			    __put_user(epi->event.data, &uevent->data)) {
				list_add(&epi->rdllink, head);
				return eventcnt ? eventcnt : -EFAULT;
			}
			eventcnt++;
			uevent++;
			if (epi->event.events & EPOLLONESHOT)
				epi->event.events &= EP_PRIVATE_BITS;
			else if (!(epi->event.events & EPOLLET)) {
				/*
				 * If this file has been added with Level
				 * Trigger mode, we need to insert back inside
				 * the ready list, so that the next call to
				 * epoll_wait() will check again the events
				 * availability. At this point, no one can insert
				 * into ep->rdllist besides us. The epoll_ctl()
				 * callers are locked out by
				 * ep_scan_ready_list() holding "mtx" and the
				 * poll callback will queue them in ep->ovflist.
				 */
				epoll_debug("%s: EPOLLET mode inserting ready epi back %p\n", __func__, epi);
				list_add_tail(&epi->rdllink, &ep->rdllist);
			}
		}
	}

	return eventcnt;
}

static int ep_send_events(struct lego_eventpoll *ep,
			  struct epoll_event __user *events, int maxevents)
{
	struct ep_send_events_data esed;

	esed.maxevents = maxevents;
	esed.events = events;

	return ep_scan_ready_list(ep, ep_send_events_proc, &esed, 0);
}

/**
 * ep_events_available - Checks if ready events might be available.
 *
 * @ep: Pointer to the lego_eventpoll context.
 *
 * Returns: Returns a value different than zero if ready events are available,
 *          or zero otherwise.
 */
static inline int ep_events_available(struct lego_eventpoll *ep)
{
	return !list_empty(&ep->rdllist) || ep->ovflist != EP_UNACTIVE_PTR;
}

/**
 * ep_poll - Retrieves ready events, and delivers them to the caller supplied
 *           event buffer.
 *
 * @ep: Pointer to the lego_eventpoll context.
 * @events: Pointer to the userspace buffer where the ready events should be
 *          stored.
 * @maxevents: Size (in terms of number of events) of the caller event buffer.
 * @timeout: Maximum timeout for the ready events fetch operation, in
 *           milliseconds. If the @timeout is zero, the function will not block,
 *           while if the @timeout is less than zero, the function will block
 *           until at least one event has been retrieved (or an error
 *           occurred).
 *
 * Returns: Returns the number of ready events which have been fetched, or an
 *          error code, in case of error.
 */
static int ep_poll(struct lego_eventpoll *ep, struct epoll_event __user *events,
		   int maxevents, long timeout)
{
	int res = 0, eavail, timed_out = 0;
	unsigned long flags;
	long slack = 0;
	wait_queue_t wait;
	long jtimeout; 

	jtimeout = (timeout < 0 || timeout >= EP_MAX_MSTIMEO) ?  
		MAX_SCHEDULE_TIMEOUT : (timeout * HZ + 999) / 1000;  
	if (timeout == 0) {
		/*
		 * Avoid the unnecessary trip to the wait queue loop, if the
		 * caller specified a non blocking operation.
		 */
		timed_out = 1;
		spin_lock_irqsave(&ep->lock, flags);
		goto check_events;
	}

	epoll_debug("%s timeout %d jiffies %d\n", __func__, timeout, jtimeout);

fetch_events:
	spin_lock_irqsave(&ep->lock, flags);

	if (!ep_events_available(ep)) {
		epoll_debug("event unavailable now\n");
		/*
		 * We don't have any available event to return to the caller.
		 * We need to sleep here, and we will be wake up by
		 * ep_poll_callback() when events will become available.
		 */
		init_waitqueue_entry(&wait, current);
		__add_wait_queue_exclusive(&ep->wq, &wait);

		for (;;) {
			/*
			 * We don't want to sleep if the ep_poll_callback() sends us
			 * a wakeup in between. That's why we set the task state
			 * to TASK_INTERRUPTIBLE before doing the checks.
			 */
			set_current_state(TASK_INTERRUPTIBLE);
			if (ep_events_available(ep) || timed_out)
				break;
			if (signal_pending(current)) {
				res = -EINTR;
				break;
			}

			spin_unlock_irqrestore(&ep->lock, flags);
			jtimeout = schedule_timeout(jtimeout);
			spin_lock_irqsave(&ep->lock, flags);
		}
		__remove_wait_queue(&ep->wq, &wait);

		set_current_state(TASK_RUNNING);
	}
check_events:
	/* Is it worth to try to dig for events ? */
	eavail = ep_events_available(ep);

	spin_unlock_irqrestore(&ep->lock, flags);

	/*
	 * Try to transfer events to user space. In case we get 0 events and
	 * there's still timeout left over, we go trying again in search of
	 * more luck.
	 */
	if (!res && eavail &&
	    !(res = ep_send_events(ep, events, maxevents)) && !timed_out)
		goto fetch_events;

	return res;
}

/*
 * This is the callback that is passed to the wait queue wakeup
 * mechanism. It is called by the stored file descriptors when they
 * have events to report.
 */
static int ep_poll_callback(struct epitem *epi, void *key)
{
	int pwake = 0;
	unsigned long flags;
	struct lego_eventpoll *ep;

	BUG_ON(epi == NULL);
	ep = epi->ep;

	epoll_debug("%s\n", __func__);

	spin_lock_irqsave(&ep->lock, flags);

	/*
	 * If the event mask does not contain any poll(2) event, we consider the
	 * descriptor to be disabled. This condition is likely the effect of the
	 * EPOLLONESHOT bit that disables the descriptor when an event is received,
	 * until the next EPOLL_CTL_MOD will be issued.
	 */
	if (!(epi->event.events & ~EP_PRIVATE_BITS))
		goto out_unlock;

	/*
	 * Check the events coming with the callback. At this stage, not
	 * every device reports the events in the "key" parameter of the
	 * callback. We need to be able to handle both cases here, hence the
	 * test for "key" != NULL before the event match test.
	 */
	if (key && !((unsigned long) key & epi->event.events))
		goto out_unlock;

	/*
	 * If we are transferring events to userspace, we can hold no locks
	 * (because we're accessing user memory, and because of linux f_op->poll()
	 * semantics). All the events that happen during that period of time are
	 * chained in ep->ovflist and requeued later on.
	 */
	if (unlikely(ep->ovflist != EP_UNACTIVE_PTR)) {
		if (epi->next == EP_UNACTIVE_PTR) {
			epi->next = ep->ovflist;
			ep->ovflist = epi;
		}
		goto out_unlock;
	}

	/* If this file is already in the ready list we exit soon */
	if (!ep_is_linked(&epi->rdllink)) {
		list_add_tail(&epi->rdllink, &ep->rdllist);
	}

	/* Wake up ( if active ) both the eventpoll wait list */
	if (waitqueue_active(&ep->wq))
		wake_up_locked(&ep->wq);

out_unlock:
	spin_unlock_irqrestore(&ep->lock, flags);

	return 1;
}

int lego_epoll_callback(struct file *f, void *key)
{
	struct epitem *epi;

	epoll_debug("%s\n", __func__);

	list_for_each_entry(epi, &f->f_epi_links, fllink) {
		if (epi == NULL)
			continue;
		ep_poll_callback(epi, key);
	}

	return 0;
}

static int ep_alloc(struct lego_eventpoll **pep)
{
	int error;
	struct lego_eventpoll *ep;

	error = -ENOMEM;
	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (unlikely(!ep))
		return error;

	spin_lock_init(&ep->lock);
	mutex_init(&ep->mtx);
	init_waitqueue_head(&ep->wq);
	INIT_LIST_HEAD(&ep->rdllist);
	ep->rbr = RB_ROOT;
	ep->ovflist = EP_UNACTIVE_PTR;

	*pep = ep;

	return 0;
}

/*
 * Open an lego_eventpoll file descriptor.
 */
SYSCALL_DEFINE1(epoll_create1, int, flags)
{
	int error, fd = -1;
	struct lego_eventpoll *ep = NULL;
	struct file *f;

	if (flags & ~EPOLL_CLOEXEC)
		return -EINVAL;

	/*
	 * Create the internal data structure ("struct lego_eventpoll").
	 */
	error = ep_alloc(&ep);
	if (error < 0)
		return error;
	/*
	 * Creates all the items needed to setup an lego_eventpoll file. That is,
	 * a file structure and a free file descriptor.
	 */
	fd = sys_open("sock/epoll", O_RDWR | O_CREAT, 0);
	if (fd < 0) {
		error = fd;
		return error;
	}
	f = fdget(fd);
	if (!f)
		return -ENFILE;
	f->f_op = &eventpoll_fops;
	f->private_data = ep;

	ep->file = f;
	
	return fd;
}

SYSCALL_DEFINE1(epoll_create, int, size)
{
	if (size <= 0)
		return -EINVAL;

	return sys_epoll_create1(0);
}

/*
 * The following function implements the controller interface for
 * the lego_eventpoll file that enables the insertion/removal/change of
 * file descriptors inside the interest set.
 */
SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd,
		struct epoll_event __user *, event)
{
	int error;
	int did_lock_epmutex = 0;
	struct file *file, *tfile;
	struct lego_eventpoll *ep;
	struct epitem *epi;
	struct epoll_event epds;

	epoll_debug("%s\n", __func__);

	error = -EFAULT;
	if (ep_op_has_event(op) &&
	    copy_from_user(&epds, event, sizeof(struct epoll_event)))
		goto error_return;

	/* Get the "struct file *" for the lego_eventpoll file */
	error = -EBADF;
	file = fdget(epfd);
	if (!file)
		goto error_return;

	/* Get the "struct file *" for the target file */
	tfile = fdget(fd);
	if (!tfile)
		goto error_fput;

	/*
	 * We have to check that the file structure underneath the file descriptor
	 * the user passed to us _is_ an lego_eventpoll file. And also we do not permit
	 * adding an epoll file descriptor inside itself.
	 */
	error = -EINVAL;
	if (file == tfile || !is_file_epoll(file))
		goto error_tgt_fput;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = (struct lego_eventpoll *)file->private_data;

	/*
	 * We need to hold the epmutex across both ep_insert and ep_remove
	 * b/c we want to make sure we are looking at a coherent view of
	 * epoll network.
	 */
	if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_DEL) {
		mutex_lock(&epmutex);
		did_lock_epmutex = 1;
	}

	mutex_lock(&ep->mtx);

	/*
	 * Try to lookup the file inside our RB tree, Since we grabbed "mtx"
	 * above, we can be sure to be able to use the item looked up by
	 * ep_find() till we release the mutex.
	 */
	epi = ep_find(ep, tfile, fd);

	error = -EINVAL;
	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
			epds.events |= POLLERR | POLLHUP;
			error = ep_insert(ep, &epds, tfile, fd);
		} else
			error = -EEXIST;
		break;
#if 0
// TODO, not used currently in TensorFlow
	case EPOLL_CTL_DEL:
		if (epi)
			error = ep_remove(ep, epi);
		else
			error = -ENOENT;
		break;
	case EPOLL_CTL_MOD:
		if (epi) {
			epds.events |= POLLERR | POLLHUP;
			error = ep_modify(ep, epi, &epds);
		} else
			error = -ENOENT;
		break;
#endif
	default:
		printk(KERN_CRIT "%s op %d not supported now\n", __func__, op);
	}
	mutex_unlock(&ep->mtx);

error_tgt_fput:
	if (did_lock_epmutex)
		mutex_unlock(&epmutex);

	//fput(tfile);
error_fput:
	//fput(file);
error_return:

	return error;
}

/*
 * Implement the event wait interface for the lego_eventpoll file. It is the kernel
 * part of the user space epoll_wait(2).
 */
SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
		int, maxevents, int, timeout)
{
	int error;
	struct file *f;
	struct lego_eventpoll *ep;

	epoll_debug("%s\n", __func__);

	/* The maximum number of event must be greater than zero */
	if (maxevents <= 0 || maxevents > EP_MAX_EVENTS)
		return -EINVAL;

	/* Get the "struct file *" for the lego_eventpoll file */
	f = fdget(epfd);
	if (!f)
		return -EBADF;

	/*
	 * We have to check that the file structure underneath the fd
	 * the user passed to us _is_ an lego_eventpoll file.
	 */
	error = -EINVAL;
	if (!is_file_epoll(f))
		goto error_fput;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = f->private_data;

	/* Time to fish for events ... */
	error = ep_poll(ep, events, maxevents, timeout);

error_fput:
	//fdput(f);
	return error;
}

#if 0
/*
 * POSIX select on fd_sets
 * Only supporting inp now (incoming buffer)
 */
SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, fd_set __user *, outp,
		fd_set __user *, exp, struct timeval __user *, tvp)
{
	int fd;
	struct timeval *start, *end;
	struct timeval *timeout;
	struct lego_socket *sock;
	struct file *f = fdget(fd);

	if (!f)
		return -ENFILE;
	sock = (struct lego_socket *)f->private_data;

	copy_from_user(timeout, tvp, sizeof (struct timeval));
//	gettimeofday(

	while (1) {
		fd = inp;
		if ((sock->avail_buf_size) > 0) {
		}
	}	
}
#endif



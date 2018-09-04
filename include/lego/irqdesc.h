/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_IRQDESC_H_
#define _LEGO_IRQDESC_H_

#include <lego/irq.h>
#include <lego/irqchip.h>

#include <lego/msi.h>
#include <lego/spinlock.h>

/*
 * Bits used by threaded handlers:
 * IRQTF_RUNTHREAD - signals that the interrupt handler thread should run
 * IRQTF_WARNED    - warning "IRQ_WAKE_THREAD w/o thread_fn" has been printed
 * IRQTF_AFFINITY  - irq thread is requested to adjust affinity
 * IRQTF_FORCED_THREAD  - irq action is force threaded
 */
enum {
	IRQTF_RUNTHREAD,
	IRQTF_WARNED,
	IRQTF_AFFINITY,
	IRQTF_FORCED_THREAD,
};

/*
 * Bit masks for irq_common_data.state_use_accessors
 *
 * IRQD_TRIGGER_MASK		- Mask for the trigger type bits
 * IRQD_SETAFFINITY_PENDING	- Affinity setting is pending
 * IRQD_NO_BALANCING		- Balancing disabled for this IRQ
 * IRQD_PER_CPU			- Interrupt is per cpu
 * IRQD_AFFINITY_SET		- Interrupt affinity was set
 * IRQD_LEVEL			- Interrupt is level triggered
 * IRQD_WAKEUP_STATE		- Interrupt is configured for wakeup
 *				  from suspend
 * IRDQ_MOVE_PCNTXT		- Interrupt can be moved in process
 *				  context
 * IRQD_IRQ_DISABLED		- Disabled state of the interrupt
 * IRQD_IRQ_MASKED		- Masked state of the interrupt
 * IRQD_IRQ_INPROGRESS		- In progress state of the interrupt
 * IRQD_WAKEUP_ARMED		- Wakeup mode armed
 * IRQD_FORWARDED_TO_VCPU	- The interrupt is forwarded to a VCPU
 * IRQD_AFFINITY_MANAGED	- Affinity is auto-managed by the kernel
 */
enum {
	IRQD_TRIGGER_MASK		= 0xf,
	IRQD_SETAFFINITY_PENDING	= (1 <<  8),
	IRQD_NO_BALANCING		= (1 << 10),
	IRQD_PER_CPU			= (1 << 11),
	IRQD_AFFINITY_SET		= (1 << 12),
	IRQD_LEVEL			= (1 << 13),
	IRQD_WAKEUP_STATE		= (1 << 14),
	IRQD_MOVE_PCNTXT		= (1 << 15),
	IRQD_IRQ_DISABLED		= (1 << 16),
	IRQD_IRQ_MASKED			= (1 << 17),
	IRQD_IRQ_INPROGRESS		= (1 << 18),
	IRQD_WAKEUP_ARMED		= (1 << 19),
	IRQD_FORWARDED_TO_VCPU		= (1 << 20),
	IRQD_AFFINITY_MANAGED		= (1 << 21),
};

/*
 * struct irq_common_data - per irq data shared by all irqchips
 * @state_use_accessors: status information for irq chip functions.
 *			Use accessor functions to deal with it
 * @node:		node index useful for balancing
 * @handler_data:	per-IRQ data for the irq_chip methods
 * @affinity:		IRQ affinity on SMP. If this is an IPI
 *			related irq, then this is the mask of the
 *			CPUs to which an IPI can be sent.
 * @msi_desc:		MSI descriptor
 * @ipi_offset:		Offset of first IPI target cpu in @affinity. Optional.
 */
struct irq_common_data {
	unsigned int		state_use_accessors;
#ifdef CONFIG_NUMA
	unsigned int		node;
#endif
	void			*handler_data;
	struct msi_desc		*msi_desc;
	struct cpumask		affinity;
#ifdef CONFIG_GENERIC_IRQ_IPI
	unsigned int		ipi_offset;
#endif
};

/**
 * struct irq_data - per irq chip data passed down to chip functions
 * @mask:		precomputed bitmask for accessing the chip registers
 * @irq:		interrupt number
 * @hwirq:		hardware interrupt number, local to the interrupt domain
 * @common:		point to data shared by all irqchips
 * @chip:		low level interrupt hardware access
 * @domain:		Interrupt translation domain; responsible for mapping
 *			between hwirq number and lego irq number.
 * @parent_data:	pointer to parent struct irq_data to support hierarchy
 *			irq_domain
 * @chip_data:		platform-specific per-chip private data for the chip
 *			methods, to allow shared chip implementations
 */
struct irq_data {
	u32			mask;
	unsigned int		irq;
	unsigned long		hwirq;
	struct irq_common_data	*common;
	struct irq_chip		*chip;
	struct irq_domain	*domain;
	struct irq_data		*parent_data;
	void			*chip_data;
};

/**
 * struct irqaction - per interrupt action descriptor
 * @handler:	interrupt handler function
 * @dev_id:	cookie to identify the device
 * @next:	pointer to the next irqaction for shared interrupts
 * @irq:	interrupt number
 * @flags:	flags (see IRQF_* above)
 * @thread_fn:	interrupt handler function for threaded interrupts
 * @thread:	thread pointer for threaded interrupts
 * @secondary:	pointer to secondary irqaction (force threading)
 * @thread_flags:	flags related to @thread
 * @thread_mask:	bitmask for keeping track of @thread activity
 * @name:	name of the device
 */
struct irqaction {
	irq_handler_t		handler;
	void			*dev_id;
	struct irqaction	*next;
	irq_handler_t		thread_fn;
	struct task_struct	*thread;
	struct irqaction	*secondary;
	unsigned int		irq;
	unsigned int		flags;
	unsigned long		thread_flags;
	unsigned long		thread_mask;
	const char		*name;
} ____cacheline_aligned;

extern int __must_check
request_threaded_irq(unsigned int irq, irq_handler_t handler,
		     irq_handler_t thread_fn,
		     unsigned long flags, const char *name, void *dev);

static inline int __must_check
request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
	    const char *name, void *dev)
{
	return request_threaded_irq(irq, handler, NULL, flags, name, dev);
}

/*
 * IRQ line status.
 *
 * IRQ_TYPE_NONE		- default, unspecified type
 * IRQ_TYPE_EDGE_RISING		- rising edge triggered
 * IRQ_TYPE_EDGE_FALLING	- falling edge triggered
 * IRQ_TYPE_EDGE_BOTH		- rising and falling edge triggered
 * IRQ_TYPE_LEVEL_HIGH		- high level triggered
 * IRQ_TYPE_LEVEL_LOW		- low level triggered
 * IRQ_TYPE_LEVEL_MASK		- Mask to filter out the level bits
 * IRQ_TYPE_SENSE_MASK		- Mask for all the above bits
 * IRQ_TYPE_DEFAULT		- For use by some PICs to ask irq_set_type
 *				  to setup the HW to a sane default (used
 *                                by irqdomain map() callbacks to synchronize
 *                                the HW state and SW flags for a newly
 *                                allocated descriptor).
 *
 * IRQ_TYPE_PROBE		- Special flag for probing in progress
 *
 * Bits which can be modified via irq_set/clear/modify_status_flags()
 * IRQ_LEVEL			- Interrupt is level type. Will be also
 *				  updated in the code when the above trigger
 *				  bits are modified via irq_set_irq_type()
 * IRQ_PER_CPU			- Mark an interrupt PER_CPU. Will protect
 *				  it from affinity setting
 * IRQ_NOPROBE			- Interrupt cannot be probed by autoprobing
 * IRQ_NOREQUEST		- Interrupt cannot be requested via
 *				  request_irq()
 * IRQ_NOTHREAD			- Interrupt cannot be threaded
 * IRQ_NOAUTOEN			- Interrupt is not automatically enabled in
 *				  request/setup_irq()
 * IRQ_NO_BALANCING		- Interrupt cannot be balanced (affinity set)
 * IRQ_MOVE_PCNTXT		- Interrupt can be migrated from process context
 * IRQ_NESTED_THREAD		- Interrupt nests into another thread
 * IRQ_PER_CPU_DEVID		- Dev_id is a per-cpu variable
 * IRQ_IS_POLLED		- Always polled by another interrupt. Exclude
 *				  it from the spurious interrupt detection
 *				  mechanism and from core side polling.
 * IRQ_DISABLE_UNLAZY		- Disable lazy irq disable
 */
enum {
	IRQ_TYPE_NONE		= 0x00000000,
	IRQ_TYPE_EDGE_RISING	= 0x00000001,
	IRQ_TYPE_EDGE_FALLING	= 0x00000002,
	IRQ_TYPE_EDGE_BOTH	= (IRQ_TYPE_EDGE_FALLING | IRQ_TYPE_EDGE_RISING),
	IRQ_TYPE_LEVEL_HIGH	= 0x00000004,
	IRQ_TYPE_LEVEL_LOW	= 0x00000008,
	IRQ_TYPE_LEVEL_MASK	= (IRQ_TYPE_LEVEL_LOW | IRQ_TYPE_LEVEL_HIGH),
	IRQ_TYPE_SENSE_MASK	= 0x0000000f,
	IRQ_TYPE_DEFAULT	= IRQ_TYPE_SENSE_MASK,

	IRQ_TYPE_PROBE		= 0x00000010,

	IRQ_LEVEL		= (1 <<  8),
	IRQ_PER_CPU		= (1 <<  9),
	IRQ_NOPROBE		= (1 << 10),
	IRQ_NOREQUEST		= (1 << 11),
	IRQ_NOAUTOEN		= (1 << 12),
	IRQ_NO_BALANCING	= (1 << 13),
	IRQ_MOVE_PCNTXT		= (1 << 14),
	IRQ_NESTED_THREAD	= (1 << 15),
	IRQ_NOTHREAD		= (1 << 16),
	IRQ_PER_CPU_DEVID	= (1 << 17),
	IRQ_IS_POLLED		= (1 << 18),
	IRQ_DISABLE_UNLAZY	= (1 << 19),
};

#define IRQF_MODIFY_MASK	\
	(IRQ_TYPE_SENSE_MASK | IRQ_NOPROBE | IRQ_NOREQUEST | \
	 IRQ_NOAUTOEN | IRQ_MOVE_PCNTXT | IRQ_LEVEL | IRQ_NO_BALANCING | \
	 IRQ_PER_CPU | IRQ_NESTED_THREAD | IRQ_NOTHREAD | IRQ_PER_CPU_DEVID | \
	 IRQ_IS_POLLED | IRQ_DISABLE_UNLAZY)

/* irq_desc->status_use_accessors */
enum {
	_IRQ_DEFAULT_INIT_FLAGS	= 0,
	_IRQ_PER_CPU		= IRQ_PER_CPU,
	_IRQ_LEVEL		= IRQ_LEVEL,
	_IRQ_NOPROBE		= IRQ_NOPROBE,
	_IRQ_NOREQUEST		= IRQ_NOREQUEST,
	_IRQ_NOTHREAD		= IRQ_NOTHREAD,
	_IRQ_NOAUTOEN		= IRQ_NOAUTOEN,
	_IRQ_MOVE_PCNTXT	= IRQ_MOVE_PCNTXT,
	_IRQ_NO_BALANCING	= IRQ_NO_BALANCING,
	_IRQ_NESTED_THREAD	= IRQ_NESTED_THREAD,
	_IRQ_PER_CPU_DEVID	= IRQ_PER_CPU_DEVID,
	_IRQ_IS_POLLED		= IRQ_IS_POLLED,
	_IRQ_DISABLE_UNLAZY	= IRQ_DISABLE_UNLAZY,
	_IRQF_MODIFY_MASK	= IRQF_MODIFY_MASK,
};

/*
 * Return value for chip->irq_set_affinity()
 *
 * IRQ_SET_MASK_OK	- OK, core updates irq_common_data.affinity
 * IRQ_SET_MASK_NOCPY	- OK, chip did update irq_common_data.affinity
 * IRQ_SET_MASK_OK_DONE	- Same as IRQ_SET_MASK_OK for core. Special code to
 *			  support stacked irqchips, which indicates skipping
 *			  all descendent irqchips.
 */
enum {
	IRQ_SET_MASK_OK = 0,
	IRQ_SET_MASK_OK_NOCOPY,
	IRQ_SET_MASK_OK_DONE,
};

/*
 * Bit masks for desc->core_internal_state__do_not_mess_with_it
 *
 * IRQS_AUTODETECT		- autodetection in progress
 * IRQS_SPURIOUS_DISABLED	- was disabled due to spurious interrupt
 *				  detection
 * IRQS_POLL_INPROGRESS		- polling in progress
 * IRQS_ONESHOT			- irq is not unmasked in primary handler
 * IRQS_REPLAY			- irq is replayed
 * IRQS_WAITING			- irq is waiting
 * IRQS_PENDING			- irq is pending and replayed later
 * IRQS_SUSPENDED		- irq is suspended
 */
enum {
	IRQS_AUTODETECT		= 0x00000001,
	IRQS_SPURIOUS_DISABLED	= 0x00000002,
	IRQS_POLL_INPROGRESS	= 0x00000008,
	IRQS_ONESHOT		= 0x00000020,
	IRQS_REPLAY		= 0x00000040,
	IRQS_WAITING		= 0x00000080,
	IRQS_PENDING		= 0x00000200,
	IRQS_SUSPENDED		= 0x00000800,
};

/**
 * struct irq_desc - interrupt descriptor
 * @irq_common_data:	per irq and chip data passed down to chip functions
 * @name:		flow handler name for /proc/interrupts output
 * @handle_irq:		highlevel irq-events handler
 * @action:		the irq action chain
 * @istate:		core internal status information
 * @depth:		disable-depth, for nested irq_disable() calls
 * @irq_count:		stats field to detect stalled irqs
 * @last_unhandled:	aging timer for unhandled count
 * @irqs_unhandled:	stats field for spurious unhandled interrupts
 * @lock:		locking for SMP
 * @pending_mask:	pending rebalanced interrupts
 */
struct irq_desc {
	struct irq_common_data	irq_common_data;
	struct irq_data		irq_data;
	const char		*name;
	irq_flow_handler_t	handle_irq;
	struct irqaction	*action;
	unsigned int		status_use_accessors;
	unsigned int		istate;
	unsigned int		depth;
	unsigned int		irq_count;
	unsigned long		last_unhandled;
	unsigned int		irqs_unhandled;
	spinlock_t		lock;
	cpumask_var_t		pending_mask;
	unsigned long		threads_oneshot;
	atomic_t		threads_active;
};

extern struct irq_desc irq_desc[NR_IRQS];

static inline struct irq_desc *irq_to_desc(unsigned int irq)
{
	return (irq < NR_IRQS) ? irq_desc + irq : NULL;
}

static inline unsigned int irq_desc_get_irq(struct irq_desc *desc)
{
	return desc->irq_data.irq;
}

static inline struct irq_chip *irq_desc_get_chip(struct irq_desc *desc)
{
	return desc->irq_data.chip;
}

static inline void *irq_desc_get_chip_data(struct irq_desc *desc)
{
	return desc->irq_data.chip_data;
}

/**
 *	irq_set_chip_data - set irq chip data for an irq
 *	@irq:	Interrupt number
 *	@data:	Pointer to chip specific data
 *
 *	Set the hardware irq chip data for an irq
 */
static inline int irq_set_chip_data(unsigned int irq, void *data)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return -EINVAL;
	desc->irq_data.chip_data = data;
	return 0;
}

static inline struct irq_data *irq_get_irq_data(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	return desc ? &desc->irq_data : NULL;
}

static inline struct irq_data *irq_desc_get_irq_data(struct irq_desc *desc)
{
	return &desc->irq_data;
}

#define __irqd_to_state(d) (d)->common->state_use_accessors

static inline void irqd_clear(struct irq_data *d, unsigned int mask)
{
	__irqd_to_state(d) &= ~mask;
}

static inline void irqd_set(struct irq_data *d, unsigned int mask)
{
	__irqd_to_state(d) |= mask;
}

static inline u32 irqd_get_trigger_type(struct irq_data *d)
{
	return __irqd_to_state(d) & IRQD_TRIGGER_MASK;
}

static inline bool irqd_has_set(struct irq_data *d, unsigned int mask)
{
	return __irqd_to_state(d) & mask;
}

static inline bool irqd_irq_masked(struct irq_data *d)
{
	return __irqd_to_state(d) & IRQD_IRQ_MASKED;
}

static inline bool irqd_irq_disabled(struct irq_data *d)
{
	return __irqd_to_state(d) & IRQD_IRQ_DISABLED;
}

static inline bool irqd_is_setaffinity_pending(struct irq_data *d)
{
	return __irqd_to_state(d) & IRQD_SETAFFINITY_PENDING;
}

/*
 * Manipulation functions for irq_data.state
 */
static inline void irqd_set_move_pending(struct irq_data *d)
{
	__irqd_to_state(d) |= IRQD_SETAFFINITY_PENDING;
}

static inline void irqd_clr_move_pending(struct irq_data *d)
{
	__irqd_to_state(d) &= ~IRQD_SETAFFINITY_PENDING;
}

static inline bool irq_settings_disable_unlazy(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_DISABLE_UNLAZY;
}

static inline bool irqd_can_move_in_process_context(struct irq_data *d)
{
	return __irqd_to_state(d) & IRQD_MOVE_PCNTXT;
}

static inline void irq_settings_clr_disable_unlazy(struct irq_desc *desc)
{
	desc->status_use_accessors &= ~_IRQ_DISABLE_UNLAZY;
}

static inline void
irq_settings_set_trigger_mask(struct irq_desc *desc, u32 mask)
{
	desc->status_use_accessors &= ~IRQ_TYPE_SENSE_MASK;
	desc->status_use_accessors |= mask & IRQ_TYPE_SENSE_MASK;
}

static inline void irq_settings_clr_level(struct irq_desc *desc)
{
	desc->status_use_accessors &= ~_IRQ_LEVEL;
}

static inline void irq_settings_set_level(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_LEVEL;
}

static inline void irq_settings_set_noprobe(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_NOPROBE;
}

static inline void irq_settings_set_norequest(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_NOREQUEST;
}

static inline void irq_settings_set_nothread(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_NOTHREAD;
}

static inline bool irq_settings_can_probe(struct irq_desc *desc)
{
	return !(desc->status_use_accessors & _IRQ_NOPROBE);
}

static inline void irq_settings_clr_noprobe(struct irq_desc *desc)
{
	desc->status_use_accessors &= ~_IRQ_NOPROBE;
}

static inline bool irq_settings_can_move_pcntxt(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_MOVE_PCNTXT;
}

static inline bool irq_settings_can_autoenable(struct irq_desc *desc)
{
	return !(desc->status_use_accessors & _IRQ_NOAUTOEN);
}

static inline bool irq_settings_is_nested_thread(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_NESTED_THREAD;
}

static inline bool irq_settings_is_polled(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_IS_POLLED;
}

static inline bool irq_settings_is_level(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_LEVEL;
}

static inline void *irq_get_chip_data(unsigned int irq)
{
	struct irq_data *d = irq_get_irq_data(irq);
	return d ? d->chip_data : NULL;
}

static inline void
irq_settings_clr_and_set(struct irq_desc *desc, u32 clr, u32 set)
{
	desc->status_use_accessors &= ~(clr & _IRQF_MODIFY_MASK);
	desc->status_use_accessors |= (set & _IRQF_MODIFY_MASK);
}

static inline bool irq_settings_has_no_balance_set(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_NO_BALANCING;
}

static inline void irq_settings_set_per_cpu(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_PER_CPU;
}

static inline bool irq_settings_is_per_cpu(struct irq_desc *desc)
{
	return desc->status_use_accessors & _IRQ_PER_CPU;
}

static inline void irq_settings_set_no_balancing(struct irq_desc *desc)
{
	desc->status_use_accessors |= _IRQ_NO_BALANCING;
}

static inline u32 irq_settings_get_trigger_mask(struct irq_desc *desc)
{
	return desc->status_use_accessors & IRQ_TYPE_SENSE_MASK;
}

static inline bool irqd_can_balance(struct irq_data *d)
{
	return !(__irqd_to_state(d) & (IRQD_PER_CPU | IRQD_NO_BALANCING));
}

static inline struct irq_desc *irq_data_to_desc(struct irq_data *data)
{
	return container_of(data->common, struct irq_desc, irq_common_data);
}

static inline struct irq_chip *irq_data_get_irq_chip(struct irq_data *d)
{
	return d->chip;
}

static inline bool irqd_affinity_is_managed(struct irq_data *d)
{
	return __irqd_to_state(d) & IRQD_AFFINITY_MANAGED;
}

static inline int irq_common_data_get_node(struct irq_common_data *d)
{
#ifdef CONFIG_NUMA
	return d->node;
#else
	return 0;
#endif
}

static inline int irq_data_get_node(struct irq_data *d)
{
	return irq_common_data_get_node(d->common);
}

static inline int irq_desc_get_node(struct irq_desc *desc)
{
	return irq_common_data_get_node(&desc->irq_common_data);
}

/* Architecture may has a lower bound for dynamic IRQ allocation */
unsigned int arch_dynirq_lower_bound(unsigned int from);

/*
 * Allocate unique IRQ numbers from Lego
 */
int irq_alloc_descs(int irq, unsigned int from, unsigned int cnt, int node);

#define irq_alloc_desc(node)			\
	irq_alloc_descs(-1, 0, 1, node)

#define irq_alloc_desc_at(at, node)		\
	irq_alloc_descs(at, at, 1, node)

#define irq_alloc_desc_from(from, node)		\
	irq_alloc_descs(-1, from, 1, node)

#define irq_alloc_descs_from(from, cnt, node)	\
	irq_alloc_descs(-1, from, cnt, node)

/*
 * Fee unique IRQ numbers to Lego
 */
void irq_free_descs(unsigned int from, unsigned int cnt);

/*
 * For IRQ number lookup
 */
unsigned int irq_get_next_irq(unsigned int offset);

#define for_each_irq_desc(irq, desc)					\
	for (irq = 0, desc = irq_to_desc(irq); irq < NR_IRQS;		\
	     irq++, desc = irq_to_desc(irq))				\
		if (!desc)						\
			;						\
		else

#define for_each_active_irq(irq)			\
	for (irq = irq_get_next_irq(0); irq < NR_IRQS;	\
	     irq = irq_get_next_irq(irq + 1))

#define for_each_irq_nr(irq)                   \
       for (irq = 0; irq < NR_IRQS; irq++)

static inline bool irq_can_move_pcntxt(struct irq_data *data)
{
	return irqd_can_move_in_process_context(data);
}

static inline bool irq_move_pending(struct irq_data *data)
{
	return irqd_is_setaffinity_pending(data);
}

static inline void
irq_copy_pending(struct irq_desc *desc, const struct cpumask *mask)
{
	cpumask_copy(desc->pending_mask, mask);
}

static inline void
irq_get_pending(struct cpumask *mask, struct irq_desc *desc)
{
	cpumask_copy(mask, desc->pending_mask);
}

/* Internal implementation. Use the helpers below */
extern int __irq_set_affinity(unsigned int irq, const struct cpumask *cpumask,
			      bool force);

/**
 * irq_set_affinity - Set the irq affinity of a given irq
 * @irq:	Interrupt to set affinity
 * @cpumask:	cpumask
 *
 * Fails if cpumask does not contain an online CPU
 */
static inline int
irq_set_affinity(unsigned int irq, const struct cpumask *cpumask)
{
	return __irq_set_affinity(irq, cpumask, false);
}

int irq_can_set_affinity(unsigned int irq);

void irq_mark_irq(unsigned int irq);
void synchronize_irq(unsigned int irq);
void disable_irq(unsigned int irq);
void disable_irq_nosync(unsigned int irq);
void enable_irq(unsigned int irq);

int setup_irq(unsigned int irq, struct irqaction *new);

int __irq_set_trigger(struct irq_desc *desc, unsigned long flags);

void check_irq_resend(struct irq_desc *desc);

void irq_move_masked_irq(struct irq_data *data);
void irq_move_irq(struct irq_data *idata);

static inline struct msi_desc *irq_get_msi_desc(unsigned int irq)
{
       struct irq_data *d = irq_get_irq_data(irq);
       return d ? d->common->msi_desc : NULL;
}

static inline struct msi_desc *irq_data_get_msi_desc(struct irq_data *d)
{
	return d->common->msi_desc;
}

/* Test to see if a driver has successfully requested an irq */
static inline int irq_desc_has_action(struct irq_desc *desc)
{
	return desc->action != NULL;
}

static inline int irq_has_action(unsigned int irq)
{
	return irq_desc_has_action(irq_to_desc(irq));
}

#endif /* _LEGO_IRQDESC_H_ */

/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/kernel.h>
#include <lego/bitmap.h>
#include <lego/irqdesc.h>
#include <lego/cpumask.h>
#include <lego/nodemask.h>
#include <lego/spinlock.h>

cpumask_var_t irq_default_affinity;

int nr_irqs = NR_IRQS;

static DECLARE_BITMAP(allocated_irqs, NR_IRQS);
static DEFINE_SPINLOCK(allocated_irqs_lock);

void irq_mark_irq(unsigned int irq)
{
	spin_lock(&allocated_irqs_lock);
	bitmap_set(allocated_irqs, irq, 1);
	spin_unlock(&allocated_irqs_lock);
}

struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned = {
	[0 ... NR_IRQS-1] = {
		.handle_irq	= handle_bad_irq,
		.depth		= 1,
		.lock		= __SPIN_LOCK_UNLOCKED(irq_desc->lock),
	}
};

static void desc_smp_init(struct irq_desc *desc, int node,
			  const struct cpumask *affinity)
{
	if (!affinity)
		affinity = irq_default_affinity;
	cpumask_copy(&desc->irq_common_data.affinity, affinity);

#ifdef CONFIG_NUMA
	desc->irq_common_data.node = node;
#endif
}

static void desc_set_defaults(unsigned int irq, struct irq_desc *desc, int node,
			      const struct cpumask *affinity)
{
	desc->irq_common_data.handler_data = NULL;
	desc->irq_common_data.msi_desc = NULL;

	desc->irq_data.common = &desc->irq_common_data;
	desc->irq_data.irq = irq;
	desc->irq_data.chip = &no_irq_chip;
	desc->irq_data.chip_data = NULL;
	desc->handle_irq = handle_bad_irq;
	desc->depth = 1;
	desc->irq_count = 0;
	desc->irqs_unhandled = 0;
	desc->name = NULL;
	desc_smp_init(desc, node, affinity);
}

/* Dynamic interrupt handling */

static void free_desc(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	unsigned long flags;

	spin_lock_irqsave(&desc->lock, flags);
	desc_set_defaults(irq, desc, irq_desc_get_node(desc), NULL);
	spin_unlock_irqrestore(&desc->lock, flags);
}

/**
 * __irq_number_free
 * @from:	Free base
 * @cnt:	number of irqs to free
 */
void __irq_number_free(unsigned int from, unsigned int cnt)
{
	int i;

	if (from >= NR_IRQS || (from + cnt) > NR_IRQS)
		return;

	for (i = 0; i < cnt; i++)
		free_desc(from + i);

	spin_lock(&allocated_irqs_lock);
	bitmap_clear(allocated_irqs, from, cnt);
	spin_unlock(&allocated_irqs_lock);
}

/**
 * __irq_number_alloc
 * @irq:	Allocate for specific irq number if irq >= 0
 * @from:	Start the search from this irq number
 * @cnt:	Number of consecutive irqs to allocate.
 * @node:	Preferred node on which the irq descriptor should be allocated
 * @affinity:	Optional pointer to an affinity mask array of size @cnt which
 *		hints where the irq descriptors should be allocated and which
 *		default affinities to use
 *
 * Returns the first irq number or error code
 */
int  __irq_number_alloc(int irq, unsigned int from, unsigned int cnt, int node,
			const struct cpumask *affinity)
{
	int start, ret;

	if (!cnt)
		return -EINVAL;

	if (irq >= 0) {
		if (from > irq)
			return -EINVAL;
		from = irq;
	} else {
		/*
		 * For interrupts which are freely allocated the
		 * architecture can force a lower bound to the @from
		 * argument. x86 uses this to exclude the GSI space.
		 */
		from = arch_dynirq_lower_bound(from);
	}

	spin_lock(&allocated_irqs_lock);
	start = bitmap_find_next_zero_area(allocated_irqs, NR_IRQS,
					   from, cnt, 0);

	/* Already used by another device */
	if (irq >= 0 && start != irq) {
		ret = -EEXIST;
		goto err;
	}

	if (start + cnt > NR_IRQS) {
		ret = -ENOMEM;
		goto err;
	}

	bitmap_set(allocated_irqs, start, cnt);
	spin_unlock(&allocated_irqs_lock);

	return start;

err:
	spin_unlock(&allocated_irqs_lock);
	return ret;
}

/**
 * irq_get_next_irq - get next allocated irq number
 * @offset:	where to start the search
 *
 * Returns next irq number after offset or nr_irqs if none is found.
 */
unsigned int irq_get_next_irq(unsigned int offset)
{
	return find_next_bit(allocated_irqs, nr_irqs, offset);
}

static void __init init_irq_default_affinity(void)
{
	if (cpumask_empty(irq_default_affinity))
		cpumask_setall(irq_default_affinity);
}

void __init irq_init(void)
{
	int i, node = first_online_node;

	init_irq_default_affinity();

	pr_info("NR_IRQS:%d\n", NR_IRQS);

	for (i = 0; i < NR_IRQS; i++) {
		spin_lock_init(&irq_desc[i].lock);
		desc_set_defaults(i, &irq_desc[i], node, NULL);
	}

	arch_irq_init();
}

/*
 * Default primary interrupt handler for threaded interrupts. Is
 * assigned as primary handler when request_threaded_irq is called
 * with handler == NULL. Useful for oneshot interrupts.
 */
static irqreturn_t irq_default_primary_handler(int irq, void *dev_id)
{
	return IRQ_WAKE_THREAD;
}

/*
 * Primary handler for nested threaded interrupts. Should never be
 * called.
 */
static irqreturn_t irq_nested_primary_handler(int irq, void *dev_id)
{
	WARN(1, "Primary handler called for nested irq %d\n", irq);
	return IRQ_NONE;
}

/**
 *	synchronize_irq - wait for pending IRQ handlers (on other CPUs)
 *	@irq: interrupt number to wait for
 *
 *	This function waits for any pending IRQ handlers for this interrupt
 *	to complete before returning. If you use this function while
 *	holding a resource the IRQ handler may need you will deadlock.
 *
 *	This function may be called - with care - from IRQ context.
 */
void synchronize_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (desc) {
	}
}

void __disable_irq(struct irq_desc *desc)
{
	if (!desc->depth++)
		irq_disable(desc);
}

/**
 *	disable_irq_nosync - disable an irq without waiting
 *	@irq: Interrupt to disable
 *
 *	Disable the selected interrupt line.
 *	Disables and Enables are nested.
 *
 *	Unlike disable_irq(), this function does not ensure existing
 *	instances of the IRQ handler have completed before returning.
 *
 *	This function may be called from IRQ context.
 */
void disable_irq_nosync(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return;
	__disable_irq(desc);
}

/**
 *	disable_irq - disable an irq and wait for completion
 *	@irq: Interrupt to disable
 *
 *	Disable the selected interrupt line.
 *	Disables and Enables are nested.
 *
 *	This function waits for any pending IRQ handlers for this interrupt
 *	to complete before returning. If you use this function while
 *	holding a resource the IRQ handler may need you will deadlock.
 *
 *	This function may be called - with care - from IRQ context.
 */
void disable_irq(unsigned int irq)
{
	disable_irq_nosync(irq);
	synchronize_irq(irq);
}

int __irq_set_trigger(struct irq_desc *desc, unsigned long flags)
{
	struct irq_chip *chip = desc->irq_data.chip;
	int ret, unmask = 0;

	if (!chip || !chip->irq_set_type) {
		/*
		 * IRQF_TRIGGER_* but the PIC does not support multiple
		 * flow-types?
		 */
		pr_debug("No set_type function for IRQ %d (%s)\n",
			 irq_desc_get_irq(desc),
			 chip ? (chip->name ? : "unknown") : "unknown");
		return 0;
	}

	if (chip->flags & IRQCHIP_SET_TYPE_MASKED) {
		if (!irqd_irq_masked(&desc->irq_data))
			mask_irq(desc);
		if (!irqd_irq_disabled(&desc->irq_data))
			unmask = 1;
	}

	/* Mask all flags except trigger mode */
	flags &= IRQ_TYPE_SENSE_MASK;
	ret = chip->irq_set_type(&desc->irq_data, flags);

	switch (ret) {
	case IRQ_SET_MASK_OK:
	case IRQ_SET_MASK_OK_DONE:
		irqd_clear(&desc->irq_data, IRQD_TRIGGER_MASK);
		irqd_set(&desc->irq_data, flags);

	case IRQ_SET_MASK_OK_NOCOPY:
		flags = irqd_get_trigger_type(&desc->irq_data);
		irq_settings_set_trigger_mask(desc, flags);
		irqd_clear(&desc->irq_data, IRQD_LEVEL);
		irq_settings_clr_level(desc);
		if (flags & IRQ_TYPE_LEVEL_MASK) {
			irq_settings_set_level(desc);
			irqd_set(&desc->irq_data, IRQD_LEVEL);
		}

		ret = 0;
		break;
	default:
		pr_err("Setting trigger mode %lu for irq %u failed (%pF)\n",
		       flags, irq_desc_get_irq(desc), chip->irq_set_type);
	}
	if (unmask)
		unmask_irq(desc);
	return ret;
}

/*
 * IRQ resend
 *
 * Is called with interrupts disabled and desc->lock held.
 */
void check_irq_resend(struct irq_desc *desc)
{
}

static int
setup_irq_thread(struct irqaction *new, unsigned int irq, bool secondary)
{
	return 0;
}

static int irq_request_resources(struct irq_desc *desc)
{
	struct irq_data *d = &desc->irq_data;
	struct irq_chip *c = d->chip;

	return c->irq_request_resources ? c->irq_request_resources(d) : 0;
}

static bool __irq_can_set_affinity(struct irq_desc *desc)
{
	if (!desc || !irqd_can_balance(&desc->irq_data) ||
	    !desc->irq_data.chip || !desc->irq_data.chip->irq_set_affinity)
		return false;
	return true;
}

/**
 *	irq_can_set_affinity - Check if the affinity of a given irq can be set
 *	@irq:		Interrupt to check
 *
 */
int irq_can_set_affinity(unsigned int irq)
{
	return __irq_can_set_affinity(irq_to_desc(irq));
}

/**
 *	irq_set_thread_affinity - Notify irq threads to adjust affinity
 *	@desc:		irq descriptor which has affitnity changed
 *
 *	We just set IRQTF_AFFINITY and delegate the affinity setting
 *	to the interrupt thread itself. We can not call
 *	set_cpus_allowed_ptr() here as we hold desc->lock and this
 *	code can be called from hard interrupt context.
 */
void irq_set_thread_affinity(struct irq_desc *desc)
{
}

int irq_do_set_affinity(struct irq_data *data, const struct cpumask *mask,
			bool force)
{
	struct irq_desc *desc = irq_data_to_desc(data);
	struct irq_chip *chip = irq_data_get_irq_chip(data);
	int ret;

	ret = chip->irq_set_affinity(data, mask, force);
	switch (ret) {
	case IRQ_SET_MASK_OK:
	case IRQ_SET_MASK_OK_DONE:
		cpumask_copy(&desc->irq_common_data.affinity, mask);
	case IRQ_SET_MASK_OK_NOCOPY:
		irq_set_thread_affinity(desc);
		ret = 0;
	}

	return ret;
}

static int setup_affinity(struct irq_desc *desc, struct cpumask *mask)
{
	struct cpumask *set = irq_default_affinity;
	int node = irq_desc_get_node(desc);

	/* Excludes PER_CPU and NO_BALANCE interrupts */
	if (!__irq_can_set_affinity(desc))
		return 0;

	/*
	 * Preserve the managed affinity setting and an userspace affinity
	 * setup, but make sure that one of the targets is online.
	 */
	if (irqd_affinity_is_managed(&desc->irq_data) ||
	    irqd_has_set(&desc->irq_data, IRQD_AFFINITY_SET)) {
		if (cpumask_intersects(&desc->irq_common_data.affinity,
				       cpu_online_mask))
			set = &desc->irq_common_data.affinity;
		else
			irqd_clear(&desc->irq_data, IRQD_AFFINITY_SET);
	}

	cpumask_and(mask, cpu_online_mask, set);
	if (node != NUMA_NO_NODE) {
		const struct cpumask *nodemask = cpumask_of_node(node);

		/* make sure at least one of the cpus in nodemask is online */
		if (cpumask_intersects(mask, nodemask))
			cpumask_and(mask, mask, nodemask);
	}

	irq_do_set_affinity(&desc->irq_data, mask, false);
	return 0;
}

/*
 * Internal function to register an irqaction - typically used to
 * allocate special interrupts that are part of the architecture.
 */
static int __setup_irq(unsigned int irq, struct irq_desc *desc,
		       struct irqaction *new)
{
	struct irqaction *old, **old_ptr;
	unsigned long flags, thread_mask = 0;
	int ret, nested, shared = 0;
	cpumask_var_t mask;

	if (!desc)
		return -EINVAL;

	if (desc->irq_data.chip == &no_irq_chip)
		return -ENOSYS;

	new->irq = irq;

	/*
	 * If the trigger type is not specified by the caller,
	 * then use the default for this interrupt.
	 */
	if (!(new->flags & IRQF_TRIGGER_MASK))
		new->flags |= irqd_get_trigger_type(&desc->irq_data);

	/*
	 * Check whether the interrupt nests into another interrupt
	 * thread.
	 */
	nested = irq_settings_is_nested_thread(desc);
	if (nested) {
		if (!new->thread_fn) {
			ret = -EINVAL;
			goto out;
		}
		/*
		 * Replace the primary handler which was provided from
		 * the driver for non nested interrupt handling by the
		 * dummy function which warns when called.
		 */
		new->handler = irq_nested_primary_handler;
	}

	/*
	 * Create a handler thread when a thread function is supplied
	 * and the interrupt does not nest into another interrupt
	 * thread.
	 */
	if (new->thread_fn && !nested) {
		ret = setup_irq_thread(new, irq, false);
		if (ret)
			goto out;
		if (new->secondary) {
			ret = setup_irq_thread(new->secondary, irq, true);
			if (ret)
				goto out_thread;
		}
	}

	/*
	 * Drivers are often written to work w/o knowledge about the
	 * underlying irq chip implementation, so a request for a
	 * threaded irq without a primary hard irq context handler
	 * requires the ONESHOT flag to be set. Some irq chips like
	 * MSI based interrupts are per se one shot safe. Check the
	 * chip flags, so we can avoid the unmask dance at the end of
	 * the threaded handler for those.
	 */
	if (desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)
		new->flags &= ~IRQF_ONESHOT;

	spin_lock_irqsave(&desc->lock, flags);
	old_ptr = &desc->action;
	old = *old_ptr;
	if (old) {
		/*
		 * Can't share interrupts unless both agree to and are
		 * the same type (level, edge, polarity). So both flag
		 * fields must have IRQF_SHARED set and the bits which
		 * set the trigger type must match. Also all must
		 * agree on ONESHOT.
		 */
		if (!((old->flags & new->flags) & IRQF_SHARED) ||
		    ((old->flags ^ new->flags) & IRQF_TRIGGER_MASK) ||
		    ((old->flags ^ new->flags) & IRQF_ONESHOT))
			goto mismatch;

		/* All handlers must agree on per-cpuness */
		if ((old->flags & IRQF_PERCPU) !=
		    (new->flags & IRQF_PERCPU))
			goto mismatch;

		/* add new interrupt at end of irq queue */
		do {
			/*
			 * Or all existing action->thread_mask bits,
			 * so we can find the next zero bit for this
			 * new action.
			 */
			thread_mask |= old->thread_mask;
			old_ptr = &old->next;
			old = *old_ptr;
		} while (old);
		shared = 1;
	}

	/*
	 * Setup the thread mask for this irqaction for ONESHOT. For
	 * !ONESHOT irqs the thread mask is 0 so we can avoid a
	 * conditional in irq_wake_thread().
	 */
	if (new->flags & IRQF_ONESHOT) {
		/*
		 * Unlikely to have 32 resp 64 irqs sharing one line,
		 * but who knows.
		 */
		if (thread_mask == ~0UL) {
			ret = -EBUSY;
			goto out_unlock;
		}
		/*
		 * The thread_mask for the action is or'ed to
		 * desc->thread_active to indicate that the
		 * IRQF_ONESHOT thread handler has been woken, but not
		 * yet finished. The bit is cleared when a thread
		 * completes. When all threads of a shared interrupt
		 * line have completed desc->threads_active becomes
		 * zero and the interrupt line is unmasked. See
		 * handle.c:irq_wake_thread() for further information.
		 *
		 * If no thread is woken by primary (hard irq context)
		 * interrupt handlers, then desc->threads_active is
		 * also checked for zero to unmask the irq line in the
		 * affected hard irq flow handlers
		 * (handle_[fasteoi|level]_irq).
		 *
		 * The new action gets the first zero bit of
		 * thread_mask assigned. See the loop above which or's
		 * all existing action->thread_mask bits.
		 */
		new->thread_mask = 1 << ffz(thread_mask);

	} else if (new->handler == irq_default_primary_handler &&
		   !(desc->irq_data.chip->flags & IRQCHIP_ONESHOT_SAFE)) {
		/*
		 * The interrupt was requested with handler = NULL, so
		 * we use the default primary handler for it. But it
		 * does not have the oneshot flag set. In combination
		 * with level interrupts this is deadly, because the
		 * default primary handler just wakes the thread, then
		 * the irq lines is reenabled, but the device still
		 * has the level irq asserted. Rinse and repeat....
		 *
		 * While this works for edge type interrupts, we play
		 * it safe and reject unconditionally because we can't
		 * say for sure which type this interrupt really
		 * has. The type flags are unreliable as the
		 * underlying chip implementation can override them.
		 */
		pr_err("Threaded irq requested with handler=NULL and !ONESHOT for irq %d\n",
		       irq);
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!shared) {
		ret = irq_request_resources(desc);
		if (ret) {
			pr_err("Failed to request resources for %s (irq %d) on irqchip %s\n",
			       new->name, irq, desc->irq_data.chip->name);
			goto out_unlock;
		}

		/* Setup the type (level, edge polarity) if configured: */
		if (new->flags & IRQF_TRIGGER_MASK) {
			ret = __irq_set_trigger(desc,
						new->flags & IRQF_TRIGGER_MASK);

			if (ret)
				goto out_unlock;
		}

		desc->istate &= ~(IRQS_AUTODETECT | IRQS_SPURIOUS_DISABLED | \
				  IRQS_ONESHOT | IRQS_WAITING);
		irqd_clear(&desc->irq_data, IRQD_IRQ_INPROGRESS);

		if (new->flags & IRQF_PERCPU) {
			irqd_set(&desc->irq_data, IRQD_PER_CPU);
			irq_settings_set_per_cpu(desc);
		}

		if (new->flags & IRQF_ONESHOT)
			desc->istate |= IRQS_ONESHOT;

		if (irq_settings_can_autoenable(desc))
			irq_startup(desc, true);
		else
			/* Undo nested disables: */
			desc->depth = 1;

		/* Exclude IRQ from balancing if requested */
		if (new->flags & IRQF_NOBALANCING) {
			irq_settings_set_no_balancing(desc);
			irqd_set(&desc->irq_data, IRQD_NO_BALANCING);
		}

		/* Set default affinity mask once everything is setup */
		setup_affinity(desc, mask);

	} else if (new->flags & IRQF_TRIGGER_MASK) {
		unsigned int nmsk = new->flags & IRQF_TRIGGER_MASK;
		unsigned int omsk = irqd_get_trigger_type(&desc->irq_data);

		if (nmsk != omsk)
			/* hope the handler works with current  trigger mode */
			pr_warn("irq %d uses trigger mode %u; requested %u\n",
				irq, omsk, nmsk);
	}

	*old_ptr = new;

	/* Reset broken irq detection when installing new handler */
	desc->irq_count = 0;
	desc->irqs_unhandled = 0;

	/*
	 * Check whether we disabled the irq via the spurious handler
	 * before. Reenable it and give it another chance.
	 */
	if (shared && (desc->istate & IRQS_SPURIOUS_DISABLED)) {
		desc->istate &= ~IRQS_SPURIOUS_DISABLED;
		__enable_irq(desc);
	}

	spin_unlock_irqrestore(&desc->lock, flags);

	return 0;

mismatch:
	if (!(new->flags & IRQF_PROBE_SHARED)) {
		pr_err("Flags mismatch irq %d. %08x (%s) vs. %08x (%s)\n",
		       irq, new->flags, new->name, old->flags, old->name);
#ifdef CONFIG_DEBUG_SHIRQ
		dump_stack();
#endif
	}
	ret = -EBUSY;

out_unlock:
	spin_unlock_irqrestore(&desc->lock, flags);

out_thread:
out:
	return ret;
}

/**
 *	setup_irq - setup an interrupt
 *	@irq: Interrupt line to setup
 *	@act: irqaction for the interrupt
 *
 * Used to statically setup interrupts in the early boot process.
 */
int setup_irq(unsigned int irq, struct irqaction *act)
{
	int retval;
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return -EINVAL;

	retval = __setup_irq(irq, desc, act);
	return retval;
}

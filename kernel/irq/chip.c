/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irqdesc.h>
#include <lego/irqchip.h>
#include <lego/irqdomain.h>

static irqreturn_t bad_chained_irq(int irq, void *dev_id)
{
	WARN_ONCE(1, "Chained irq %d should not call an action\n", irq);
	return IRQ_NONE;
}

/*
 * Chained handlers should never call action on their IRQ. This default
 * action will emit warning if such thing happens.
 */
struct irqaction chained_action = {
	.handler = bad_chained_irq,
};

static void irq_state_clr_disabled(struct irq_desc *desc)
{
	irqd_clear(&desc->irq_data, IRQD_IRQ_DISABLED);
}

static void irq_state_set_disabled(struct irq_desc *desc)
{
	irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
}

static void irq_state_clr_masked(struct irq_desc *desc)
{
	irqd_clear(&desc->irq_data, IRQD_IRQ_MASKED);
}

static void irq_state_set_masked(struct irq_desc *desc)
{
	irqd_set(&desc->irq_data, IRQD_IRQ_MASKED);
}

void mask_ack_irq(struct irq_desc *desc)
{
	if (desc->irq_data.chip->irq_mask_ack)
		desc->irq_data.chip->irq_mask_ack(&desc->irq_data);
	else {
		desc->irq_data.chip->irq_mask(&desc->irq_data);
		if (desc->irq_data.chip->irq_ack)
			desc->irq_data.chip->irq_ack(&desc->irq_data);
	}
	irq_state_set_masked(desc);
}

/**
 *	irq_set_chip - set the irq chip for an irq
 *	@irq:	irq number
 *	@chip:	pointer to irq chip description structure
 */
int irq_set_chip(unsigned int irq, struct irq_chip *chip)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return -EINVAL;

	if (!chip)
		chip = &no_irq_chip;

	desc->irq_data.chip = chip;

	/*
	 * For !CONFIG_SPARSE_IRQ make the irq show up in
	 * allocated_irqs.
	 */
	irq_mark_irq(irq);

	return 0;
}

static void
__irq_do_set_handler(struct irq_desc *desc, irq_flow_handler_t handle,
		     int is_chained, const char *name)
{
	if (!handle) {
		handle = handle_bad_irq;
	} else {
		struct irq_data *irq_data = &desc->irq_data;
		if (WARN_ON(!irq_data || irq_data->chip == &no_irq_chip))
			return;
	}

	/* Uninstall? */
	if (handle == handle_bad_irq) {
		if (desc->irq_data.chip != &no_irq_chip)
			mask_ack_irq(desc);
		irq_state_set_disabled(desc);
		if (is_chained)
			desc->action = NULL;
		desc->depth = 1;
	}
	desc->handle_irq = handle;
	desc->name = name;

	if (handle != handle_bad_irq && is_chained) {
		unsigned int type = irqd_get_trigger_type(&desc->irq_data);

		/*
		 * We're about to start this interrupt immediately,
		 * hence the need to set the trigger configuration.
		 * But the .set_type callback may have overridden the
		 * flow handler, ignoring that we're dealing with a
		 * chained interrupt. Reset it immediately because we
		 * do know better.
		 */
		if (type != IRQ_TYPE_NONE) {
			__irq_set_trigger(desc, type);
			desc->handle_irq = handle;
		}

		irq_settings_set_noprobe(desc);
		irq_settings_set_norequest(desc);
		irq_settings_set_nothread(desc);
		desc->action = &chained_action;
		irq_startup(desc, true);
	}
}

void __irq_set_handler(unsigned int irq, irq_flow_handler_t handle,
		       int is_chained, const char *name)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return;
	__irq_do_set_handler(desc, handle, is_chained, name);
}

void irq_set_chip_and_handler_name(unsigned int irq, struct irq_chip *chip,
			      irq_flow_handler_t handle, const char *name)
{
	irq_set_chip(irq, chip);
	__irq_set_handler(irq, handle, 0, name);
}

/**
 *	irq_set_msi_desc_off - set MSI descriptor data for an irq at offset
 *	@irq_base:	Interrupt number base
 *	@irq_offset:	Interrupt number offset
 *	@entry:		Pointer to MSI descriptor data
 *
 *	Set the MSI descriptor entry for an irq at offset
 */
int irq_set_msi_desc_off(unsigned int irq_base, unsigned int irq_offset,
			 struct msi_desc *entry)
{
	struct irq_desc *desc = irq_to_desc(irq_base + irq_offset);

	if (!desc)
		return -EINVAL;
	desc->irq_common_data.msi_desc = entry;
	if (entry && !irq_offset)
		entry->irq = irq_base;
	return 0;
}

/**
 *	irq_set_msi_desc - set MSI descriptor data for an irq
 *	@irq:	Interrupt number
 *	@entry:	Pointer to MSI descriptor data
 *
 *	Set the MSI descriptor entry for an irq
 */
int irq_set_msi_desc(unsigned int irq, struct msi_desc *entry)
{
	return irq_set_msi_desc_off(irq, 0, entry);
}

/**
 *	irq_set_handler_data - set irq handler data for an irq
 *	@irq:	Interrupt number
 *	@data:	Pointer to interrupt specific data
 *
 *	Set the hardware irq controller data for an irq
 */
int irq_set_handler_data(unsigned int irq, void *data)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return -EINVAL;
	desc->irq_common_data.handler_data = data;
	return 0;
}

void __enable_irq(struct irq_desc *desc)
{
	switch (desc->depth) {
	case 0:
 err_out:
		WARN(1, KERN_WARNING "Unbalanced enable for IRQ %d\n",
		     irq_desc_get_irq(desc));
		break;
	case 1: {
		if (desc->istate & IRQS_SUSPENDED)
			goto err_out;
		/* Prevent probing on this irq: */
		irq_settings_set_noprobe(desc);
		irq_enable(desc);
		check_irq_resend(desc);
		/* fall-through */
	}
	default:
		desc->depth--;
	}
}

/**
 *	enable_irq - enable handling of an irq
 *	@irq: Interrupt to enable
 *
 *	Undoes the effect of one call to disable_irq().  If this
 *	matches the last disable, processing of interrupts on this
 *	IRQ line is re-enabled.
 *
 *	This function may be called from IRQ context only when
 *	desc->irq_data.chip->bus_lock and desc->chip->bus_sync_unlock are NULL !
 */
void enable_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return;
	if (WARN(!desc->irq_data.chip,
		 "enable_irq before setup/request_irq: irq %u\n", irq))
		return;

	__enable_irq(desc);
}

void mask_irq(struct irq_desc *desc)
{
	if (desc->irq_data.chip->irq_mask) {
		desc->irq_data.chip->irq_mask(&desc->irq_data);
		irq_state_set_masked(desc);
	}
}

void unmask_irq(struct irq_desc *desc)
{
	if (desc->irq_data.chip->irq_unmask) {
		desc->irq_data.chip->irq_unmask(&desc->irq_data);
		irq_state_clr_masked(desc);
	}
}

/**
 * irq_disable - Mark interrupt disabled
 * @desc:	irq descriptor which should be disabled
 *
 * If the chip does not implement the irq_disable callback, we
 * use a lazy disable approach. That means we mark the interrupt
 * disabled, but leave the hardware unmasked. That's an
 * optimization because we avoid the hardware access for the
 * common case where no interrupt happens after we marked it
 * disabled. If an interrupt happens, then the interrupt flow
 * handler masks the line at the hardware level and marks it
 * pending.
 *
 * If the interrupt chip does not implement the irq_disable callback,
 * a driver can disable the lazy approach for a particular irq line by
 * calling 'irq_set_status_flags(irq, IRQ_DISABLE_UNLAZY)'. This can
 * be used for devices which cannot disable the interrupt at the
 * device level under certain circumstances and have to use
 * disable_irq[_nosync] instead.
 */
void irq_disable(struct irq_desc *desc)
{
	irq_state_set_disabled(desc);
	if (desc->irq_data.chip->irq_disable) {
		desc->irq_data.chip->irq_disable(&desc->irq_data);
		irq_state_set_masked(desc);
	} else if (irq_settings_disable_unlazy(desc)) {
		mask_irq(desc);
	}
}

void irq_enable(struct irq_desc *desc)
{
	irq_state_clr_disabled(desc);
	if (desc->irq_data.chip->irq_enable)
		desc->irq_data.chip->irq_enable(&desc->irq_data);
	else
		desc->irq_data.chip->irq_unmask(&desc->irq_data);
	irq_state_clr_masked(desc);
}

int irq_startup(struct irq_desc *desc, bool resend)
{
	int ret = 0;

	irq_state_clr_disabled(desc);
	desc->depth = 0;

	irq_domain_activate_irq(&desc->irq_data);
	if (desc->irq_data.chip->irq_startup) {
		ret = desc->irq_data.chip->irq_startup(&desc->irq_data);
		irq_state_clr_masked(desc);
	} else {
		irq_enable(desc);
	}
	if (resend)
		check_irq_resend(desc);
	return ret;
}

void irq_shutdown(struct irq_desc *desc)
{
	irq_state_set_disabled(desc);
	desc->depth = 1;
	if (desc->irq_data.chip->irq_shutdown)
		desc->irq_data.chip->irq_shutdown(&desc->irq_data);
	else if (desc->irq_data.chip->irq_disable)
		desc->irq_data.chip->irq_disable(&desc->irq_data);
	else
		desc->irq_data.chip->irq_mask(&desc->irq_data);
	irq_state_set_masked(desc);
}

void irq_modify_status(unsigned int irq, unsigned long clr, unsigned long set)
{
	unsigned long flags;
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return;

	spin_lock_irqsave(&desc->lock, flags);	
	irq_settings_clr_and_set(desc, clr, set);

	irqd_clear(&desc->irq_data, IRQD_NO_BALANCING | IRQD_PER_CPU |
		   IRQD_TRIGGER_MASK | IRQD_LEVEL | IRQD_MOVE_PCNTXT);
	if (irq_settings_has_no_balance_set(desc))
		irqd_set(&desc->irq_data, IRQD_NO_BALANCING);
	if (irq_settings_is_per_cpu(desc))
		irqd_set(&desc->irq_data, IRQD_PER_CPU);
	if (irq_settings_can_move_pcntxt(desc))
		irqd_set(&desc->irq_data, IRQD_MOVE_PCNTXT);
	if (irq_settings_is_level(desc))
		irqd_set(&desc->irq_data, IRQD_LEVEL);

	irqd_set(&desc->irq_data, irq_settings_get_trigger_mask(desc));

	spin_unlock_irqrestore(&desc->lock, flags);
}

/**
 * irq_chip_ack_parent - Acknowledge the parent interrupt
 * @data:	Pointer to interrupt specific data
 */
void irq_chip_ack_parent(struct irq_data *data)
{
	data = data->parent_data;
	data->chip->irq_ack(data);
}

/**
 * irq_chip_retrigger_hierarchy - Retrigger an interrupt in hardware
 * @data:	Pointer to interrupt specific data
 *
 * Iterate through the domain hierarchy of the interrupt and check
 * whether a hw retrigger function exists. If yes, invoke it.
 */
int irq_chip_retrigger_hierarchy(struct irq_data *data)
{
	for (data = data->parent_data; data; data = data->parent_data)
		if (data->chip && data->chip->irq_retrigger)
			return data->chip->irq_retrigger(data);

	return 0;
}

/**
 * irq_chip_compose_msi_msg - Componse msi message for a irq chip
 * @data:	Pointer to interrupt specific data
 * @msg:	Pointer to the MSI message
 *
 * For hierarchical domains we find the first chip in the hierarchy
 * which implements the irq_compose_msi_msg callback. For non
 * hierarchical we use the top level chip.
 */
int irq_chip_compose_msi_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct irq_data *pos = NULL;

	for (; data; data = data->parent_data)
		if (data->chip && data->chip->irq_compose_msi_msg)
			pos = data;
	if (!pos)
		return -ENOSYS;

	pos->chip->irq_compose_msi_msg(pos, msg);

	return 0;
}

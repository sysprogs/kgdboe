#include "irqsync.h"
#include <linux/slab.h>

/*
	This file contains the code that disables the IRQ used by the network card for the duration of using it from kgdb via the netpoll API.
	This is needed on the multi-core systems because the network driver may try to disable/enable the IRQ around the netpoll call and actually 
	enabling it would need some internal locks of the interrupt controller driver that may be held by other cores. As IRQ disabling in
	Linux is recursive, once we disable the IRQ, enabling and disabling it from the network card driver will just keep it disabled without
	invoking any dangerous code from the APIC.

	Note that we cannot enable the IRQ immediately when done talking to the driver as the other cores (potentially holding APIC locks) are
	still active. For that reason we use a timer to enable the IRQ later once the normal execution is resumed.
*/

static void irqsync_timer_func(unsigned long ctx);
#define IRQSYNC_TIMER_PERIOD (HZ / 100)

struct irqsync_manager *irqsync_create(void)
{
	struct irqsync_manager* result = (struct irqsync_manager *)kmalloc(sizeof(struct irqsync_manager), GFP_KERNEL);
	if (!result)
		return NULL;
	memset(result, 0, sizeof(*result));
	spin_lock_init(&result->lock);
	init_timer(&result->timer);
	result->timer.function = irqsync_timer_func;
	result->timer.data = (unsigned long)result;
	INIT_LIST_HEAD(&result->irqs);
	mod_timer(&result->timer, jiffies + IRQSYNC_TIMER_PERIOD);
	return result;
}

static void irqsync_enable_all_irqs_locked(struct irqsync_manager *mgr);

void irqsync_free(struct irqsync_manager *mgr)
{
	struct managed_irq *irq, *tmp;

	BUG_ON(!mgr);
	del_timer(&mgr->timer);
	spin_lock(&mgr->lock);
	if (mgr->irqs_disabled)
		irqsync_enable_all_irqs_locked(mgr);
	spin_unlock(&mgr->lock);

	list_for_each_entry_safe(irq, tmp, &mgr->irqs, list)
	{
		kfree(irq);
	}

	kfree(mgr);
}

bool irqsync_add_managed_irq(struct irqsync_manager *mgr, unsigned number, struct irq_desc *irq)
{
	struct managed_irq* result = (struct managed_irq *)kmalloc(sizeof(struct managed_irq), GFP_KERNEL);
	if (!result)
		return false;

	result->irq = irq;
	result->number = number;

	spin_lock(&mgr->lock);
	list_add_tail(&result->list, &mgr->irqs);
	spin_unlock(&mgr->lock);
	return true;
}

void irqsync_suspend_irqs(struct irqsync_manager *mgr)
{
	struct managed_irq *irq;
	BUG_ON(!mgr);
	BUG_ON(mgr->suspend_active);
	spin_lock(&mgr->lock);
	BUG_ON(mgr->suspend_active);
	mgr->suspend_active = true;
	if (!mgr->irqs_disabled)
	{
		list_for_each_entry(irq, &mgr->irqs, list)
		{
			disable_irq(irq->number);
		}
		mgr->irqs_disabled = true;
	}
}

void irqsync_resume_irqs(struct irqsync_manager *mgr)
{
	BUG_ON(!mgr);
	BUG_ON(!mgr->suspend_active);
	mgr->suspend_active = false;
	spin_unlock(&mgr->lock);
}

static void irqsync_timer_func(unsigned long ctx)
{
	struct irqsync_manager *mgr = (struct irqsync_manager *)ctx;
	BUG_ON(!mgr);
	if (spin_trylock(&mgr->lock))
	{
		if (mgr->irqs_disabled)
			irqsync_enable_all_irqs_locked(mgr);
		spin_unlock(&mgr->lock);
	}

	mod_timer(&mgr->timer, jiffies + IRQSYNC_TIMER_PERIOD);
}

static void irqsync_enable_all_irqs_locked(struct irqsync_manager *mgr)
{
	struct managed_irq *irq;

	BUG_ON(!mgr);
	BUG_ON(!mgr->irqs_disabled);
	mgr->irqs_disabled = false;

	list_for_each_entry(irq, &mgr->irqs, list)
	{
		enable_irq(irq->number);
	}
}

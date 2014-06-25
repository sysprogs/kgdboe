#include "irqsync.h"
#include <linux/slab.h>

static void irqsync_timer_func(unsigned long ctx);
#define IRQSYNC_TIMER_PERIOD (HZ / 100)

struct irqsync_manager *irqsync_create()
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
	BUG_ON(!mgr);
	del_timer(&mgr->timer);
	spin_lock(&mgr->lock);
	if (mgr->irqs_disabled)
		irqsync_enable_all_irqs_locked(mgr);
	spin_unlock(&mgr->lock);
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

void irqsync_clear_managed_irq_list(struct irqsync_manager *mgr)
{
	struct managed_irq *irq, *tmp;
	spin_lock(&mgr->lock);
	if (mgr->irqs_disabled)
		irqsync_enable_all_irqs_locked(mgr);

	list_for_each_entry_safe(irq, tmp, &mgr->irqs, list)
	{
		kfree(irq);
	}

	spin_unlock(&mgr->lock);
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

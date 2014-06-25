#pragma once
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/list.h>

struct managed_irq
{
	struct list_head list;
	unsigned number;
	struct irq_desc *irq;
};

struct irqsync_manager
{
	struct list_head irqs;
	struct timer_list timer;
	spinlock_t lock;
	bool irqs_disabled;
	bool suspend_active;
};

struct irqsync_manager *irqsync_create(void);
void irqsync_free(struct irqsync_manager *mgr);

bool irqsync_add_managed_irq(struct irqsync_manager *mgr, unsigned number, struct irq_desc *irq);

void irqsync_suspend_irqs(struct irqsync_manager *mgr);
void irqsync_resume_irqs(struct irqsync_manager *mgr);

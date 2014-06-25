#pragma once
#include <linux/module.h>
#include <linux/spinlock.h>

struct timer_hook
{
	spinlock_t lock;
	struct module *module;
};

struct timer_hook *timerhook_create(struct module *moduleToHook);
void timerhook_free(struct timer_hook *hook);

static inline spinlock_t *timerhook_get_spinlock(struct timer_hook *hook)
{
	BUG_ON(!hook);
	return &hook->lock;
}
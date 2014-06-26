#include "timerhook.h"
#include <linux/atomic.h>
#include <linux/netdevice.h>
#include <trace/events/timer.h>
#include "tracewrapper.h"

/*
	This file provides the functionality allows putting a spinlock around timer functions in a given module.
	It is used to ensure that no timer registered by the network driver is running on another CPU when kgdb
	is stopping all CPUs except the one with an exception.

	Some network drivers (like pcnet32) define timers that can take internal spinlocks required to access the device.
	If a core hits an exception while another core is executing such a timer (and owns the spinlock), kgdb will deadlock
	as it won't be able to access the network card. Putting a spinlock around those timers and taking it before
	disabling other cores solves this problem.

	Note that this code relies on assumption that the timer function is defined in the same module that registered
	the network device. If this assumption is broken, this code won't be able to catch the timer!
*/

static atomic_t timer_hook_installed;

static notrace void hook_timer_entry(void *v, struct timer_list *timer)
{
	if (within_module_core((unsigned long)timer->function, ((struct timer_hook *)v)->module))
		spin_lock(&((struct timer_hook *)v)->lock);
}

static notrace void hook_timer_exit(void *v, struct timer_list *timer)
{
	if (within_module_core((unsigned long)timer->function, ((struct timer_hook *)v)->module))
		spin_unlock(&((struct timer_hook *)v)->lock);
}

struct timer_hook *timerhook_create(struct module *moduleToHook)
{
	struct timer_hook *hook;
	BUG_ON(!moduleToHook);

	hook = (struct timer_hook *)kmalloc(sizeof(struct timer_hook), GFP_KERNEL);
	if (!hook)
		return NULL;

	spin_lock_init(&hook->lock);
	hook->module = moduleToHook;

	if (atomic_inc_return(&timer_hook_installed) == 1)
	{
		register_tracepoint_wrapper(timer_expire_entry, hook_timer_entry, hook);
		register_tracepoint_wrapper(timer_expire_exit, hook_timer_exit, hook);
	}

	return hook;
}

void timerhook_free(struct timer_hook *hook)
{
	if (!hook)
		return;

	if (!atomic_dec_return(&timer_hook_installed))
	{
		unregister_tracepoint_wrapper(timer_expire_entry, hook_timer_entry, hook);
		unregister_tracepoint_wrapper(timer_expire_exit, hook_timer_exit, hook);
	}

	kfree(hook);
}

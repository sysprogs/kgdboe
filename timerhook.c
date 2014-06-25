#include "timerhook.h"
#include <linux/atomic.h>
#include <linux/netdevice.h>
#include <trace/events/timer.h>
#include "tracewrapper.h"

static atomic_t timer_hook_installed;

static notrace void hook_timer_entry(void *v, struct timer_list *timer)
{
	if (within_module_core(timer->function, ((struct timer_hook *)v)->module))
		spin_lock(&((struct timer_hook *)v)->lock);
}

static notrace void hook_timer_exit(void *v, struct timer_list *timer)
{
	if (within_module_core(timer->function, ((struct timer_hook *)v)->module))
		spin_unlock(&((struct timer_hook *)v)->lock);
}

struct timer_hook *timerhook_create(struct module *moduleToHook)
{
	BUG_ON(!moduleToHook);

	struct timer_hook *hook = (struct timer_hook *)kmalloc(sizeof(struct timer_hook), GFP_KERNEL);
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

#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#include "nethook.h"
#include "irqsync.h"
#include "spinhook.h"
#include "timerhook.h"
#include <linux/preempt.h>
#include <linux/seqlock.h>
#include <linux/version.h>

/*
	This file is the central place for hooking a network card driver to ensure that no other cores are executing
	any of its code. Note that this is only needed when debugging a system with multiple logical CPUs (and they were
	not disabled dynamically when starting debugging).

	We ensure that the network driver invoked by the current core won't need any resources owned by the other cores
	(that are stopped by kgdb) using the following techniques:
		1. Disabling the network card IRQ. This ensures that a driver calling enable_irq() won't hang waiting for an internal APIC lock.
		2. Putting a spinlock around NAPI functions provided by the driver that may take some internal locks (currently ndo_get_stats).
		3. Putting a spinlock around the timers registered by the network card driver.
		4. Ensuring that no other core owns the jiffies_lock (that is used by some network-related code to manage timestamps)
		5. Setting a SOFTIRQ_MASK bit in preemption mask so that the network driver code will think we're handling an interrupt and
		   won't try anything that requires locks held by other cores (like waking up softirqd).

	The combination of techniques used here is fairly reliable (tested on 20K+ breakpoint iterations), but may be insufficient for
	some network card drivers that were not explicitly tested with it. Use with caution and prefer the forced single-CPU mode unless
	you absolutely need SMP during debugging.
*/

struct nethook
{
	bool initialized;
	int saved_preempt;
	struct irqsync_manager *irqsync;
	spinlock_t netdev_api_lock;
	struct spinlock_hook_manager *spinhook;
	struct timer_hook *timerhook;
	struct net_device *hooked_device;
};

static struct nethook nethook;

#define DECLARE_NET_API_HOOK1(name, return_type, type1, arg1) \
	return_type(*original_ ## name)(type1 arg1);	\
	\
	return_type name ## _hook(type1 arg1)	\
{	\
	return_type result;	\
	spin_lock(&nethook.netdev_api_lock);	\
	result = original_ ## name(arg1);	\
	spin_unlock(&nethook.netdev_api_lock);	\
	return result;	\
}

#define DECLARE_NET_API_HOOK2(name, return_type, type1, arg1, type2, arg2) \
	return_type(*original_ ## name)(type1 arg1, type2 arg2);	\
	\
	return_type name ## _hook(type1 arg1, type2 arg2)	\
{	\
	return_type result;	\
	spin_lock(&nethook.netdev_api_lock);	\
	result = original_ ## name(arg1, arg2);	\
	spin_unlock(&nethook.netdev_api_lock);	\
	return result;	\
}

DECLARE_NET_API_HOOK2(ndo_get_stats64, struct rtnl_link_stats64*, struct net_device *, dev, struct rtnl_link_stats64 *, storage)
DECLARE_NET_API_HOOK1(ndo_get_stats, struct net_device_stats*, struct net_device *, dev)

bool nethook_initialize(struct net_device *dev)
{
	struct module *owner_module;
	seqlock_t *jiffies_lock = (seqlock_t *)kallsyms_lookup_name("jiffies_lock");
	int err;
	int i;
	struct napi_struct *napi;

	if (nethook.initialized)
		return false;
	memset(&nethook, 0, sizeof(nethook));

	BUG_ON(!dev);
	printk(KERN_INFO "kgdboe: Trying to synchronize calls to %s between multiple CPU cores...\n", dev->name);
	if (!dev->netdev_ops || !dev->netdev_ops->ndo_start_xmit)
	{
		printk(KERN_ERR "kgdboe: ndo_start_xmit not defined. Cannot determine which module owns %s\n", dev->name);
		return false;
	}

	owner_module = __module_address((unsigned long)dev->netdev_ops->ndo_start_xmit);
	if (!owner_module)
	{
		printk(KERN_ERR "kgdboe: cannot find the module owning %s: 0x%p does not belong to any module.\n", dev->name, dev->netdev_ops->ndo_start_xmit);
		return false;
	}

	printk("kgdboe: found owner module for %s: %s\n", dev->name, owner_module->name);
	
	nethook.initialized = true;
	nethook.spinhook = spinlock_hook_manager_create();
	if (!nethook.spinhook)
	{
		printk(KERN_ERR "kgdboe: cannot create spinlock hook manager. Aborting.\n");
		nethook_cleanup();
		return false;
	}

	nethook.irqsync = irqsync_create();
	if (!nethook.irqsync)
	{
		printk(KERN_ERR "kgdboe: create IRQ synchronization manager. Aborting.\n");
		nethook_cleanup();
		return false;
	}

	nethook.timerhook = timerhook_create(owner_module);
	if (!nethook.timerhook)
	{
		printk(KERN_ERR "kgdboe: create timer hook. Aborting.\n");
		nethook_cleanup();
		return false;
	}

	spin_lock_init(&nethook.netdev_api_lock);

	err = set_memory_rw(((unsigned long)dev->netdev_ops >> PAGE_SHIFT) << PAGE_SHIFT, 2);
	if (err)
	{
		printk(KERN_ERR "Cannot change memory protection attributes of netdev_ops for %s. Aborting.", dev->name);
		nethook_cleanup();
		return false;
	}
#define HOOK_NET_API_FUNC(name) \
	if (dev->netdev_ops->name) \
	{	\
		original_ ## name = dev->netdev_ops->name;	\
		*((void **)&dev->netdev_ops->name) = name ## _hook;	\
	} \
	else \
		original_ ## name = NULL;

	HOOK_NET_API_FUNC(ndo_get_stats);
	HOOK_NET_API_FUNC(ndo_get_stats64);

#undef HOOK_NET_API_FUNC

	nethook.hooked_device = dev;

	for (i = 0; i < nr_irqs; i++)
	{
		struct irq_desc *desc = irq_to_desc(i);
		if (!desc || !desc->action)
			continue;
		if (within_module_core((unsigned long)desc->action->handler, owner_module))
		{
			printk(KERN_INFO "kgdboe: IRQ %d appears to be managed by %s and will be disabled while stopped in debugger.", i, owner_module->name);
			if (!irqsync_add_managed_irq(nethook.irqsync, i, desc))
			{
				printk(KERN_ERR "kgdboe: failed to take control over IRQ %d. Aborting\n", i);
				nethook_cleanup();
				return false;
			}

			if (!hook_spinlock(nethook.spinhook, &desc->lock))
			{
				printk(KERN_ERR "kgdboe: failed to hook spinlock of IRQ %d. Aborting\n", i);
				nethook_cleanup();
				return false;
			}
		}
	}

	list_for_each_entry(napi, &dev->napi_list, dev_list)
	{
		if (!hook_spinlock(nethook.spinhook, &napi->poll_lock.rlock))
		{
			printk(KERN_ERR "kgdboe: failed to hook spinlock of NAPI %p. Aborting\n", napi);
			nethook_cleanup();
			return false;
		}
	}

	if (!hook_spinlock(nethook.spinhook, &timerhook_get_spinlock(nethook.timerhook)->rlock))
	{
		printk(KERN_ERR "kgdboe: failed to %s timer lock. Aborting\n", owner_module->name);
		nethook_cleanup();
		return false;
	}

	if (!hook_spinlock(nethook.spinhook, &nethook.netdev_api_lock.rlock))
	{
		printk(KERN_ERR "kgdboe: failed to hook %s API lock. Aborting\n", dev->name);
		nethook_cleanup();
		return false;
	}

	for (i = 0; i < dev->num_tx_queues; i++)
	{
		printk(KERN_INFO "kgdboe: hooking TX queue #%d of %s...\n", i, dev->name);
		if (!hook_spinlock(nethook.spinhook, &netdev_get_tx_queue(dev, i)->_xmit_lock.rlock))
		{
			printk(KERN_ERR "kgdboe: failed to hook TX queue #%d of %s. Aborting\n", i, dev->name);
			nethook_cleanup();
			return false;
		}
	}

	if (jiffies_lock)
	{
		if (!hook_spinlock(nethook.spinhook, &jiffies_lock->lock.rlock))
		{
			printk(KERN_ERR "kgdboe: failed to hook jiffies_lock. Aborting\n");
			nethook_cleanup();
			return false;
		}
	}
	else
		printk(KERN_WARNING "kgdboe: cannot find and hook jiffies_lock. Your session will hang if a breakpoint coincides with jiffies updating.\n");

	printk(KERN_INFO "kgdboe: your kernel has been hooked to avoid deadlocks caused by accessing network driver from debugger.\n");
	printk(KERN_INFO "        If you experience random hangups, try enabling the forced single-CPU mode via module parameters.\n");
	return true;
}

void nethook_cleanup()
{
	if (!nethook.initialized)
		return;

	nethook.initialized = false;

	if (nethook.hooked_device)
	{
		if (original_ndo_get_stats)
#define UNHOOK_NET_API_FUNC(name) \
		if (original_ ## name) \
		{	\
		*((void **)&nethook.hooked_device->netdev_ops->name) = original_ ## name;	\
		}

		UNHOOK_NET_API_FUNC(ndo_get_stats);
		UNHOOK_NET_API_FUNC(ndo_get_stats64);

#undef UNHOOK_NET_API_FUNC
	}

	if (nethook.timerhook)
		timerhook_free(nethook.timerhook);

	if (nethook.irqsync)
		irqsync_free(nethook.irqsync);

	if (nethook.spinhook)
		spinlock_hook_manager_free(nethook.spinhook);
}

void nethook_take_relevant_resources()
{
	if (!nethook.initialized)
		return;
	irqsync_suspend_irqs(nethook.irqsync);
	spinlock_hook_manager_take_all_locks(nethook.spinhook);
}

void nethook_release_relevant_resources()
{
	if (!nethook.initialized)
		return;

	irqsync_resume_irqs(nethook.irqsync);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
#define preempt_count_set(val) preempt_count() = val
#endif

void nethook_netpoll_work_starting()
{
	if (!nethook.initialized)
		return;

	spinlock_hook_manager_save_and_reset_all_locks(nethook.spinhook);

	nethook.saved_preempt = preempt_count();
	preempt_count_set(nethook.saved_preempt | (1 << SOFTIRQ_SHIFT));
}

void nethook_netpoll_work_done()
{
	if (!nethook.initialized)
		return;

	preempt_count_set(nethook.saved_preempt);
	spinlock_hook_manager_restore_all_locks(nethook.spinhook);
}

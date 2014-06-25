#include <linux/netdevice.h>
#include <linux/radix-tree.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <trace/events/timer.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <linux/cpu.h>
#include <linux/kallsyms.h>
#include "irqsync.h"
#include "spinhook.h"
#include <linux/seqlock.h>

//#define DISABLE_SYNC_HOOKING

#ifdef DISABLE_SYNC_HOOKING
void take_hooked_spinlocks() {}
void save_hooked_spinlocks() {}
void restore_hooked_spinlocks() {}
void release_hooked_spinlocks() {}

void hold_irq_enabling() {}
void enable_queued_irqs() {}
void nethook_service(){}
void hook_netdev(struct net_device *pNetDev)
{
	void(*pset_cpu_online)(int, bool) = kallsyms_lookup_name("set_cpu_online");
	printk(KERN_INFO "kgdboe: single-core mode enabled. Shutting down all cores except #0\n");
	for (int i = 1; i < nr_cpu_ids; i++)
		cpu_down(i);
}

#else

struct module *testModule;

#ifdef SYNC_IRQ
struct hooked_spinlock hookedIrqLock;
#endif

spinlock_t timerLock;
spinlock_t transmitLock;	//ndo_start_xmit

static notrace void hook_timer_entry(void *v, struct timer_list *timer)
{
	if (within_module_core(timer->function, testModule))
		spin_lock(&timerLock);
}

static notrace void hook_timer_exit(void *v, struct timer_list *timer)
{
	if (within_module_core(timer->function, testModule))
		spin_unlock(&timerLock);
}


struct rtnl_link_stats64* (*original_ndo_get_stats64)(struct net_device *dev, struct rtnl_link_stats64 *storage);
struct net_device_stats* (*original_ndo_get_stats)(struct net_device *dev);

struct rtnl_link_stats64* ndo_get_stats64_hook(struct net_device *dev, struct rtnl_link_stats64 *storage)
{
	spin_lock(&transmitLock);
	struct rtnl_link_stats64* result = original_ndo_get_stats64(dev, storage);
	spin_unlock(&transmitLock);
	return result;
}

struct net_device_stats* ndo_get_stats_hook(struct net_device *dev)
{
	spin_lock(&transmitLock);
	struct net_device_stats* result = original_ndo_get_stats(dev);
	spin_unlock(&transmitLock);
	return result;
}

struct irqsync_manager *irqsync;
struct spinlock_hook_manager *spinhook;

void hook_netdev(struct net_device *pNetDev)
{
	testModule = find_module("pcnet32");
	
	seqlock_t *jiffies_lock = (seqlock_t *)kallsyms_lookup_name("jiffies_lock");

	irqsync = irqsync_create();
	spinhook = spinlock_hook_manager_create();

	spin_lock_init(&timerLock);
	spin_lock_init(&transmitLock);

	original_ndo_get_stats = pNetDev->netdev_ops->ndo_get_stats;
	original_ndo_get_stats64 = pNetDev->netdev_ops->ndo_get_stats64;
	
	set_memory_rw(((unsigned)pNetDev->netdev_ops >> PAGE_SHIFT) << PAGE_SHIFT, 2);

	*((void **)&pNetDev->netdev_ops->ndo_get_stats) = ndo_get_stats_hook;
	//*((void **)&pNetDev->netdev_ops->ndo_get_stats64) = ndo_get_stats64_hook;

	//set pNetDev->netdev_ops->ndo_start_xmit = ndo_start_xmit_hook
	//set pNetDev->netdev_ops->ndo_get_stats = ndo_get_stats_hook
	//set pNetDev->netdev_ops->ndo_get_stats64 = ndo_get_stats64_hook
	
	asm("nop");

	for (int i = 0; i < nr_irqs; i++)
	{
		struct irq_desc *pDesc = irq_to_desc(i);
		if (!pDesc || !pDesc->action)
			continue;
		if (within_module_core(pDesc->action->handler, testModule))
		{
			irqsync_add_managed_irq(irqsync, i, pDesc);
			hook_spinlock(spinhook, &pDesc->lock);
		}
	}

	hook_spinlock(spinhook, &jiffies_lock->lock);


	struct napi_struct *napi;
	list_for_each_entry(napi, &pNetDev->napi_list, dev_list)
	{
		hook_spinlock(spinhook, &napi->poll_lock);
	}

	hook_spinlock(spinhook, &timerLock);
	hook_spinlock(spinhook, &transmitLock);

	for (int i = 0; i < pNetDev->num_tx_queues; i++)
	{
		hook_spinlock(spinhook, &netdev_get_tx_queue(pNetDev, i)->_xmit_lock);
	}

	register_trace_timer_expire_entry(hook_timer_entry, NULL);
	register_trace_timer_expire_exit(hook_timer_exit, NULL);

//	register_trace_irq_handler_entry(hook_irq_enter, NULL);
//	register_trace_irq_handler_exit(hook_irq_exit, NULL);
}

#include <linux/preempt.h>
int saved_preempt;

void take_hooked_spinlocks()
{
	spinlock_hook_manager_take_all_locks(spinhook);
}

void save_hooked_spinlocks()
{
	spinlock_hook_manager_save_and_reset_all_locks(spinhook);

	saved_preempt = preempt_count();
	preempt_count() |= NMI_MASK;
}


void restore_hooked_spinlocks()
{
	preempt_count() = saved_preempt;
	spinlock_hook_manager_restore_all_locks(spinhook);
}

void hold_irq_enabling()
{
	//hold_irq_enable = true;
	irqsync_suspend_irqs(irqsync);
}

void enable_queued_irqs()
{
	//hold_irq_enable = false;
	//check_lock();
	irqsync_resume_irqs(irqsync);
}

void nethook_service()
{
}
#endif
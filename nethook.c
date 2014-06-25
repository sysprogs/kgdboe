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

//#define SYNC_IRQ

int hookedIrq;
struct irq_desc *pHookedIrq;

struct module *testModule;

enum hooked_spinlock_state
{
	hooked_spinlock_not_owned,	//We don't own the spin lock. Either we have not taken it yet, or have released it already.
	hooked_spinlock_taken,		//The spin lock is taken by us. We don't know how many other cores are enqueued there
	hooked_spinlock_saved,
};

struct hooked_spinlock
{
	struct hooked_spinlock *pNext;
	spinlock_t *pOriginalLock;
	spinlock_t copiedState;
	enum hooked_spinlock_state state;
};

#ifdef SYNC_IRQ
struct hooked_spinlock hookedIrqLock;
#endif

spinlock_t timerLock;
spinlock_t transmitLock;	//ndo_start_xmit

struct hooked_spinlock *s_pFirst = NULL, *s_pLast = NULL;

/*static notrace void hook_irq_enter(void *v, int irq, struct irqaction *action)
{
	if (irq == hookedIrq)
		spin_lock(&hookLock);
}

static notrace void hook_irq_exit(void *v, int irq, struct irqaction *action,
				   int ret)
{
	if (irq == hookedIrq)
		spin_unlock(&hookLock);
}*/

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


static void hook_spinlock(spinlock_t *pSpinLock)
{
	struct hooked_spinlock *pHooked = (struct hooked_spinlock *)kmalloc(sizeof(struct hooked_spinlock), GFP_KERNEL);
	pHooked->pOriginalLock = pSpinLock;
	pHooked->pNext = NULL;
	pHooked->state = hooked_spinlock_not_owned;
	if (!s_pFirst)
		s_pFirst = pHooked;
	if (s_pLast)
		s_pLast->pNext = pHooked;
	s_pLast = pHooked;
}

netdev_tx_t(*original_ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev);
struct rtnl_link_stats64* (*original_ndo_get_stats64)(struct net_device *dev, struct rtnl_link_stats64 *storage);
struct net_device_stats* (*original_ndo_get_stats)(struct net_device *dev);

static netdev_tx_t ndo_start_xmit_hook(struct sk_buff *skb, struct net_device *dev)
{
	spin_lock(&transmitLock);
	netdev_tx_t result = original_ndo_start_xmit(skb, dev);
	spin_unlock(&transmitLock);
	return result;
}

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

void hook_netdev(struct net_device *pNetDev)
{
	testModule = find_module("pcnet32");

	seqlock_t *jiffies_lock = (seqlock_t *)kallsyms_lookup_name("jiffies_lock");

	irqsync = irqsync_create();

	spin_lock_init(&timerLock);
	spin_lock_init(&transmitLock);

	original_ndo_start_xmit = pNetDev->netdev_ops->ndo_start_xmit;
	original_ndo_get_stats = pNetDev->netdev_ops->ndo_get_stats;
	original_ndo_get_stats64 = pNetDev->netdev_ops->ndo_get_stats64;
	
	set_memory_rw(((unsigned)pNetDev->netdev_ops >> PAGE_SHIFT) << PAGE_SHIFT, 2);

	*((void **)&pNetDev->netdev_ops->ndo_start_xmit) = ndo_start_xmit_hook;
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

			hookedIrq = i;
			pHookedIrq = pDesc;
			//hookedIrqLock.pOriginalLock = &pDesc->lock;
			hook_spinlock(&pDesc->lock);
		}
	}

	hook_spinlock(&jiffies_lock->lock);


	struct napi_struct *napi;
	list_for_each_entry(napi, &pNetDev->napi_list, dev_list)
	{
		hook_spinlock(&napi->poll_lock);
	}

	hook_spinlock(&timerLock);
	hook_spinlock(&transmitLock);

	for (int i = 0; i < pNetDev->num_tx_queues; i++)
	{
		hook_spinlock(&netdev_get_tx_queue(pNetDev, i)->_xmit_lock);
	}

	register_trace_timer_expire_entry(hook_timer_entry, NULL);
	register_trace_timer_expire_exit(hook_timer_exit, NULL);

//	register_trace_irq_handler_entry(hook_irq_enter, NULL);
//	register_trace_irq_handler_exit(hook_irq_exit, NULL);
}

static bool try_take_irq_lock()
{
	if (spin_trylock(&pHookedIrq->lock))
	{
		if (!irqd_irq_inprogress(&pHookedIrq->irq_data))
		{
			return true;
		}
		spin_unlock(&pHookedIrq->lock);
	}
	return false;
}

void check_lock()
{
#ifdef SYNC_IRQ
	if (spin_is_locked(hookedIrqLock.pOriginalLock))
	{
		asm("nop");
	}
#endif
}

void take_hooked_spinlocks()
{
	check_lock();

	for (;;)
	{
		check_lock();

#ifdef SYNC_IRQ
		while (irqd_irq_inprogress(&pHookedIrq->irq_data))
			cpu_relax();

		check_lock();

		if (!try_take_irq_lock())
			continue;
#endif

		bool failed = false;

		for (struct hooked_spinlock *pLock = s_pFirst; pLock; pLock = pLock->pNext)
		{
			if (spin_trylock(pLock->pOriginalLock))
			{
				pLock->state = hooked_spinlock_taken;
			}
			else
			{
				failed = true;
				break;
			}
		}

		if (!failed)
		{
#ifdef SYNC_IRQ
			hookedIrqLock.state = hooked_spinlock_taken;
#endif
			return;
		}

		for (struct hooked_spinlock *pLock = s_pFirst; pLock; pLock = pLock->pNext)
		{
			if (pLock->state == hooked_spinlock_taken)
			{
				spin_unlock(pLock->pOriginalLock);
				pLock->state = hooked_spinlock_not_owned;
			}
		}

		cpu_relax();
	}

}

static bool s_SpinLocksSaved;

#include <linux/preempt.h>
int saved_preempt;

void save_hooked_spinlocks()
{
	BUG_ON(s_SpinLocksSaved);

	for (struct hooked_spinlock *pLock = s_pFirst; pLock; pLock = pLock->pNext)
	{
		BUG_ON(pLock->state != hooked_spinlock_taken && pLock->state != hooked_spinlock_not_owned);
		if (pLock->state == hooked_spinlock_taken)
			spin_unlock(pLock->pOriginalLock);

		pLock->copiedState = *pLock->pOriginalLock;
		spin_lock_init(pLock->pOriginalLock);
		pLock->state = hooked_spinlock_saved;
	}

#ifdef SYNC_IRQ
	if (hookedIrqLock.state == hooked_spinlock_taken)
		spin_unlock(hookedIrqLock.pOriginalLock);

	check_lock();

	hookedIrqLock.copiedState = *hookedIrqLock.pOriginalLock;
	spin_lock_init(hookedIrqLock.pOriginalLock);
	hookedIrqLock.state = hooked_spinlock_saved;
#endif

	s_SpinLocksSaved = true;

	saved_preempt = preempt_count();
	if (!(saved_preempt & NMI_MASK))
	{
		asm("nop");
	}
	preempt_count() |= NMI_MASK;
	check_lock();
}


void restore_hooked_spinlocks()
{
	preempt_count() = saved_preempt;

	BUG_ON(!s_SpinLocksSaved);
	for (struct hooked_spinlock *pLock = s_pFirst; pLock; pLock = pLock->pNext)
	{
		BUG_ON(pLock->state != hooked_spinlock_saved);
		*pLock->pOriginalLock = pLock->copiedState;
		pLock->state = hooked_spinlock_not_owned;
	}

#ifdef  SYNC_IRQ
	*hookedIrqLock.pOriginalLock = hookedIrqLock.copiedState;
	hookedIrqLock.state = hooked_spinlock_not_owned;
#endif

	s_SpinLocksSaved = false;
	check_lock();
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
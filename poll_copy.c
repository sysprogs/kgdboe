#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/netpoll.h>
#include "netpoll_wrapper.h"

/*
	This file contains copies of netpoll_poll_dev() and all related functions that are no longer usable
	in kernel 3.15.
*/

#ifndef NETPOLL_POLL_DEV_USABLE

static int poll_one_napi(struct napi_struct *napi, int budget)
{
	int work;

	/* net_rx_action's ->poll() invocations and our's are
	* synchronized by this test which is only made while
	* holding the napi->poll_lock.
	*/
	if (!test_bit(NAPI_STATE_SCHED, &napi->state))
		return budget;

	if (test_and_set_bit(NAPI_STATE_NPSVC, &napi->state))
		return budget;
	
	work = napi->poll(napi, budget);
	WARN_ONCE(work > budget, "%pF exceeded budget in poll\n", napi->poll);

	clear_bit(NAPI_STATE_NPSVC, &napi->state);

	return budget - work;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static void poll_napi(struct net_device *dev, int budget)
{
	struct napi_struct *napi;

	list_for_each_entry(napi, &dev->napi_list, dev_list) {
		if (napi->poll_owner != smp_processor_id() &&
			spin_trylock(&napi->poll_lock)) {
			budget = poll_one_napi(napi, budget);
			spin_unlock(&napi->poll_lock);
		}
	}
}
#else
static void __attribute__((optimize("O2", "-fno-omit-frame-pointer"))) poll_napi(struct net_device *dev, int budget)
{
    struct napi_struct *napi;
    int cpu = smp_processor_id();

    list_for_each_entry(napi, &dev->napi_list, dev_list) {
        if (cmpxchg(&napi->poll_owner, -1, cpu) == -1) {
            poll_one_napi(napi, budget);
            smp_store_release(&napi->poll_owner, -1);
        }
    }
}
#endif

void netpoll_poll_dev_copy(struct net_device *dev, void(*zap_completion_queue)(void))
{
	const struct net_device_ops *ops;
	struct netpoll_info *ni = rcu_dereference_bh(dev->npinfo);
	int budget = 16;

	/* Don't do any rx activity if the dev_lock mutex is held
	* the dev_open/close paths use this to block netpoll activity
	* while changing device state
	*/
	if (down_trylock(&ni->dev_lock))
		return;

	if (!netif_running(dev)) {
		up(&ni->dev_lock);
		return;
	}

	ops = dev->netdev_ops;
	if (!ops->ndo_poll_controller) {
		up(&ni->dev_lock);
		return;
	}

	/* Process pending work on NIC */
	ops->ndo_poll_controller(dev);

	poll_napi(dev, budget);

	up(&ni->dev_lock);

	zap_completion_queue();
}
#endif
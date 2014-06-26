#include <linux/slab.h>
#include <linux/cpu.h>
#include "spinhook.h"

/*
	This file provides functionality that helps ensuring that network driver invoked by kgdb
	can take any spinlocks it needs. This code is only needed on systems with more than 1 logical CPU.
	Here is a simplified view of what's going on:
	1. KGDB handles an exception. All other CPU cores are running and may hold some of the locks.
	2. KGDB core calls spinlock_hook_manager_take_all_locks() that acquires all relevant locks.
	3. KGDB stops all other cores. The previous step ensures that none of them holds any of our locks.
	4. spinlock_hook_manager_save_and_reset_all_locks() is called. The locks are released. As other
	   cores are stopped, they cannot re-take the locks.
	5. KGDB communicates with GDB over the network from the non-stopped core. The locks are taken and released
	   by the network driver as needed. Other cores are stopped and don't interfere.
	6. The user resumes execution. KGDB resumes all other cores. They can now take the spinlocks normally.

	The complication is that the Linux kernel uses the ticket spinlocks that ensure the first-come-first-serve
	principle. Assume the following scenario:
		1. Core #0 got an exception and took a lock
		2. Core #1 tried to take the lock and is now waiting for it to be released
		3. Core #1 is stopped by KGDB
		4. Core #0 releases the lock
		5. Network code running on core #0 tries to take the lock

	This won't work, as the ticket spinlocks guarantee that the core #1 (that is now stopped) will get served before
	core #0.

	To avoid this problem we use a hack:
		1. When all other cores are stopped, and we want to run some network core on the only active core, 
		   we release the spinlock, then save its state and re-initialize it from scratch.
		2. All network code running on the active core can take the lock as if there were no other cores waiting.
		3. Now we need to really rely on the other cores being stopped by KGDB! If they awake and try to access our
		   manally modified lock, they will deadlock! Thankfully, KGDB ensures they are stopped.
		4. After KGDB is done using the network driver, we restore the original state of the spinlocks. When the other
		   cores are resumed, our manipulations with the spinlocks won't affect them as we restore exactly the state that
		   was before they were stopped.

	Our hack will break if:
		1. Other cores get woken up before kgdb is done talking to the network. Should not happen given the *current* kgdb
		   architecture (unless core roundup is manually disabled).
		2. Calling the network code from kgdb will change the state of some spinlocks. E.g. the network driver will take a 
		   spinlock and queue a timer that will release it later. If that happens, the network driver will have to be patched
		   to disable this behavior!

	Anyway, it is recommended to use the single-core mode while debugging (enabled by default) unless you absolutely have to
	use SMP, as it eliminates the need for any hacks and implicit assumptions.
*/

struct spinlock_hook_manager *spinlock_hook_manager_create()
{
	struct spinlock_hook_manager *mgr = (struct spinlock_hook_manager *)kmalloc(sizeof(struct spinlock_hook_manager), GFP_KERNEL);
	if (!mgr)
		return NULL;
	INIT_LIST_HEAD(&mgr->hooks);
	mgr->global_state = hooked_spinlock_not_owned;
	return mgr;
}

void spinlock_hook_manager_free(struct spinlock_hook_manager *mgr)
{
	struct hooked_spinlock *hook, *tmp;
	BUG_ON(!mgr);
	BUG_ON(mgr->global_state != hooked_spinlock_not_owned);
	list_for_each_entry_safe(hook, tmp, &mgr->hooks, list)
	{
		kfree(hook);
	}
	kfree(mgr);
}

bool hook_spinlock(struct spinlock_hook_manager *mgr, struct raw_spinlock *lock)
{
	struct hooked_spinlock *hook;
	BUG_ON(!mgr);
	BUG_ON(!lock);
	if (mgr->global_state != hooked_spinlock_not_owned)
		return false;

	hook = (struct hooked_spinlock *)kmalloc(sizeof(struct hooked_spinlock), GFP_KERNEL);
	if (!hook)
		return false;

	memset(hook, 0, sizeof(*hook));
	hook->lock = lock;
	list_add_tail(&hook->list, &mgr->hooks);
	return true;
}

void spinlock_hook_manager_take_all_locks(struct spinlock_hook_manager *mgr)
{
	BUG_ON(!mgr);
	BUG_ON(mgr->global_state != hooked_spinlock_not_owned);
	for (;;)
	{
		struct hooked_spinlock *lock, *busy_lock = NULL;
		list_for_each_entry(lock, &mgr->hooks, list)
		{
			if (!raw_spin_trylock(lock->lock))
			{
				busy_lock = lock;
				break;
			}
		}

		if (!busy_lock)
		{
			mgr->global_state = hooked_spinlock_taken;
			return;
		}

		list_for_each_entry(lock, &mgr->hooks, list)
		{
			if (lock == busy_lock)
				break;
			raw_spin_unlock(lock->lock);
		}

		cpu_relax();
	}
}

void spinlock_hook_manager_save_and_reset_all_locks(struct spinlock_hook_manager *mgr)
{
	struct hooked_spinlock *lock;

	BUG_ON(!mgr);
	BUG_ON(mgr->global_state != hooked_spinlock_taken && mgr->global_state != hooked_spinlock_not_owned);
	list_for_each_entry(lock, &mgr->hooks, list)
	{
		if (mgr->global_state == hooked_spinlock_taken)
			raw_spin_unlock(lock->lock);

		lock->saved_state = *lock->lock;
		raw_spin_lock_init(lock->lock);
	}

	mgr->global_state = hooked_spinlock_saved;
}

void spinlock_hook_manager_restore_all_locks(struct spinlock_hook_manager *mgr)
{
	struct hooked_spinlock *lock;

	BUG_ON(!mgr);
	BUG_ON(mgr->global_state != hooked_spinlock_saved);
	list_for_each_entry(lock, &mgr->hooks, list)
	{
		*lock->lock = lock->saved_state;
	}

	mgr->global_state = hooked_spinlock_not_owned;
}

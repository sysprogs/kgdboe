#include <linux/slab.h>
#include <linux/cpu.h>
#include "spinhook.h"

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

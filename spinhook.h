#pragma once
#include <linux/spinlock.h>
#include <linux/list.h>

enum hooked_spinlock_state
{
	hooked_spinlock_not_owned,	//We don't own the spin lock. Either we have not taken it yet, or have released it already.
	hooked_spinlock_taken,		//The spin lock is taken by us. We don't know how many other cores are enqueued there
	hooked_spinlock_saved,
};

struct hooked_spinlock
{
	struct list_head list;
	struct raw_spinlock *lock;
	struct raw_spinlock saved_state;
};

struct spinlock_hook_manager
{
	struct list_head hooks;
	enum hooked_spinlock_state global_state;
};

struct spinlock_hook_manager *spinlock_hook_manager_create(void);
void spinlock_hook_manager_free(struct spinlock_hook_manager *mgr);

//Not thread-safe. Should be called after initialization and before any calls to xxx_all_locks()
bool hook_spinlock(struct spinlock_hook_manager *mgr, struct raw_spinlock *lock);

//Takes all locks. If any of the locks is already taken, releases all of them and tries again. This avoids
//deadlocking as we don't always know the order in which the locks are taken by the third-party components.
void spinlock_hook_manager_take_all_locks(struct spinlock_hook_manager *mgr);

//Called when all locks are taken (or already restored) and all other cores are stopped. 
//This will save the lock state and re-initialize them as available so that the current core can take them.
//Note that spinlock_hook_manager_restore_all_locks() should be called before resuming other cores, otherwise if
//some of them are already waiting on a lock, they will lock up indefinitely.
void spinlock_hook_manager_save_and_reset_all_locks(struct spinlock_hook_manager *mgr);

//Restores the saved lock state.
void spinlock_hook_manager_restore_all_locks(struct spinlock_hook_manager *mgr);

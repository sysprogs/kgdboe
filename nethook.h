#pragma once
#include <linux/netdevice.h>

bool nethook_initialize(struct net_device *dev);
void nethook_cleanup(void);

//Other cores should NOT be stopped at this point. Nethook will grab relevant spinlocks and ensure other cores won't.
void nethook_take_relevant_resources(void);
//Other cores may be still frozen. Nethook should not do anything that may block.
void nethook_release_relevant_resources(void);

//Other cores SHOULD be stopped at this point and up until a call to work_done().
//Nethook will release non-recursive locks and it's the caller's responsibility to ensure that no other core grabs them.
void nethook_netpoll_work_starting(void);

//Other cores SHOULD be stopped at this point.
void nethook_netpoll_work_done(void);

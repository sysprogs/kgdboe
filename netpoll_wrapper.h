#pragma once
#include <linux/netpoll.h>
#include <linux/atomic.h>

typedef void(*pnetpoll_wrapper_synced_action)(void *pContext);
typedef void(*pnetpoll_wrapper_rx_handler)(void *pContext, int port, char *msg, int len);

#define NETPOLL_RX_HOOK_SUPPORTED
#define NETPOLL_POLL_DEV_USABLE

struct netpoll_wrapper
{
	struct netpoll netpoll_obj;
	struct net_device *pDeviceWithHandler;

	atomic_t synced_action_pending;
	pnetpoll_wrapper_synced_action pSyncedAction;
	pnetpoll_wrapper_rx_handler pReceiveHandler;
	void *pUserContext;

#ifdef NETPOLL_POLL_DEV_USABLE
	void (*netpoll_poll_dev)(struct net_device *dev);
#else
	void(*zap_completion_queue)();
#endif
	
	bool netpoll_initialized;
	bool drop_other_packets;
};

struct netpoll_wrapper *netpoll_wrapper_create(const char *pDeviceName, int localPort, const char *pOptionalLocalIp);
void netpoll_wrapper_free(struct netpoll_wrapper *pWrapper);
void netpoll_wrapper_send_reply(struct netpoll_wrapper *pWrapper, const void *pData, int dataSize);
void netpoll_wrapper_poll(struct netpoll_wrapper *pWrapper);
void netpoll_wrapper_set_callbacks(struct netpoll_wrapper *pWrapper, pnetpoll_wrapper_rx_handler pReceiveHandler, pnetpoll_wrapper_synced_action pSyncedAction, void *pUserContext);

static inline void netpoll_enqueue_synced_action(struct netpoll_wrapper *pWrapper)
{
	BUG_ON(!pWrapper);
	atomic_xchg(&pWrapper->synced_action_pending, 1);
}

#ifndef NETPOLL_POLL_DEV_USABLE
void netpoll_poll_dev_copy(struct net_device *dev, void(*zap_completion_queue)(void));
#endif
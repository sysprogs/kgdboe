#pragma once
#include <linux/netpoll.h>
#include <linux/atomic.h>

enum netpoll_wrapper_iface
{
	netpoll_wrapper_iface1,
	netpoll_wrapper_iface2
};

typedef void(*pnetpoll_wrapper_rx_handler)(void *pContext, enum netpoll_wrapper_iface iface, int port, char *msg, int len);

#define NETPOLL_RX_HOOK_SUPPORTED
#define NETPOLL_POLL_DEV_USABLE

struct netpoll_wrapper
{
	struct netpoll netpoll_obj1, netpoll_obj2;
	struct net_device *pDeviceWithHandler;

	pnetpoll_wrapper_rx_handler pReceiveHandler;
	void *pUserContext;

#ifdef NETPOLL_POLL_DEV_USABLE
	void (*netpoll_poll_dev)(struct net_device *dev);
#else
	void(*zap_completion_queue)();
#endif
	
	bool netpoll1_initialized, netpoll2_initialized;
	bool reply_address_assigned;
	bool drop_other_packets;
};

struct netpoll_wrapper *netpoll_wrapper_create(const char *pDeviceName, int localPort, int localPort2, const char *pOptionalLocalIp);
void netpoll_wrapper_free(struct netpoll_wrapper *pWrapper);
void netpoll_wrapper_send_reply(struct netpoll_wrapper *pWrapper, const void *pData, int dataSize);
void netpoll_wrapper_poll(struct netpoll_wrapper *pWrapper);
void netpoll_wrapper_set_callback(struct netpoll_wrapper *pWrapper, pnetpoll_wrapper_rx_handler pReceiveHandler, void *pUserContext);
void netpoll_wrapper_set_reply_addresses(struct netpoll_wrapper *pWrapper, const void *pMacAddress, int ipAddres);

static bool netpoll_wrapper_reply_address_assigned(struct netpoll_wrapper *pWrapper)
{
	BUG_ON(!pWrapper);
	return pWrapper->reply_address_assigned;
}

static void netpoll_wrapper_reset_reply_address(struct netpoll_wrapper *pWrapper)
{
	BUG_ON(!pWrapper);
	pWrapper->reply_address_assigned = false;
	pWrapper->netpoll_obj1.remote_ip = pWrapper->netpoll_obj2.remote_ip = 0;
}

static void netpoll_wrapper_set_drop_flag(struct netpoll_wrapper *pWrapper, bool flag)
{
	BUG_ON(!pWrapper);
	pWrapper->drop_other_packets = flag;
}

#ifndef NETPOLL_POLL_DEV_USABLE
void netpoll_poll_dev_copy(struct net_device *dev, void(*zap_completion_queue)(void));
#endif
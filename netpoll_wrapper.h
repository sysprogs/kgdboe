#pragma once
#include <linux/netpoll.h>
#include <linux/atomic.h>
#include <linux/version.h>

typedef void(*pnetpoll_wrapper_rx_handler)(void *pContext, int port, char *msg, int len);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)
#define NETPOLL_POLL_DEV_USABLE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#define ip_addr_as_int(addr) (addr)
#else
#define ip_addr_as_int(addr) ((addr).ip)
#endif

struct queued_arp_reply
{
	__be32 local_ip;
	__be32 remote_ip;
	u8 remote_mac[ETH_ALEN];
	bool valid;
};

struct netpoll_wrapper
{
	struct netpoll netpoll_obj;
	struct net_device *pDeviceWithHandler;

	pnetpoll_wrapper_rx_handler pReceiveHandler;
	void *pUserContext;

#ifdef NETPOLL_POLL_DEV_USABLE
	void (*netpoll_poll_dev)(struct net_device *dev);
#else
	void(*zap_completion_queue)(void);
#endif
	
	bool netpoll_initialized, tracepoint_registered;
	bool drop_other_packets;
	bool handle_arp;
	struct queued_arp_reply pending_arp_replies[4];
};

struct netpoll_wrapper *netpoll_wrapper_create(const char *pDeviceName, int localPort, const char *pOptionalLocalIp);
void netpoll_wrapper_free(struct netpoll_wrapper *pWrapper);
void netpoll_wrapper_send_reply(struct netpoll_wrapper *pWrapper, const void *pData, int dataSize);
void netpoll_wrapper_poll(struct netpoll_wrapper *pWrapper);
void netpoll_wrapper_set_callback(struct netpoll_wrapper *pWrapper, pnetpoll_wrapper_rx_handler pReceiveHandler, void *pUserContext);

static inline void netpoll_wrapper_set_drop_flag(struct netpoll_wrapper *pWrapper, bool flag)
{
	BUG_ON(!pWrapper);
	pWrapper->drop_other_packets = flag;
}

#ifndef NETPOLL_POLL_DEV_USABLE
void netpoll_poll_dev_copy(struct net_device *dev, void(*zap_completion_queue)(void));
#endif
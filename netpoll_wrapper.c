#include "netpoll_wrapper.h"
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/kallsyms.h>

static rx_handler_result_t netpoll_wrapper_rx_handler(struct sk_buff **pskb);

#ifdef NETPOLL_RX_HOOK_SUPPORTED
static void netpoll_wrapper_rx_hook1(struct netpoll *np, int port, char *msg, int len);
static void netpoll_wrapper_rx_hook2(struct netpoll *np, int port, char *msg, int len);
#endif

struct netpoll_wrapper *netpoll_wrapper_create(const char *pDeviceName, int localPort, int localPort2, const char *pOptionalLocalIp)
{
	if (!pDeviceName || !localPort)
	{
		printk(KERN_ERR "kgdboe: cannot create a netpoll wrapper without a device name\n");
		return NULL;
	}

	struct net_device *pDevice = dev_get_by_name(&init_net, pDeviceName);
	if (!pDevice)
	{
		printk(KERN_ERR "kgdboe: Cannot find network device by name: %s\n", pDeviceName);
		return NULL;
	}


	int localIp;
	if (pOptionalLocalIp)
	{
		localIp = in_aton(pOptionalLocalIp);
		if (!localIp)
		{
			printk(KERN_ERR "kgdboe: Invalid local IP: %s\n", pOptionalLocalIp);
			return NULL;
		}
	}
	else
	{
		if (!pDevice->ip_ptr)
		{
			printk(KERN_ERR "kgdboe: %s does not have an in_device associated. Cannot get default IP address.\n", pDeviceName);
			return NULL;
		}
		if (!pDevice->ip_ptr->ifa_list)
		{
			printk(KERN_ERR "kgdboe: %s does not have a in_ifaddr struct associated. Cannot get default IP address.\n", pDeviceName);
			return NULL;
		}

		localIp = pDevice->ip_ptr->ifa_list->ifa_local;
	}

	struct netpoll_wrapper *pResult = (struct netpoll_wrapper *)kmalloc(sizeof(struct netpoll_wrapper), GFP_KERNEL);
	if (!pResult)
	{
		printk(KERN_ERR "kgdboe: cannot allocate memory for netpoll wrapper\n");
		return NULL;
	}

	memset(pResult, 0, sizeof(*pResult));

#ifdef NETPOLL_POLL_DEV_USABLE
	pResult->netpoll_poll_dev = (void(*)(struct net_device *))kallsyms_lookup_name("netpoll_poll_dev");
	if (!pResult->netpoll_poll_dev)
	{
		printk(KERN_ERR "kgdboe: Cannot find netpoll_poll_dev(). Aborting.\n");
		netpoll_wrapper_free(pResult);
		return NULL;
	}
#else
	pResult->zap_completion_queue = (void(*)(void))kallsyms_lookup_name("zap_completion_queue");
	if (!pResult->zap_completion_queue)
	{
		printk(KERN_ERR "kgdboe: Cannot find zap_completion_queue(). Aborting.\n");
		netpoll_wrapper_free(pResult);
		return NULL;
	}
#endif

	int err = netdev_rx_handler_register(pDevice, netpoll_wrapper_rx_handler, pResult);
	if (err < 0)
	{
		printk(KERN_ERR "kgdboe: Failed to register rx handler for %s, code %d\n", pDeviceName, err);
		netpoll_wrapper_free(pResult);
		return NULL;
	}

	pResult->pDeviceWithHandler = pDevice;

	strncpy(pResult->netpoll_obj1.dev_name, pDeviceName, sizeof(pResult->netpoll_obj1.dev_name));
	pResult->netpoll_obj1.name = "kgdboe";
	pResult->netpoll_obj1.local_port = localPort;
	memset(pResult->netpoll_obj1.remote_mac, 0xFF, sizeof(pResult->netpoll_obj1.remote_mac));

	strncpy(pResult->netpoll_obj2.dev_name, pDeviceName, sizeof(pResult->netpoll_obj2.dev_name));
	pResult->netpoll_obj2.name = "kgdboe";
	pResult->netpoll_obj2.local_port = localPort2;
	memset(pResult->netpoll_obj2.remote_mac, 0xFF, sizeof(pResult->netpoll_obj2.remote_mac));

#ifdef NETPOLL_RX_HOOK_SUPPORTED
	pResult->netpoll_obj1.rx_hook = netpoll_wrapper_rx_hook1;
	pResult->netpoll_obj2.rx_hook = netpoll_wrapper_rx_hook2;
#endif

	err = netpoll_setup(&pResult->netpoll_obj1);
	if (err < 0)
	{
		printk(KERN_ERR "kgdboe: Failed to setup netpoll for %s, code %d\n", pDeviceName, err);
		netpoll_wrapper_free(pResult);
		return NULL;
	}

	pResult->netpoll1_initialized = true;

	err = netpoll_setup(&pResult->netpoll_obj2);
	if (err < 0)
	{
		printk(KERN_ERR "kgdboe: Failed to setup netpoll for %s, code %d\n", pDeviceName, err);
		netpoll_wrapper_free(pResult);
		return NULL;
	}

	pResult->netpoll2_initialized = true;
	return pResult;
}

void netpoll_wrapper_free(struct netpoll_wrapper *pWrapper)
{
	if (pWrapper)
	{
		if (pWrapper->netpoll2_initialized)
 			netpoll_cleanup(&pWrapper->netpoll_obj2);
		if (pWrapper->netpoll1_initialized)
			netpoll_cleanup(&pWrapper->netpoll_obj1);
		if (pWrapper->pDeviceWithHandler)
			netdev_rx_handler_unregister(pWrapper->pDeviceWithHandler);
		kfree(pWrapper);
	}
}

/*
	Based on __netpoll_rx() from netpoll.c in pre-3.15 kernels.
	This method will be called by the network device to process each incoming packet.
	On pre-3.15 kernels it won't be called when doing a netpoll poll. On 3.15+ where there is no
	rx_hook anymore, all packets will go through here and we'll need to invoke the rx_hook manually.
*/
static rx_handler_result_t netpoll_wrapper_rx_handler(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	int proto, len, ulen;
	const struct iphdr *iph;
	struct udphdr *uh;

	struct netpoll_wrapper *pWrapper = (struct netpoll_wrapper *)skb->dev->rx_handler_data;
	BUG_ON(!pWrapper);

	proto = ntohs(eth_hdr(skb)->h_proto);
	if (proto != ETH_P_IP)
		goto out;
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto out;
	if (skb_shared(skb))
		goto out;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto out;
	iph = (struct iphdr *)skb->data;
	if (iph->ihl < 5 || iph->version != 4)
		goto out;
	if (!pskb_may_pull(skb, iph->ihl * 4))
		goto out;
	iph = (struct iphdr *)skb->data;
	if (ip_fast_csum((u8 *)iph, iph->ihl) != 0)
		goto out;

	len = ntohs(iph->tot_len);
	if (skb->len < len || len < iph->ihl * 4)
		goto out;

	/*
	* Our transport medium may have padded the buffer out.
	* Now We trim to the true length of the frame.
	*/
	if (pskb_trim_rcsum(skb, len))
		goto out;

	iph = (struct iphdr *)skb->data;
	if (iph->protocol != IPPROTO_UDP)
		goto out;

	len -= iph->ihl * 4;
	uh = (struct udphdr *)(((char *)iph) + iph->ihl * 4);
	ulen = ntohs(uh->len);

	if (ulen != len)
		goto out;

#ifndef NETPOLL_RX_HOOK_SUPPORTED
	if (ip_addr_as_int(pWrapper->netpoll_obj1.local_ip) && ip_addr_as_int(pWrapper->netpoll_obj1.local_ip) == iph->daddr &&
		pWrapper->netpoll_obj1.local_port && pWrapper->netpoll_obj1.local_port == ntohs(uh->dest))
	{
		pWrapper->netpoll_obj1.remote_port = ntohs(uh->source);
		if (pWrapper->pReceiveHandler)
		pWrapper->pReceiveHandler(pWrapper, netpoll_wrapper_iface1, ntohs(uh->source), (char *)(uh + 1), ulen - sizeof(struct udphdr));
	}
	if (ip_addr_as_int(pWrapper->netpoll_obj2.local_ip) && ip_addr_as_int(pWrapper->netpoll_obj2.local_ip) == iph->daddr &&
		pWrapper->netpoll_obj2.local_port && pWrapper->netpoll_obj2.local_port == ntohs(uh->dest))
	{
		pWrapper->netpoll_obj2.remote_port = ntohs(uh->source);
		if (pWrapper->pReceiveHandler)
			pWrapper->pReceiveHandler(pWrapper, netpoll_wrapper_iface2, ntohs(uh->source), (char *)(uh + 1), ulen - sizeof(struct udphdr));
	}
#endif
out:
	if (pWrapper->drop_other_packets)
		return RX_HANDLER_CONSUMED;
	else
		return RX_HANDLER_PASS;
}

void netpoll_wrapper_send_reply(struct netpoll_wrapper *pWrapper, const void *pData, int dataSize)
{
	BUG_ON(!pWrapper);
	BUG_ON(!pData);

	netpoll_send_udp(&pWrapper->netpoll_obj1, pData, dataSize);
}

void netpoll_wrapper_set_reply_addresses(struct netpoll_wrapper *pWrapper, const void *pMacAddress, int ipAddres)
{
	BUG_ON(!pWrapper);
	BUG_ON(!pMacAddress);
	memcpy(pWrapper->netpoll_obj1.remote_mac, pMacAddress, sizeof(pWrapper->netpoll_obj1.remote_mac));
	memcpy(pWrapper->netpoll_obj2.remote_mac, pMacAddress, sizeof(pWrapper->netpoll_obj2.remote_mac));
	ip_addr_as_int(pWrapper->netpoll_obj1.remote_ip) = ip_addr_as_int(pWrapper->netpoll_obj2.remote_ip) = ipAddres;
	pWrapper->reply_address_assigned = true;
}

void netpoll_wrapper_poll(struct netpoll_wrapper *pWrapper)
{
	BUG_ON(!pWrapper);
	BUG_ON(pWrapper->netpoll_obj1.dev != pWrapper->netpoll_obj2.dev);
#ifdef NETPOLL_POLL_DEV_USABLE
	BUG_ON(!pWrapper->netpoll_poll_dev);
	pWrapper->netpoll_poll_dev(pWrapper->netpoll_obj1.dev);
#else
	BUG_ON(!pWrapper->zap_completion_queue);
	netpoll_poll_dev_copy(pWrapper->netpoll_obj1.dev, pWrapper->zap_completion_queue);
#endif
}

void netpoll_wrapper_set_callback(struct netpoll_wrapper *pWrapper, pnetpoll_wrapper_rx_handler pReceiveHandler, void *pUserContext)
{
	BUG_ON(!pWrapper);
	pWrapper->pReceiveHandler = pReceiveHandler;
	pWrapper->pUserContext = pUserContext;
}

#ifdef NETPOLL_RX_HOOK_SUPPORTED
static void netpoll_wrapper_rx_hook1(struct netpoll *np, int port, char *msg, int len)
{
	BUG_ON(!np);

	struct netpoll_wrapper *pWrapper = container_of(np, struct netpoll_wrapper, netpoll_obj1);
	pWrapper->netpoll_obj1.remote_port = port;

	if (pWrapper->pReceiveHandler)
		pWrapper->pReceiveHandler(pWrapper, netpoll_wrapper_iface1, port, msg, len);
}

static void netpoll_wrapper_rx_hook2(struct netpoll *np, int port, char *msg, int len)
{
	BUG_ON(!np);

	struct netpoll_wrapper *pWrapper = container_of(np, struct netpoll_wrapper, netpoll_obj2);
	pWrapper->netpoll_obj2.remote_port = port;

	if (pWrapper->pReceiveHandler)
		pWrapper->pReceiveHandler(pWrapper, netpoll_wrapper_iface2, port, msg, len);
}
#endif
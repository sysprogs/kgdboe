#include "netpoll_wrapper.h"
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/kallsyms.h>
#include <trace/events/net.h>

static rx_handler_result_t netpoll_wrapper_rx_handler(struct sk_buff **pskb);

#ifdef NETPOLL_RX_HOOK_SUPPORTED
static void netpoll_wrapper_rx_hook1(struct netpoll *np, int port, char *msg, int len);
static void netpoll_wrapper_rx_hook2(struct netpoll *np, int port, char *msg, int len);
#endif

static void hook_receive_skb(void *pContext, struct sk_buff *pSkb);

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

	register_trace_netif_receive_skb(hook_receive_skb, pResult);

	pResult->pDeviceWithHandler = pDevice;

	strncpy(pResult->netpoll_obj.dev_name, pDeviceName, sizeof(pResult->netpoll_obj.dev_name));
	pResult->netpoll_obj.name = "kgdboe";
	pResult->netpoll_obj.local_port = localPort;
	memset(pResult->netpoll_obj.remote_mac, 0xFF, sizeof(pResult->netpoll_obj.remote_mac));

#ifdef NETPOLL_RX_HOOK_SUPPORTED
	pResult->netpoll_obj.rx_hook = netpoll_wrapper_rx_hook1;
#endif

	err = netpoll_setup(&pResult->netpoll_obj);
	if (err < 0)
	{
		printk(KERN_ERR "kgdboe: Failed to setup netpoll for %s, code %d\n", pDeviceName, err);
		netpoll_wrapper_free(pResult);
		return NULL;
	}

	pResult->netpoll_initialized = true;

	return pResult;
}

void netpoll_wrapper_free(struct netpoll_wrapper *pWrapper)
{
	if (pWrapper)
	{
		if (pWrapper->netpoll_initialized)
			netpoll_cleanup(&pWrapper->netpoll_obj);
		if (pWrapper->pDeviceWithHandler)
			netdev_rx_handler_unregister(pWrapper->pDeviceWithHandler);
		kfree(pWrapper);
	}
}

static bool allow_broadcast_packets = true;

#include <linux/if_arp.h>

static void netpoll_wrapper_handle_arp(struct netpoll_wrapper *pWrapper, struct sk_buff *skb)
{
	struct arphdr *arp;
	unsigned char *arp_ptr;
	unsigned char *sha;
	__be32 sip, tip;

	if (!pskb_may_pull(skb, arp_hdr_len(skb->dev)))
		return;

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	arp = arp_hdr(skb);

	if ((arp->ar_hrd != htons(ARPHRD_ETHER) &&
		arp->ar_hrd != htons(ARPHRD_IEEE802)) ||
		arp->ar_pro != htons(ETH_P_IP) ||
		arp->ar_op != htons(ARPOP_REQUEST))
		return;

	arp_ptr = (unsigned char *)(arp + 1);
	/* save the location of the src hw addr */
	sha = arp_ptr;
	arp_ptr += skb->dev->addr_len;
	memcpy(&sip, arp_ptr, 4);
	arp_ptr += 4;
	/* If we actually cared about dst hw addr,
	it would get copied here */
	arp_ptr += skb->dev->addr_len;
	memcpy(&tip, arp_ptr, 4);

	/* Should we ignore arp? */
	if (ipv4_is_loopback(tip) || ipv4_is_multicast(tip))
		return;

	if (tip != ip_addr_as_int(pWrapper->netpoll_obj.local_ip))
		return;	//This ARP request is not for our IP

	for (int i = 0; i < ARRAY_SIZE(pWrapper->pending_arp_replies); i++)
	{
		if (!pWrapper->pending_arp_replies[i].valid)
		{
			pWrapper->pending_arp_replies[i].local_ip = tip;
			pWrapper->pending_arp_replies[i].remote_ip = sip;
			memcpy(pWrapper->pending_arp_replies[i].remote_mac, sha, sizeof(pWrapper->pending_arp_replies[i].remote_mac));
			pWrapper->pending_arp_replies[i].valid = true;
			break;
		}
	}
}

static void hook_receive_skb(void *pContext, struct sk_buff *skb)
{
	int proto, len, ulen;
	const struct iphdr *iph;
	struct udphdr *uh;

	struct netpoll_wrapper *pWrapper = (struct netpoll_wrapper *)pContext;
	BUG_ON(!pWrapper);
	if (skb->dev != pWrapper->pDeviceWithHandler)
		return;

	if (pWrapper->handle_arp && skb->protocol == htons(ETH_P_ARP))
	{
		netpoll_wrapper_handle_arp(pWrapper, skb);
		return;
	}

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

	if (pWrapper->netpoll_obj.local_port && pWrapper->netpoll_obj.local_port == ntohs(uh->dest))
	{
		if ((ip_addr_as_int(pWrapper->netpoll_obj.local_ip) && ip_addr_as_int(pWrapper->netpoll_obj.local_ip) == iph->daddr) ||
			(allow_broadcast_packets && iph->daddr == 0xffffffff))
		{
			pWrapper->netpoll_obj.remote_port = ntohs(uh->source);
			ip_addr_as_int(pWrapper->netpoll_obj.remote_ip) = iph->saddr;
			memcpy(pWrapper->netpoll_obj.remote_mac, eth_hdr(skb)->h_source, sizeof(pWrapper->netpoll_obj.remote_mac));

			if (pWrapper->pReceiveHandler)
				pWrapper->pReceiveHandler(pWrapper, ntohs(uh->source), (char *)(uh + 1), ulen - sizeof(struct udphdr));
		}
	}
out:
	return;
}


/*
	Based on __netpoll_rx() from netpoll.c in pre-3.15 kernels.
	This method will be called by the network device to process each incoming packet.
	On pre-3.15 kernels it won't be called when doing a netpoll poll. On 3.15+ where there is no
	rx_hook anymore, all packets will go through here and we'll need to invoke the rx_hook manually.
*/
static rx_handler_result_t netpoll_wrapper_rx_handler(struct sk_buff **pskb)
{
	struct netpoll_wrapper *pWrapper = (struct netpoll_wrapper *)(*pskb)->dev->rx_handler_data;
	BUG_ON(!pWrapper);

	if (pWrapper->drop_other_packets)
	{
		kfree_skb(*pskb);
		return RX_HANDLER_CONSUMED;
	}
	else
		return RX_HANDLER_PASS;
}

void netpoll_wrapper_send_reply(struct netpoll_wrapper *pWrapper, const void *pData, int dataSize)
{
	BUG_ON(!pWrapper);
	BUG_ON(!pData);

	netpoll_send_udp(&pWrapper->netpoll_obj, pData, dataSize);
}

void netpoll_wrapper_set_reply_addresses(struct netpoll_wrapper *pWrapper, const void *pMacAddress, int ipAddres)
{
	BUG_ON(!pWrapper);
	BUG_ON(!pMacAddress);
}

static void netpoll_wrapper_send_arp_reply(struct netpoll_wrapper *pWrapper, struct queued_arp_reply *reply)
{
	int hlen, tlen;
	struct arphdr *arp;
	struct sk_buff *send_skb;
	unsigned char *arp_ptr;
	int size = arp_hdr_len(pWrapper->pDeviceWithHandler);
	hlen = LL_RESERVED_SPACE(pWrapper->pDeviceWithHandler);
	tlen = pWrapper->pDeviceWithHandler->needed_tailroom;
	send_skb = alloc_skb(size + hlen + tlen, GFP_ATOMIC);

	if (!send_skb)
		return;

	skb_reserve(send_skb, hlen);
	skb_reset_network_header(send_skb);
	arp = (struct arphdr *) skb_put(send_skb, size);
	send_skb->dev = pWrapper->pDeviceWithHandler;
	send_skb->protocol = htons(ETH_P_ARP);

	/* Fill the device header for the ARP frame */
	if (dev_hard_header(send_skb, pWrapper->pDeviceWithHandler, ETH_P_ARP,
		reply->remote_mac, pWrapper->pDeviceWithHandler->dev_addr,
		send_skb->len) < 0) 
	{
		kfree_skb(send_skb);
		return;
	}

	/*
	* Fill out the arp protocol part.
	*
	* we only support ethernet device type,
	* which (according to RFC 1390) should
	* always equal 1 (Ethernet).
	*/

	arp->ar_hrd = htons(pWrapper->pDeviceWithHandler->type);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = pWrapper->pDeviceWithHandler->addr_len;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_REPLY);

	arp_ptr = (unsigned char *)(arp + 1);
	memcpy(arp_ptr, pWrapper->pDeviceWithHandler->dev_addr, pWrapper->pDeviceWithHandler->addr_len);
	arp_ptr += pWrapper->pDeviceWithHandler->addr_len;
	memcpy(arp_ptr, &reply->local_ip, 4);
	arp_ptr += 4;
	memcpy(arp_ptr, reply->remote_mac, pWrapper->pDeviceWithHandler->addr_len);
	arp_ptr += pWrapper->pDeviceWithHandler->addr_len;
	memcpy(arp_ptr, &reply->remote_ip, 4);

	netpoll_send_skb(&pWrapper->netpoll_obj, send_skb);
}

void netpoll_wrapper_poll(struct netpoll_wrapper *pWrapper)
{
	BUG_ON(!pWrapper);
	pWrapper->handle_arp = true;

#ifdef NETPOLL_POLL_DEV_USABLE
	BUG_ON(!pWrapper->netpoll_poll_dev);
	pWrapper->netpoll_poll_dev(pWrapper->netpoll_obj.dev);
#else
	BUG_ON(!pWrapper->zap_completion_queue);
	netpoll_poll_dev_copy(pWrapper->netpoll_obj.dev, pWrapper->zap_completion_queue);
#endif
	pWrapper->handle_arp = false;
	for (int i = 0; i < ARRAY_SIZE(pWrapper->pending_arp_replies); i++)
	{
		if (pWrapper->pending_arp_replies[i].valid)
		{
			netpoll_wrapper_send_arp_reply(pWrapper, &pWrapper->pending_arp_replies[i]);
			pWrapper->pending_arp_replies[i].valid = false;
		}
	}
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

	struct netpoll_wrapper *pWrapper = container_of(np, struct netpoll_wrapper, netpoll_obj);
	pWrapper->netpoll_obj.remote_port = port;

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
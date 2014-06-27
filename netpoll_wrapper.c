#include "netpoll_wrapper.h"
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/kallsyms.h>
#include <trace/events/net.h>
#include <linux/rtnetlink.h>
#include "tracewrapper.h"

/*
	This file contains a wrapper around the netpoll API that encapsulates the following tasks:
		* Replying to ARP messages while the kernel is stopped (removed from kernel 3.15)
		* Filtering incoming packets and decoding UDP headers
		* Getting MAC address and IP address of the remote host

	kgdboe does NOT use the rx_hook API from netpoll as it has been removed in kernel 3.15 and
	was not fully usable before (e.g. did not provide a possibility to record remote MAC address).
*/

static rx_handler_result_t netpoll_wrapper_rx_handler(struct sk_buff **pskb);

static void hook_receive_skb(void *pContext, struct sk_buff *pSkb);

struct netpoll_wrapper *netpoll_wrapper_create(const char *pDeviceName, int localPort, const char *pOptionalLocalIp)
{
	struct net_device *pDevice;
	struct netpoll_wrapper *pResult;
	int localIp;
	int err;

	if (!pDeviceName || !localPort)
	{
		printk(KERN_ERR "kgdboe: cannot create a netpoll wrapper without a device name\n");
		return NULL;
	}

	pDevice = dev_get_by_name(&init_net, pDeviceName);
	if (!pDevice)
	{
		printk(KERN_ERR "kgdboe: Cannot find network device by name: %s\n", pDeviceName);
		return NULL;
	}


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

	pResult = (struct netpoll_wrapper *)kmalloc(sizeof(struct netpoll_wrapper), GFP_KERNEL);
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

	rtnl_lock();
	err = netdev_rx_handler_register(pDevice, netpoll_wrapper_rx_handler, pResult);
	rtnl_unlock();
	if (err < 0)
	{
		printk(KERN_ERR "kgdboe: Failed to register rx handler for %s, code %d\n", pDeviceName, err);
		netpoll_wrapper_free(pResult);
		return NULL;
	}

	register_tracepoint_wrapper(netif_receive_skb, hook_receive_skb, pResult);
	pResult->tracepoint_registered = true;

	pResult->pDeviceWithHandler = pDevice;

	strncpy(pResult->netpoll_obj.dev_name, pDeviceName, sizeof(pResult->netpoll_obj.dev_name));
	pResult->netpoll_obj.name = "kgdboe";
	pResult->netpoll_obj.local_port = localPort;
	memset(pResult->netpoll_obj.remote_mac, 0xFF, sizeof(pResult->netpoll_obj.remote_mac));

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
		if (pWrapper->tracepoint_registered)
			unregister_tracepoint_wrapper(netif_receive_skb, hook_receive_skb, pWrapper);
		if (pWrapper->netpoll_initialized)
			netpoll_cleanup(&pWrapper->netpoll_obj);
		if (pWrapper->pDeviceWithHandler)
		{
			rtnl_lock();
			netdev_rx_handler_unregister(pWrapper->pDeviceWithHandler);
			rtnl_unlock();
		}
		kfree(pWrapper);
	}
}

#include <linux/module.h>
/*
	In case of problems with ARP you can enable this setting and send gdb UDP packets to 255.255.255.255:<port>.
	Note that ALL machines in your network will receive them, so use different ports if you have more than 1 machine.
	You will also need to write a small tool that will forward the repiles back to GDB (it will ignore packets coming
	from the actual remote IP).
*/
static int support_broadcast_packets = 0;
module_param(support_broadcast_packets, int, 0664);

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
		return;	//This ARP request is not for our IP address

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

static bool parse_udp_packet(struct sk_buff *skb, struct iphdr **piph, struct udphdr **puh, int *pulen)
{
	int proto, len, ulen;
	struct iphdr *iph;
	struct udphdr *uh;

	proto = ntohs(eth_hdr(skb)->h_proto);
	if (proto != ETH_P_IP)
		return false;
	if (skb->pkt_type == PACKET_OTHERHOST)
		return false;
	if (skb_shared(skb))
		return false;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return false;
	iph = (struct iphdr *)skb->data;
	if (iph->ihl < 5 || iph->version != 4)
		return false;
	if (!pskb_may_pull(skb, iph->ihl * 4))
		return false;
	iph = (struct iphdr *)skb->data;
	if (ip_fast_csum((u8 *)iph, iph->ihl) != 0)
		return false;

	len = ntohs(iph->tot_len);
	if (skb->len < len || len < iph->ihl * 4)
		return false;

	/*
	* Our transport medium may have padded the buffer out.
	* Now We trim to the true length of the frame.
	*/
	if (pskb_trim_rcsum(skb, len))
		return false;

	iph = (struct iphdr *)skb->data;
	if (iph->protocol != IPPROTO_UDP)
		return false;

	len -= iph->ihl * 4;
	uh = (struct udphdr *)(((char *)iph) + iph->ihl * 4);
	ulen = ntohs(uh->len);

	if (ulen != len)
		return false;

	*piph = iph;
	*puh = uh;
	*pulen = ulen;

	return true;
}

//We need this function in addition to netpoll_wrapper_rx_handler() because pre-3.15 kernel versions 
//will not call the rx handler for the packets matching the IP/port of our netpoll objects (expecting them
//to be handled in rx_hook that we don't use because it provides no way of reading the MAC address).
static void hook_receive_skb(void *pContext, struct sk_buff *skb)
{
	int ulen;
	struct iphdr *iph;
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

	if (!parse_udp_packet(skb, &iph, &uh, &ulen))
		return;

	if (pWrapper->netpoll_obj.local_port && pWrapper->netpoll_obj.local_port == ntohs(uh->dest))
	{
		if ((ip_addr_as_int(pWrapper->netpoll_obj.local_ip) && ip_addr_as_int(pWrapper->netpoll_obj.local_ip) == iph->daddr) ||
			(support_broadcast_packets && iph->daddr == 0xffffffff))
		{
			pWrapper->netpoll_obj.remote_port = ntohs(uh->source);
			ip_addr_as_int(pWrapper->netpoll_obj.remote_ip) = iph->saddr;
			memcpy(pWrapper->netpoll_obj.remote_mac, eth_hdr(skb)->h_source, sizeof(pWrapper->netpoll_obj.remote_mac));

			if (pWrapper->pReceiveHandler)
				pWrapper->pReceiveHandler(pWrapper, ntohs(uh->source), (char *)(uh + 1), ulen - sizeof(struct udphdr));
		}
	}
}

//We need this in addition to hook_receive_skb() because not dropping a packet
//while stopped in gdb may invoke some processing functions from the network stack that
//would like to take resources owned by other cores (that are now stopped).
//We don't want to guess and pre-acquire those resources, so we just drop all packets while stopped in kgdb.
static rx_handler_result_t netpoll_wrapper_rx_handler(struct sk_buff **pskb)
{
	struct netpoll_wrapper *pWrapper = (struct netpoll_wrapper *)(*pskb)->dev->rx_handler_data;
	bool drop = false;
	BUG_ON(!pWrapper);

	if (pWrapper->drop_other_packets)
		drop = true;
	else
	{
		int ulen;
		struct iphdr *iph;
		struct udphdr *uh;

		if (parse_udp_packet(*pskb, &iph, &uh, &ulen))
		{
			if (pWrapper->netpoll_obj.local_port && pWrapper->netpoll_obj.local_port == ntohs(uh->dest) && (ip_addr_as_int(pWrapper->netpoll_obj.local_ip) && ip_addr_as_int(pWrapper->netpoll_obj.local_ip) == iph->daddr))
			{
				//Otherwise Linux itself may handle it, reply with ICMP 'port not available' and force GDB to disconnect.
				drop = true;
			}
		}
	}

	if (drop)
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

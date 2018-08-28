/*
 * arp.c
 *
 *  Created on: Aug 28, 2018
 *      Author: anlang
 */
#include <linux/if_arp.h>
#include "common/skb_buff.h"

//计算arp头部长度
static inline unsigned int arp_hdr_len() {
	/* ARP header, plus 2 device addresses, plus 2 IP addresses. */
	return sizeof(struct arphdr) + (ETH_ALEN + sizeof(u32)) * 2;
}
//收到arp包，并开始处理
static int arp_rcv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig_dev) {
	const struct arphdr *arp;

	/* ARP header, plus 2 device addresses, plus 2 IP addresses.  */
	//不足arp协议所需字段，丢包
	if (!pskb_may_pull(skb, arp_hdr_len()))
		goto freeskb;

	//偏移到arp头部
	arp = arp_hdr(skb);

	//当前设备不支持此类型arp报文（以太网只支持硬件长度为6，协议地址长度为4的arp)
	if (arp->ar_hln != dev->addr_len || arp->ar_pln != 4)
		goto freeskb;

	//当skb的cb置为空
	memset(NEIGH_CB(skb), 0, sizeof(struct neighbour_cb));

	//走ARP钩子点,ARP_IN
	return NF_HOOK(NFPROTO_ARP, NF_ARP_IN, dev_net(dev), NULL, skb, dev, NULL,
			arp_process);

	consumeskb: consume_skb(skb);
	return NET_RX_SUCCESS;
	freeskb: kfree_skb(skb);
	out_of_mem: return NET_RX_DROP;
}

int arp_rcv(struct skb_buff *skb) {

	return 0;
}

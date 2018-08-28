/*
 * skb_buf.h
 *
 *  Created on: Aug 28, 2018
 *      Author: langan
 */

#ifndef SKB_BUFF_H_
#define SKB_BUFF_H_

#include "rte_mbuf.h"

struct sk_buff {
	struct rte_mbuf mbuf;
};

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{
	if (likely(len <= rte_pktmbuf_data_len(&skb->mbuf)))
		return 1;
	if (unlikely(len > rte_pktmbuf_pkt_len(&skb->mbuf)))
		//需要的长度比数据长度还要长，肯定搞不定
		return 0;
	//暂时不实现线性化
	return __pskb_pull_tail(skb, len - skb_headlen(skb)) != NULL;
}

#endif /* SKB_BUFF_H_ */

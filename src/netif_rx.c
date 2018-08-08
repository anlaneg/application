/*
 * netif_rx.c
 *
 *  Created on: Aug 8, 2018
 *      Author: langan
 */
#include <stdio.h>

#include "rte_ether.h"
#include "rte_eal.h"


#include "netif_rx.h"

int netif_rx_mbuf(struct rte_mbuf *mbuf)
{
	struct ether_hdr*hdr = rte_pktmbuf_mtod(mbuf,struct ether_hdr*);
	printf("ether_type=0X%X\n",rte_be_to_cpu_16(hdr->ether_type));
	return 0;
}

/*
 * nl_local_arp.h
 *
 *  Created on: Aug 24, 2018
 *      Author: anlang
 */

#ifndef NL_LOCAL_ARP_H_
#define NL_LOCAL_ARP_H_

struct rtnl_neigh;
struct event_base;
struct nl_addr;
int nl_arp_table_init(struct event_base*base);
void nl_arp_table_destory();
int nl_arp_table_reset();
int nl_arp_table_foreach(int (*func)(struct rtnl_neigh*, void*), void*args);
void nl_arp_table_show();
int nl_arp_table_lookup(struct nl_addr *dst, char*mac);
#endif /* NL_LOCAL_ARP_H_ */

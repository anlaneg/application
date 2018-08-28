/*
 * nl_local_arp.h
 *
 *  Created on: Aug 24, 2018
 *      Author: anlang
 */

#ifndef KARP_TABLE_H_
#define KARP_TABLE_H_

struct rtnl_neigh;
struct event_base;
struct nl_addr;
int karp_table_init(struct event_base*base);
void karp_table_destory();
int karp_table_reset();
int karp_table_foreach(int (*func)(struct rtnl_neigh*, void*), void*args);
void karp_table_show();
int karp_table_lookup(struct nl_addr *dst, char*mac);
#endif /* KARP_TABLE_H_ */

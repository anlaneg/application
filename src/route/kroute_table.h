/*
 * nl_local_route.h
 *
 *  Created on: Aug 27, 2018
 *      Author: anlang
 */

#ifndef KROUTE_TABLE_H_
#define KROUTE_TABLE_H_

struct nl_object;
struct event_base;
int kroute_table_foreach(int (*func)(struct nl_object *, void*), void*args);
int kroute_table_reset();
int kroute_table_init(struct event_base*base);
void kroute_table_destory();
void kroute_table_show(void);
int kroute_table_lookup_ipv4(uint32_t dst, uint32_t* gw);

#endif /* KROUTE_TABLE_H_ */

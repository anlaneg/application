/*
 * nl_local_route.h
 *
 *  Created on: Aug 27, 2018
 *      Author: anlang
 */

#ifndef NL_LOCAL_ROUTE_H_
#define NL_LOCAL_ROUTE_H_

struct nl_object;
struct event_base;
int nl_route_table_foreach(int (*func)(struct nl_object *, void*), void*args);
int nl_route_table_reset();
int nl_route_table_init(struct event_base*base);
void nl_route_table_destory();
void nl_route_table_show(void);
int nl_route_table_lookup_ipv4(uint32_t dst, uint32_t* gw);

#endif /* NL_LOCAL_ROUTE_H_ */

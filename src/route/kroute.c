/*
 * nl-route.c
 *
 *  Created on: Aug 23, 2018
 *      Author: anlang
 */
#include <stddef.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include "netlink/route/route.h"
#include "netlink/route/nexthop.h"
#include "netlink/addr.h"
#include "netlink/cache.h"

#include "event2/event.h"
#include "event2/event_struct.h"

#include "common/log.h"
#include "netlink/nl_socket.h"

#include "common/die.h"
#include "kroute_table.h"
#include "common/rcu.h"

static struct nl_sock *s_sock = NULL;
static struct nl_cache* s_cache = NULL;

static inline void free_nl_cache(struct nl_cache* cache) {
	if (cache) {
		nl_cache_mngt_unprovide(cache);
		//nl_cache_mngt_unprovide中有一个bug,没有调用nl_cache_put函数
		//这里手动调用一遍
		nl_cache_put(cache);
		nl_cache_free(cache);
	}
}

int kroute_table_reset() {
	struct nl_cache* cache = NULL;
	struct nl_cache* old = NULL;
	//如果指定为AF_UNSPEC则同时包含ipv4,ipv6及其它
	if (rtnl_route_alloc_cache(s_sock,/*AF_UNSPEC*/AF_INET, 0, &cache)) {
		return -1;
	}

	//生成全局可用的cache表
	nl_cache_mngt_provide(cache);

	old = s_cache;
	s_cache = cache;
	rcu_wait();
	free_nl_cache(old);
	return 0;
}

int kroute_table_foreach(int (*func)(struct nl_object *, void*), void*args) {
	int ret;
	struct nl_object*obj;
	for (obj = nl_cache_get_first(s_cache); obj != NULL; obj =
			nl_cache_get_next(obj)) {
		nl_object_get(obj);
		ret = func(obj, args);
		nl_object_put(obj);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}
struct lookup_args {
	uint32_t dst;
	uint32_t out_gw;
	int32_t prelen;
};

static inline uint32_t ip_mask_get(int prefix_len) {
	assert(prefix_len >= 0 && prefix_len <= 32);
	return (uint32_t)((1UL << prefix_len) - 1);
}
static int route_ipv4_lookup(struct nl_object *obj, void*p) {
	struct rtnl_route *route = (struct rtnl_route *) obj;
	struct lookup_args*args = (struct lookup_args*) p;
	uint8_t family = rtnl_route_get_family(route);
	uint32_t table = rtnl_route_get_table(route);
	uint8_t type = rtnl_route_get_type(route);
	struct nl_addr* dst = rtnl_route_get_dst(route);
	struct rtnl_nexthop* nexthop = rtnl_route_nexthop_n(route, 0);
	if (table != RT_TABLE_MAIN || type != RTN_UNICAST || !dst || !nexthop) {
		return 0;
	}
	unsigned int prefix_len = nl_addr_get_prefixlen(dst);
	void* addr = nl_addr_get_binary_addr(dst);
	struct nl_addr*gw = rtnl_route_nh_get_gateway(nexthop);
	if (family == AF_INET) {

		if (args->prelen < (int) prefix_len) {
			//printf("prefix_len(0)=%X,prefix_len(32)=%X,prefix_len(4)=%X \n",ip_mask_get(0),ip_mask_get(32),ip_mask_get(4));
			if ((args->dst & ip_mask_get(prefix_len)) == (*(uint32_t*) addr)) {
				args->prelen = prefix_len;
				args->out_gw =
						gw ? (*(uint32_t*) nl_addr_get_binary_addr(gw)) : 0;
			}
		}
	}
	return 0;
}

int kroute_table_lookup_ipv4(uint32_t dst, uint32_t* gw) {
	assert(gw);
#define INVALID_PREFIX_LEN -1
	struct lookup_args arg = { .dst = dst, .out_gw = *gw, .prelen =
	INVALID_PREFIX_LEN };
	if (kroute_table_foreach(route_ipv4_lookup, &arg)) {
		return 0;
	}
	if (arg.prelen == INVALID_PREFIX_LEN) {
		return -1;
	}
	*gw = arg.out_gw;
	return 0;
}

void kroute_table_destory() {
	free_nl_cache(s_cache);
	s_cache = NULL;
	nl_socket_free(s_sock);
	s_sock = NULL;
}

static void route_monitor_event_process(evutil_socket_t fd, short event,
		void*arg) {
	LOG("route table changed\n");
	nl_sock_mcmessage_process(fd,event,arg);
	if (kroute_table_reset()) {
#if 0
		struct event* myself = (struct event*) arg;
		event_del(myself);
		if (nl_arp_table_monitor(myself->ev_base)) {
			ERROR("****ARP table monitor fail*****!\n");
		}
#else
		ERROR("****route table monitor fail*****!\n");
		DIE();
#endif
	}
	kroute_table_show();
	return;
}

static int kroute_table_monitor(struct event_base*base) {
	struct event* read_event;

	static struct nl_sock * socket = NULL;
	if (socket) {
		nl_socket_free(socket);
	}

	socket = nl_socket_alloc();
	if (!socket) {
		goto OUT;
	}

	if (nl_connect(socket, NETLINK_ROUTE)) {
		goto FREE_SOCK;
	}

	if (nl_sock_join_mcgroup(nl_socket_get_fd(socket), RTNLGRP_IPV4_ROUTE)) {
		goto FREE_SOCK;
	}

	//read request event
	read_event = event_new(base, nl_socket_get_fd(socket), EV_READ | EV_PERSIST,
			route_monitor_event_process, event_self_cbarg());

	if (!read_event) {
		ERROR("alloc read event fail!\n");
		goto FREE_SOCK;
	}

	if (event_add(read_event, NULL)) {
		goto FREE_EVENT;
	}

	if (kroute_table_reset()) {
		goto DEL_EVENT;
	}

	return 0;

	DEL_EVENT: {
		event_del(read_event);
	}
	FREE_EVENT: {
		event_free(read_event);
	}
	FREE_SOCK: {
		nl_socket_free(s_sock);
		s_sock = NULL;
	}
	OUT: {
		return -1;
	}
}

int kroute_table_init(struct event_base*base) {
	s_sock = nl_socket_alloc();
	if (!s_sock) {
		goto OUT;
	}

	if (nl_connect(s_sock, NETLINK_ROUTE)) {
		goto FREE_SOCK;
	}

	//TODO bind s_sock->fd to libevent
	if (kroute_table_monitor(base)) {
		goto FREE_SOCK;
	}
	return 0;

#if 0
	FREE_CACHE: {
		nl_cache_free(s_cache);
		s_cache = NULL;
	}
#endif
	FREE_SOCK: {
		nl_socket_free(s_sock);
		s_sock = NULL;
	}
	OUT: {
		return -1;
	}
}


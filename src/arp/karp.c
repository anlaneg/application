/*
 * nl-arp.c
 *
 *  Created on: Aug 23, 2018
 *      Author: anlang
 */
#include <stddef.h>
#include <assert.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include "netlink/route/neighbour.h"
#include "netlink/addr.h"
#include "netlink/cache.h"

#include "event2/event.h"
#include "event2/event_struct.h"

#include "common/log.h"
#include "netlink/nl_socket.h"
#include "common/die.h"
#include "karp_table.h"
#include "common/rcu.h"

static struct nl_sock *s_sock = NULL;
static struct nl_cache* s_cache = NULL;


static inline void free_nl_cache(struct nl_cache* cache)
{
	nl_cache_mngt_unprovide(cache);
	cache = NULL;
}
int karp_table_reset() {
	struct nl_cache* cache=NULL;
	struct nl_cache* old = NULL;
	if (rtnl_neigh_alloc_cache(s_sock, &cache)) {
		return -1;
	}
	//生成全局可用的邻居表
	nl_cache_mngt_provide(cache);

	old = s_cache;
	s_cache = cache;
	rcu_wait();
	free_nl_cache(old);
	return 0;
}

int karp_table_foreach(int (*func)(struct rtnl_neigh*, void*), void*args) {
	int ret;

	struct nl_object * obj;
	for (obj = nl_cache_get_first(s_cache); obj != NULL; obj =
			nl_cache_get_next(obj)) {
		nl_object_get(obj);
		ret = func((struct rtnl_neigh *) obj, args);
		nl_object_put(obj);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

struct arp_lookup_args {
	struct nl_addr*dst;
	char*mac;
};

int arp_table_lookup_cmp(struct rtnl_neigh*neigh, void*args) {
	struct nl_addr* dst = ((struct arp_lookup_args*) args)->dst;
	char* mac = ((struct arp_lookup_args*) args)->mac;
	//注：这里取掉了对ifindex的匹配，但这样会在ip地址一致的情况下，选错mac
	/*neigh->n_ifindex == ifindex &&*/
	int n_state = rtnl_neigh_get_state(neigh);
	struct nl_addr* n_dst = rtnl_neigh_get_dst(neigh);
	struct nl_addr * n_lladdr = rtnl_neigh_get_lladdr(neigh);

	if ((n_state != -1 && n_dst && n_lladdr)
			&& (n_state & (NUD_REACHABLE | NUD_PERMANENT))
			&& !nl_addr_cmp(n_dst, dst)) {
		if (nl_addr_get_len(n_lladdr) == 6) {
			memcpy(mac, (char*) nl_addr_get_binary_addr(n_lladdr), 6);
			return 1;
		}
	}
	return 0;
}

int karp_table_lookup(struct nl_addr *dst, char*mac) {
	struct arp_lookup_args args = { .dst = dst, .mac = mac };
	if (karp_table_foreach(arp_table_lookup_cmp, &args)) {
		return 0;
	}
	return -1;
}

static void arp_monitor_event_process(evutil_socket_t fd, short event, void*arg) {
	LOG("arp table changed\n");
	//nl_sock_mcmessage_process(fd,event,arg);
	if (karp_table_reset()) {
#if 0
		struct event* myself = (struct event*) arg;
		event_del(myself);
		if (karp_table_monitor(myself->ev_base)) {
			ERROR("****ARP table monitor fail*****!\n");
		}
#else
		ERROR("****ARP table monitor fail*****!\n");
		DIE();
#endif
	}
	karp_table_show();
	return;
}

static int karp_table_monitor(struct event_base*base) {
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

	if (nl_sock_join_mcgroup(nl_socket_get_fd(socket), RTNLGRP_NEIGH)) {
		goto FREE_SOCK;
	}

	//read request event
	read_event = event_new(base, nl_socket_get_fd(socket), EV_READ | EV_PERSIST,
			arp_monitor_event_process, event_self_cbarg());

	if (!read_event) {
		ERROR("alloc read event fail!\n");
		goto FREE_SOCK;
	}

	if (event_add(read_event, NULL)) {
		goto FREE_EVENT;
	}

	if (karp_table_reset()) {
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

int karp_table_init(struct event_base*base) {
	s_sock = nl_socket_alloc();
	if (!s_sock) {
		goto OUT;
	}

	if (nl_connect(s_sock, NETLINK_ROUTE)) {
		goto FREE_SOCK;
	}

	if (karp_table_monitor(base)) {
		goto FREE_SOCK;
	}

	return 0;

	FREE_SOCK: {
		nl_socket_free(s_sock);
		s_sock = NULL;
	}
	OUT: {
		return -1;
	}
}

void karp_table_destory() {
	free_nl_cache(s_cache);
	nl_socket_free(s_sock);
	s_sock = NULL;
}

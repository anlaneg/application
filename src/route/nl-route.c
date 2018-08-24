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
static struct nl_sock *s_sock = NULL;
static struct nl_cache* s_cache = NULL;

int nl_route_table_reset() {
	return -1;
}

int nl_route_table_foreach(int (*func)(struct nl_object *, void*), void*args) {
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

static inline uint32_t ip_mask_get(int prefix_len)
{
	assert(prefix_len >=0 && prefix_len <= 32);
	return (uint32_t)((1UL<<prefix_len)-1);
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

int nl_route_table_lookup_ipv4(uint32_t dst, uint32_t* gw) {
	assert(gw);
#define INVALID_PREFIX_LEN -1
	struct lookup_args arg = { .dst = dst, .out_gw = *gw, .prelen =
	INVALID_PREFIX_LEN };
	if (nl_route_table_foreach(route_ipv4_lookup, &arg)) {
		return 0;
	}
	if (arg.prelen == INVALID_PREFIX_LEN) {
		return -1;
	}
	*gw = arg.out_gw;
	return 0;
}

static inline char* print_ip1(void*data) {
	int32_t ip = *((int32_t*) data);
	static char ipstr[16]; //"255.255.255.255";
	unsigned char*byte = (unsigned char*) &ip;
	snprintf(ipstr, 16, "%u.%u.%u.%u", byte[0], byte[1], byte[2], byte[3]);
	ipstr[15] = '\0';
	return ipstr;
}

static inline int route_print(struct nl_object* obj, void*args) {
	struct rtnl_route *route = (struct rtnl_route *) obj;
	uint8_t family = rtnl_route_get_family(route);
	uint32_t table = rtnl_route_get_table(route);
	uint8_t type = rtnl_route_get_type(route);
	struct nl_addr* dst = rtnl_route_get_dst(route);
	struct rtnl_nexthop* nexthop = rtnl_route_nexthop_n(route, 0);
	if (table != RT_TABLE_MAIN || type != RTN_UNICAST || !dst || !nexthop) {
		return 0;
	}
	struct nl_addr*gw = rtnl_route_nh_get_gateway(nexthop);
	if (family == AF_INET) {
		printf("%s/%d ", print_ip1(nl_addr_get_binary_addr(dst)),
				nl_addr_get_prefixlen(dst));
		printf("gateway %s port %d\n",
				gw ? print_ip1(nl_addr_get_binary_addr(gw)) : "0.0.0.0",
				rtnl_route_nh_get_ifindex(nexthop));
	} else if (family == AF_INET6) {
		char buf[128];
		inet_ntop(AF_INET6, nl_addr_get_binary_addr(dst), buf, sizeof(buf));
		printf("%s/%d ", buf, nl_addr_get_prefixlen(dst));
		inet_ntop(AF_INET6, gw ? nl_addr_get_binary_addr(gw) : "0.0.0.0", buf,
				sizeof(buf));
		printf("gateway %s port %d\n", buf, rtnl_route_nh_get_ifindex(nexthop));
	} else {
		//skip
	}
	return 0;
}

int nl_route_table_list() {
	nl_route_table_foreach(route_print, NULL);
	return 0;
}

int nl_route_tablle_destory() {
	return -1;
}

int nl_route_table_init() {
	s_sock = nl_socket_alloc();
	if (!s_sock) {
		goto OUT;
	}

	if (nl_connect(s_sock, NETLINK_ROUTE)) {
		goto FREE_SOCK;
	}

	//TODO bind s_sock->fd to libevent
	//如果指定为AF_UNSPEC则同时包含ipv4,ipv6及其它
	if (rtnl_route_alloc_cache(s_sock,/*AF_UNSPEC*/AF_INET, 0, &s_cache)) {
		goto FREE_SOCK;
	}

	//生成全局可用的邻居表
	nl_cache_mngt_provide(s_cache);

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

int main(int argc, char**argv) {
	uint32_t ips[] = { 0x0A0A0A0A, 0x09090909, 0x0a00000a, };
	int idx = 0;
	if (nl_route_table_init()) {
		return 1;
	}
	nl_route_table_list();
	for (idx = 0; idx < sizeof(ips) / sizeof(uint32_t); ++idx) {
		uint32_t dst;
		if (nl_route_table_lookup_ipv4(ips[idx], &dst)) {
			printf("to %s unreachable\n", print_ip1(&ips[idx]));
		} else {
			printf("via %s to ", print_ip1(&dst));
			printf("%s\n", print_ip1(&ips[idx]));
		}
	}

	return 0;
}


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

static struct nl_sock *s_sock = NULL;
static struct nl_cache* s_cache = NULL;

int nl_arp_table_reset() {
	return -1;
}

int nl_arp_table_foreach(int (*func)(struct rtnl_neigh*, void*), void*args) {
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

	if ((n_state != -1 && n_dst && n_lladdr) && (n_state & (NUD_REACHABLE|NUD_PERMANENT)) && !nl_addr_cmp(n_dst, dst)) {
		if (nl_addr_get_len(n_lladdr) == 6) {
			memcpy(mac, (char*) nl_addr_get_binary_addr(n_lladdr), 6);
			return 1;
		}
	}
	return 0;
}

int nl_arp_table_lookup(struct nl_addr *dst, char*mac) {
	struct arp_lookup_args args = { .dst = dst, .mac = mac };
	if (nl_arp_table_foreach(arp_table_lookup_cmp, &args)) {
		return 0;
	}
	return -1;
}

static inline char* print_ip1(void*data) {
	int32_t ip = *((int32_t*) data);
	static char ipstr[16]; //"255.255.255.255";
	unsigned char*byte = (unsigned char*) &ip;
	snprintf(ipstr, 16, "%u.%u.%u.%u", byte[0], byte[1], byte[2], byte[3]);
	ipstr[15] = '\0';
	return ipstr;
}

static inline char* print_mac1(void*data) {
	unsigned char*byte = (unsigned char*) data;
	static char macstr[18]; //AA:BB:CC:DD:EE:FF
	//char*byte = mac;
	snprintf(macstr, 18, "%02X:%02X:%02X:%02X:%02X:%02X", byte[0], byte[1],
			byte[2], byte[3], byte[4], byte[5]);
	macstr[17] = '\0';
	return macstr;
}

static inline char* print_nl_addr(struct nl_addr* addr)
{
	int len = nl_addr_get_len(addr);
	switch(len)
	{
	case 4:
		return print_ip1(nl_addr_get_binary_addr(addr));
	case 6:
		return print_mac1(nl_addr_get_binary_addr(addr));
	default:
		return "length is other";
	}
}

static int neigh_print(struct rtnl_neigh*neigh, void*args) {
	int n_state = rtnl_neigh_get_state(neigh);
	struct nl_addr* n_dst = rtnl_neigh_get_dst(neigh);
	struct nl_addr * n_lladdr = rtnl_neigh_get_lladdr(neigh);
	if(n_dst && n_lladdr)
	{
		printf("state=%0X",n_state);
		printf(",ip addr:%s",print_nl_addr(n_dst));
		printf(",netlink addr:%s\n",print_nl_addr(n_lladdr));
	}
	//struct nl_dump_params params = { .dp_type = NL_DUMP_LINE, .dp_fd = stdout, };
	//dump_from_ops((struct nl_object *) neigh, &params);
	return 0;
}

void nl_arp_table_list() {
	nl_arp_table_foreach(neigh_print, NULL);
}

int nl_arp_table_monitor() {
	return -1;
}

int nl_local_arp_table_init() {
	s_sock = nl_socket_alloc();
	if (!s_sock) {
		goto OUT;
	}

	if (nl_connect(s_sock, NETLINK_ROUTE)) {
		goto FREE_SOCK;
	}

	//TODO bind s_sock->fd to libevent

	if (rtnl_neigh_alloc_cache(s_sock, &s_cache)) {
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

void nl_local_arp_table_destory() {
	nl_cache_mngt_unprovide(s_cache);
	s_cache = NULL;
	nl_socket_free(s_sock);
	s_sock = NULL;
}

int main(int argc, char**argv) {
	char mac[6];
	char dstip[4] = { 10, 10, 10, 8 };
	struct nl_addr* dst;

	if(nl_arp_table_init())
	{
		return 1;
	}

	if (!(dst = nl_addr_build(AF_INET, dstip, 4))) {
		return 1;
	}

	nl_arp_table_list();
	if (nl_arp_table_lookup(dst, mac)) {
		return 1;
	}
	printf("%s\n",print_mac1(mac));
	return 0;
}

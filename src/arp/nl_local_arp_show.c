/*
 * nl_local_arp_show.c
 *
 *  Created on: Aug 27, 2018
 *      Author: anlang
 */

#include <stddef.h>
#include <assert.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include "netlink/route/neighbour.h"
#include "netlink/addr.h"
#include "netlink/cache.h"
#include "nl_local_arp.h"

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

static inline char* print_nl_addr(struct nl_addr* addr) {
	int len = nl_addr_get_len(addr);
	switch (len) {
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
	if (n_dst && n_lladdr && (n_state & (NUD_REACHABLE | NUD_PERMANENT))) {
		printf("state=%0X", n_state);
		printf(",ip addr:%s", print_nl_addr(n_dst));
		printf(",netlink addr:%s\n", print_nl_addr(n_lladdr));
	}
	//struct nl_dump_params params = { .dp_type = NL_DUMP_LINE, .dp_fd = stdout, };
	//dump_from_ops((struct nl_object *) neigh, &params);
	return 0;
}

void nl_arp_table_show() {
	nl_arp_table_foreach(neigh_print, NULL);
}

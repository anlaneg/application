/*
 * nl_local_route_show.c
 *
 *  Created on: Aug 27, 2018
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

#include "nl_local_route.h"

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

void nl_route_table_show(void) {
	nl_route_table_foreach(route_print, NULL);
}

/*
 * ctrl.c
 *
 *  Created on: Aug 24, 2018
 *      Author: anlang
 */
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <linux/netlink.h>
#include <inttypes.h>

#include "event2/event.h"
#include "event2/event_struct.h"

#include "common/log.h"
#include "netlink/nl_socket.h"

#include "arp/nl_local_arp.h"
#include "route/nl_local_route.h"

int main(int argc, char**argv) {

	int ret = 1;
	struct event_base*base;
	base = event_base_new();
	if (!base) {
		ERROR("alloc event base fail!\n");
		goto OUT;
	}

	if (nl_arp_table_init(base)) {
		ERROR("local arp table init fail!\n");
		goto FREE_BASE;
	}

	if (nl_route_table_init(base)) {
		ERROR("local route table init fail!\n");
		goto DESTROY_ARP_TABLE;
	}

	event_base_dispatch(base);
	ret = 0;

	nl_route_table_destory();
	DESTROY_ARP_TABLE: {
		nl_arp_table_destory();
	}
	FREE_BASE: {
		event_base_free(base);
	}
	OUT: {
		return ret;
	}
}

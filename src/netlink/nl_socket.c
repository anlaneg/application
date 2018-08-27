/*
 * nl_socket.c
 *
 *  Created on: Aug 24, 2018
 *      Author: anlang
 */
#include <errno.h>
#include <error.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/types.h>

#include "common/log.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/* Tries to add 'sock' as a listener for 'multicast_group'.  Returns 0 if
 * successful, otherwise a positive errno value.
 *
 * A socket that is subscribed to a multicast group that receives asynchronous
 * notifications must not be used for Netlink transactions or dumps, because
 * transactions and dumps can cause notifications to be lost.
 *
 * Multicast group numbers are always positive.
 *
 * It is not an error to attempt to join a multicast group to which a socket
 * already belongs. */
int nl_sock_join_mcgroup(int fd, unsigned int multicast_group) {
	if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			&multicast_group, sizeof multicast_group) < 0)
	{
		WARN("could not join multicast group %u (%s)", multicast_group,
				strerror(errno));
		return errno;
	}
	return 0;
}

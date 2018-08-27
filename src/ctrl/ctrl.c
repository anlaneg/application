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
#include "common/private.h"
#include "common/ofpbuf.h"
#include "netlink/nl_socket.h"
#include "netlink/route/neighbour.h"
#include "netlink/addr.h"
#include "netlink/cache.h"

static inline int nl_sock_recv(int fd, struct ofpbuf *buf,
		int *nsid, bool wait) {
	/* We can't accurately predict the size of the data to be received.  The
	 * caller is supposed to have allocated enough space in 'buf' to handle the
	 * "typical" case.  To handle exceptions, we make available enough space in
	 * 'tail' to allow Netlink messages to be up to 64 kB long (a reasonable
	 * figure since that's the maximum length of a Netlink attribute). */
	struct nlmsghdr *nlmsghdr;
	uint8_t tail[65536];
	struct iovec iov[2];
	struct msghdr msg;
	uint8_t msgctrl[64];
	//struct cmsghdr *cmsg;
	ssize_t retval;
	//int *ptr;
	int error;

	assert(buf->allocated >= sizeof *nlmsghdr);
	ofpbuf_clear(buf);

	iov[0].iov_base = buf->base;
	iov[0].iov_len = buf->allocated;
	iov[1].iov_base = tail;
	iov[1].iov_len = sizeof tail;

	memset(&msg, 0, sizeof msg);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_control = msgctrl;
	msg.msg_controllen = sizeof msgctrl;

	/* Receive a Netlink message from the kernel.
	 *
	 * This works around a kernel bug in which the kernel returns an error code
	 * as if it were the number of bytes read.  It doesn't actually modify
	 * anything in the receive buffer in that case, so we can initialize the
	 * Netlink header with an impossible message length and then, upon success,
	 * check whether it changed. */
	nlmsghdr = buf->base;
	do {
		nlmsghdr->nlmsg_len = UINT32_MAX;
#ifdef _WIN32
		DWORD bytes;
		if (!DeviceIoControl(sock->handle, sock->read_ioctl,
						NULL, 0, tail, sizeof tail, &bytes, NULL)) {
			lost_communication(GetLastError());
			VLOG_DBG_RL(&rl, "fatal driver failure in transact: %s",
					ovs_lasterror_to_string());
			retval = -1;
			/* XXX: Map to a more appropriate error. */
			errno = EINVAL;
		} else {
			retval = bytes;
			if (retval == 0) {
				retval = -1;
				errno = EAGAIN;
			} else {
				if (retval >= buf->allocated) {
					ofpbuf_reinit(buf, retval);
					nlmsghdr = buf->base;
					nlmsghdr->nlmsg_len = UINT32_MAX;
				}
				memcpy(buf->data, tail, retval);
				buf->size = retval;
			}
		}
#else
		//读取fd
		retval = recvmsg(fd, &msg, wait ? 0 : MSG_DONTWAIT);
#endif
		error = (retval < 0 ? errno : retval == 0 ? ECONNRESET /* not possible? */
		:
					nlmsghdr->nlmsg_len != UINT32_MAX ? 0 : retval);
	} while (error == EINTR);
	if (error) {
		if (error == ENOBUFS) {
			/* Socket receive buffer overflow dropped one or more messages that
			 * the kernel tried to send to us. */
			//COVERAGE_INC(netlink_overflow);
		}
		return error;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		//报文被截短，报错
		ERROR("truncated message (longer than %"PRIu64" bytes)",
				sizeof tail);
		return E2BIG;
	}

	if (retval < sizeof *nlmsghdr || nlmsghdr->nlmsg_len < sizeof *nlmsghdr
			|| nlmsghdr->nlmsg_len > retval) {
		ERROR("received invalid nlmsg (%"PRIu64" bytes < %"PRIu64")",
				retval, sizeof *nlmsghdr);
		return EPROTO;
	}
#ifndef _WIN32
	buf->size = MIN(retval, buf->allocated);
	if (retval > buf->allocated) {
		//COVERAGE_INC(netlink_recv_jumbo);
		ofpbuf_put(buf, tail, retval - buf->allocated);
	}
#endif

#if 0
	if (nsid) {
		/* The network namespace id from which the message was sent comes
		 * as ancillary data. For older kernels, this data is either not
		 * available or it might be -1, so it falls back to local network
		 * namespace (no id). Latest kernels return a valid ID only if
		 * available or nothing. */
		netnsid_set_local(nsid);
#ifndef _WIN32
		cmsg = CMSG_FIRSTHDR(&msg);
		while (cmsg != NULL) {
			if (cmsg->cmsg_level == SOL_NETLINK
					&& cmsg->cmsg_type == NETLINK_LISTEN_ALL_NSID) {
				ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
				netnsid_set(nsid, *ptr);
			}
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
				/* This is unexpected and unwanted, close all fds */
				int nfds;
				int i;
				nfds = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr)))
						/ sizeof(int);
				ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
				for (i = 0; i < nfds; i++) {
					VLOG_ERR_RL(&rl, "closing unexpected received fd (%d).",
							ptr[i]);
					close(ptr[i]);
				}
			}

			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}
#endif
	}
#endif

	//log_nlmsg(__func__, 0, buf->data, buf->size, sock->protocol);
	//COVERAGE_INC(netlink_received);

	return 0;
}

void nl_sock_mcmessage_process(evutil_socket_t listener, short event, void*arg) {
	for (;;) {
		uint64_t buf_stub[4096 / 8];
		struct ofpbuf buf;
		int error;

		ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
		//读取socket,收取数据
		error = nl_sock_recv(listener, &buf, NULL, false);
		if (!error) {
			//解析收取到的数据
			//这里直接处理为创建两个socket,这样就不用去做解析代码了。
#if 0
			int group = nln_ptr->parse(&buf, nln_ptr->change);
			if (group != 0) {
				nln_report(nln_ptr, nln_ptr->change, group);	//调用回调
			} else {
				WARN("unexpected netlink message contents");
				nln_report(nln_ptr, NULL, 0);
			}
#endif
			//XXX TODO
			ofpbuf_uninit(&buf);
		} else if (error == EAGAIN) {
			return;
		} else {
			if (error == ENOBUFS) {
#if 0
				/* The socket buffer might be full, there could be too many
				 * notifications, so it makes sense to call nln_report() */
				nln_report(nln_ptr, NULL, 0);
#endif
				//XXX TODO
				WARN("netlink receive buffer overflowed");
			} else {
				WARN("error reading netlink socket: %s", strerror(error));
			}
			return;
		}
	}
}
static int ctrl_event_loop(void) {
	struct event*listener_event;
	struct event_base*base;
	struct nl_sock * socket;

	base = event_base_new();
	if (!base) {
		ERROR("alloc event base fail!\n");
		goto OUT;
	}

	socket = nl_socket_alloc();
	if (!socket) {
		ERROR("alloc socket fail!\n");
		goto FREE_BASE;
	}

	if (nl_connect(socket, NETLINK_ROUTE)) {
		goto FREE_SOCKET;
	}

	//ipv4路由监控
	if (nl_sock_join_mcgroup(nl_socket_get_fd(socket), RTNLGRP_IPV4_ROUTE)) {
		goto FREE_SOCKET;
	}

	//arp表监控
	if (nl_sock_join_mcgroup(nl_socket_get_fd(socket), RTNLGRP_NEIGH)) {
		goto FREE_SOCKET;
	}

	listener_event = event_new(base, nl_socket_get_fd(socket),
	EV_READ | EV_PERSIST, nl_sock_mcmessage_process, (void*) base);
	if (!listener_event) {
		ERROR("alloc event fail!\n");
		goto FREE_SOCKET;
	}

	event_add(listener_event, NULL);
	event_base_dispatch(base);

	return 0;
	FREE_SOCKET: {
		nl_socket_free(socket);
	}
	FREE_BASE: {
		event_base_free(base);
	}
	OUT: {
		return -1;
	}
}

int main(int argc, char**argv) {
	ctrl_event_loop();
}

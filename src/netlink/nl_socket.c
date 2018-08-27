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
#include <inttypes.h>

#include "event2/event.h"
#include "event2/event_struct.h"

#include "common/log.h"
#include "common/private.h"
#include "common/ofpbuf.h"

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

static inline int nl_sock_recv(int fd, struct ofpbuf *buf, int *nsid, bool wait) {
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
		ERROR("truncated message (longer than %"PRIu64" bytes)", sizeof tail);
		return E2BIG;
	}

	if (retval < sizeof *nlmsghdr || nlmsghdr->nlmsg_len < sizeof *nlmsghdr
			|| nlmsghdr->nlmsg_len > retval) {
		ERROR("received invalid nlmsg (%"PRIu64" bytes < %"PRIu64")", retval,
				sizeof *nlmsghdr);
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

int nl_sock_mcmessage_process(evutil_socket_t listener, short event, void*arg) {
	uint64_t buf_stub[4096 / 8];
	struct ofpbuf buf;
	int error;

	ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
	//读取socket,收取数据
	error = nl_sock_recv(listener, &buf, NULL, false);
	if (!error) {
		//不解析收取到的数据
		ofpbuf_uninit(&buf);
		return 0;
	} else if (error == EAGAIN) {
		WARN("netlink receive buffer not ready");
		return -1;
	} else {
		if (error == ENOBUFS) {
			WARN("netlink receive buffer overflowed");
			return 0;
		} else {
			WARN("error reading netlink socket: %s", strerror(error));
		}
		return -1;
	}
}

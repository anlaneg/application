/*
 * route-sync.c
 *
 *  Created on: Aug 16, 2018
 *      Author: anlang
 */

#define VLOG_ERR(fmt,...) printf(fmt,##__VA_ARGS__)

int nl_sock_create(int protocol) {
	int fd;
	struct sockaddr_nl local, remote;
	//创建netlink socket
	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0) {
		VLOG_ERR("fcntl: %s", ovs_strerror(errno));
		return error;
	}
	/* Connect to kernel (pid 0) as remote address. */
	memset(&remote, 0, sizeof remote);
	remote.nl_family = AF_NETLINK;
	remote.nl_pid = 0;
	if (connect(fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
		VLOG_ERR("connect(0): %s", ovs_strerror(errno));
		goto error;
	}
	return fd;
	error: {
		return -1;
	}
}

int nl_sock_join_mcgroup(int fd, unsigned int multicast_group) {
	if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			&multicast_group, sizeof multicast_group) < 0) {
		VLOG_WARN("could not join multicast group %u (%s)", multicast_group,
				ovs_strerror(errno));
		return errno;
	}
	return 0;
}

static int
nl_sock_recv__(struct nl_sock *sock, struct ofpbuf *buf, int *nsid, bool wait)
{
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
    struct cmsghdr *cmsg;
    ssize_t retval;
    int *ptr;
    int error;

    ovs_assert(buf->allocated >= sizeof *nlmsghdr);
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
        //读取fd
        retval = recvmsg(sock->fd, &msg, wait ? 0 : MSG_DONTWAIT);
        error = (retval < 0 ? errno
                 : retval == 0 ? ECONNRESET /* not possible? */
                 : nlmsghdr->nlmsg_len != UINT32_MAX ? 0
                 : retval);
    } while (error == EINTR);
    if (error) {
        if (error == ENOBUFS) {
            /* Socket receive buffer overflow dropped one or more messages that
             * the kernel tried to send to us. */
            COVERAGE_INC(netlink_overflow);
        }
        return error;
    }

    if (msg.msg_flags & MSG_TRUNC) {
    	//报文被截短，报错
        VLOG_ERR_RL(&rl, "truncated message (longer than %"PRIuSIZE" bytes)",
                    sizeof tail);
        return E2BIG;
    }

    if (retval < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len < sizeof *nlmsghdr
        || nlmsghdr->nlmsg_len > retval) {
        VLOG_ERR_RL(&rl, "received invalid nlmsg (%"PRIuSIZE" bytes < %"PRIuSIZE")",
                    retval, sizeof *nlmsghdr);
        return EPROTO;
    }
#ifndef _WIN32
    buf->size = MIN(retval, buf->allocated);
    if (retval > buf->allocated) {
        COVERAGE_INC(netlink_recv_jumbo);
        ofpbuf_put(buf, tail, retval - buf->allocated);
    }
#endif

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
            if (cmsg->cmsg_level == SOL_SOCKET
                && cmsg->cmsg_type == SCM_RIGHTS) {
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

    log_nlmsg(__func__, 0, buf->data, buf->size, sock->protocol);
    COVERAGE_INC(netlink_received);

    return 0;
}

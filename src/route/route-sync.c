/*
 * route-sync.c
 *
 *  Created on: Aug 16, 2018
 *      Author: anlang
 */
#include <stdio.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <net/if.h>
#include <pthread.h>

#include "list.h"
#include "ofpbuf.h"
#include "netnsid.h"
#include "common.h"

#include "netlink.h"
#include "ovs-router.h"

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define ARRAY_SIZE(_x)  ((sizeof(_x))/sizeof (_x)[0])
#define ETH_ADDR_LEN           6

#define COVERAGE_INC(a)

typedef int nln_parse_func(struct ofpbuf *buf, void *change);
/* Function called to report netlink notifications.  'change' describes the
 * specific change filled out by an nln_parse_func.  It may be null if the
 * buffer of change information overflowed, in which case the function must
 * assume that everything may have changed. 'aux' is as specified in
 * nln_notifier_register(). */
typedef void nln_notify_func(const void *change, void *aux);

struct nl_sock {
	int fd;
	uint32_t next_seq;
	uint32_t pid;
	int protocol;
	//收取buffer
	unsigned int rcvbuf; /* Receive buffer size (SO_RCVBUF). */
};

struct nln {
	struct nl_sock *notify_sock; /* Netlink socket. */
	//记录所有需要通知的notifier
	struct ovs_list all_notifiers; /* All nln notifiers. */
	bool has_run; /* Guard for run and wait functions. */

	/* Passed in by nln_create(). */
	int protocol; /* Protocol passed to nl_sock_create(). */
	nln_parse_func *parse; /* Message parsing function. */
	void *change; /* Change passed to parse. */
};

/* Using this struct instead of a bare array makes an ethernet address field
 * assignable.  The size of the array is also part of the type, so it is easier
 * to deal with. */
struct eth_addr {
	union {
		uint8_t ea[6];
	//ovs_be16 be16[3];
	};
};

/* These functions are Linux specific, so they should be used directly only by
 * Linux-specific code. */

/* A digested version of an rtnetlink_link message sent down by the kernel to
 * indicate that a network device's status (link or address) has been changed.
 */
struct rtnetlink_change {
	/* Copied from struct nlmsghdr. */
	int nlmsg_type; /* e.g. RTM_NEWLINK, RTM_DELLINK. */

	/* Common attributes. */
	int if_index; /* Index of network device. */
	const char *ifname; /* Name of network device. */

	/* Network device link status. */
	int master_ifindex; /* Ifindex of datapath master (0 if none). */
	int mtu; /* Current MTU. */
	struct eth_addr mac;
	unsigned int ifi_flags; /* Flags of network device. */

	/* Network device address status. */
	/* xxx To be added when needed. */

	/* Link info. */
	const char *master; /* Kind of master (NULL if not master). */
	const char *slave; /* Kind of slave (NULL if not slave). */
};

struct nln_notifier {
	struct ovs_list node; /* In struct nln's 'all_notifiers' list. */
	struct nln *nln; /* Parent nln. */

	//监听那个组播组
	int multicast_group; /* Multicast group we listen on. */
	//收到通知时，回调此函数
	nln_notify_func *cb;
	void *aux;
};

//主要是对linux kernel的路由表进行监听
//获知路由表发生了变化
struct route_data {
	/* Copied from struct rtmsg. */
	unsigned char rtm_dst_len;
	bool local;

	/* Extracted from Netlink attributes. */
	struct in6_addr rta_dst; /* 0 if missing. */
	struct in6_addr rta_gw;
	char ifname[IFNAMSIZ]; /* Interface name. */
	uint32_t mark;
};

/* A digested version of a route message sent down by the kernel to indicate
 * that a route has changed. */
struct route_table_msg {
	bool relevant; /* Should this message be processed? */
	int nlmsg_type; /* e.g. RTM_NEWROUTE, RTM_DELROUTE. */
	struct route_data rd; /* Data parsed from this message. */
};

struct nl_dump {
    /* These members are immutable during the lifetime of the nl_dump. */
    struct nl_sock *sock;       /* Socket being dumped. */
    uint32_t nl_seq;            /* Expected nlmsg_seq for replies. */
    int status ;     /* 0: dump in progress,
                                 * positive errno: dump completed with error,
                                 * EOF: dump completed successfully. */

    /* 'mutex' protects 'status' and serializes access to 'sock'. */
    struct ovs_mutex mutex;     /* Protects 'status', synchronizes recv(). */
};
/* Function called to report that a netdev has changed.  'change' describes the
 * specific change.  It may be null if the buffer of change information
 * overflowed, in which case the function must assume that every device may
 * have changed.  'aux' is as specified in the call to
 * rtnetlink_notifier_register().  */
typedef void rtnetlink_notify_func(const struct rtnetlink_change *change,
		void *aux);
static struct nln *nln = NULL;
static struct route_table_msg rtmsg;
static struct rtnetlink_change rtn_change;

/* Returns true if the given netlink msg type corresponds to RTNLGRP_LINK. */
bool rtnetlink_type_is_rtnlgrp_link(uint16_t type) {
	return type == RTM_NEWLINK || type == RTM_DELLINK;
}

/* Returns true if the given netlink msg type corresponds to
 * RTNLGRP_IPV4_IFADDR or RTNLGRP_IPV6_IFADDR. */
bool rtnetlink_type_is_rtnlgrp_addr(uint16_t type) {
	return type == RTM_NEWADDR || type == RTM_DELADDR;
}

/* Creates an nln handle which may be used to manage change notifications.  The
 * created handle will listen for netlink messages on 'multicast_group' using
 * netlink protocol 'protocol' (e.g. NETLINK_ROUTE, NETLINK_GENERIC, ...).
 * Incoming messages will be parsed with 'parse' which will be passed 'change'
 * as an argument. */
struct nln *
nln_create(int protocol, nln_parse_func *parse, void *change) {
	struct nln *nln_ptr;

	nln_ptr = calloc(sizeof *nln_ptr, 1);
	nln_ptr->notify_sock = NULL;
	nln_ptr->protocol = protocol;
	nln_ptr->parse = parse;
	nln_ptr->change = change;
	nln_ptr->has_run = false;

	ovs_list_init(&nln_ptr->all_notifiers);
	return nln_ptr;
}

/* In Windows platform, errno is not set for socket calls.
 * The last error has to be gotten from WSAGetLastError(). */
static inline int sock_errno(void) {
	return errno;
}

static int getsockopt_int(int fd, int level, int option, const char *optname,
		int *valuep) {
	//static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 10);
	socklen_t len;
	int value;
	int error;

	len = sizeof value;
	if (getsockopt(fd, level, option, &value, &len)) {
		error = sock_errno();
		VLOG_ERR("getsockopt(%s): %s", optname, strerror(error));
	} else if (len != sizeof value) {
		error = EINVAL;
		VLOG_ERR("getsockopt(%s): value is %u bytes (expected %ld)", optname,
				(unsigned int ) len, sizeof value);
	} else {
		error = 0;
	}

	*valuep = error ? 0 : value;
	return error;
}

/* Returns the size of socket 'sock''s receive buffer (SO_RCVBUF), or a
 * negative errno value if an error occurs. */
int get_socket_rcvbuf(int sock) {
	int rcvbuf;
	int error;

	error = getsockopt_int(sock, SOL_SOCKET, SO_RCVBUF, "SO_RCVBUF", &rcvbuf);
	return error ? -error : rcvbuf;
}

//创建netlink socket,并通过其连接到kernel
int nl_sock_create(int protocol, struct nl_sock **sockp) {
	struct nl_sock *sock;
	struct sockaddr_nl local, remote;
	socklen_t local_size;
	int rcvbuf;
	int retval = 0;

	*sockp = NULL;
	sock = malloc(sizeof *sock);

	//创建netlink socket
	sock->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (sock->fd < 0) {
		VLOG_ERR("fcntl: %s", strerror(errno));
		goto error;
	}

	sock->protocol = protocol;
	sock->next_seq = 1;

	rcvbuf = 1024 * 1024;
	if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf,
			sizeof rcvbuf)) {
		/* Only root can use SO_RCVBUFFORCE.  Everyone else gets EPERM.
		 * Warn only if the failure is therefore unexpected. */
		if (errno != EPERM) {
			VLOG_WARN("setting %d-byte socket receive buffer failed "
					"(%s)", rcvbuf, strerror(errno));
		}
	}

	retval = get_socket_rcvbuf(sock->fd);
	if (retval < 0) {
		retval = -retval;
		goto error;
	}
	sock->rcvbuf = retval;
	retval = 0;

	/* Connect to kernel (pid 0) as remote address. */
	memset(&remote, 0, sizeof remote);
	remote.nl_family = AF_NETLINK;
	remote.nl_pid = 0;
	if (connect(sock->fd, (struct sockaddr *) &remote, sizeof remote) < 0) {
		VLOG_ERR("connect(0): %s", strerror(errno));
		goto error;
	}

	/* Obtain pid assigned by kernel. */
	local_size = sizeof local;
	if (getsockname(sock->fd, (struct sockaddr *) &local, &local_size) < 0) {
		VLOG_ERR("getsockname: %s", strerror(errno));
		goto error;
	}
	if (local_size < sizeof local || local.nl_family != AF_NETLINK) {
		VLOG_ERR("getsockname returned bad Netlink name");
		retval = EINVAL;
		goto error;
	}
	sock->pid = local.nl_pid;

	*sockp = sock;
	return 0;

	error: if (retval == 0) {
		retval = errno;
		if (retval == 0) {
			retval = EINVAL;
		}
	}
	if (sock->fd >= 0) {
		close(sock->fd);
	}
	free(sock);
	return retval;
}

int nl_sock_join_mcgroup(struct nl_sock *sock, unsigned int multicast_group) {
#ifdef _WIN32
	/* Set the socket type as a "multicast" socket */
	sock->read_ioctl = OVS_IOCTL_READ_EVENT;
	int error = nl_sock_mcgroup(sock, multicast_group, true);
	if (error) {
		sock->read_ioctl = OVS_IOCTL_READ;
		VLOG_WARN("could not join multicast group %u (%s)",
				multicast_group, ovs_strerror(error));
		return error;
	}
#else
	if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			&multicast_group, sizeof multicast_group) < 0) {
		VLOG_WARN("could not join multicast group %u (%s)", multicast_group,
				strerror(errno));
		return errno;
	}
#endif
	return 0;
}

static int nl_sock_recv(struct nl_sock *sock, struct ofpbuf *buf, int *nsid,
bool wait) {
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
		//读取fd
		retval = recvmsg(sock->fd, &msg, wait ? 0 : MSG_DONTWAIT);
		error = (retval < 0 ? errno : retval == 0 ? ECONNRESET /* not possible? */
		:
					nlmsghdr->nlmsg_len != UINT32_MAX ? 0 : retval);
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
		VLOG_ERR("truncated message (longer than %ld bytes)", sizeof tail);
		return E2BIG;
	}

	if (retval < sizeof *nlmsghdr || nlmsghdr->nlmsg_len < sizeof *nlmsghdr
			|| nlmsghdr->nlmsg_len > retval) {
		VLOG_ERR("received invalid nlmsg (%ld bytes < %ld)", retval,
				sizeof *nlmsghdr);
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
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
				/* This is unexpected and unwanted, close all fds */
				int nfds;
				int i;
				nfds = (cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr)))
						/ sizeof(int);
				ptr = ALIGNED_CAST(int *, CMSG_DATA(cmsg));
				for (i = 0; i < nfds; i++) {
					VLOG_ERR("closing unexpected received fd (%d).", ptr[i]);
					close(ptr[i]);
				}
			}

			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}
#endif
	}

	//log_nlmsg(__func__, 0, buf->data, buf->size, sock->protocol);
	COVERAGE_INC(netlink_received);

	return 0;
}

/* Parses nested nlattr for link info. Returns false if unparseable, else
 * populates 'change' and returns true. */
static bool rtnetlink_parse_link_info(const struct nlattr *nla,
		struct rtnetlink_change *change) {
	bool parsed = false;

	static const struct nl_policy linkinfo_policy[] = { [IFLA_INFO_KIND] = {
			.type = NL_A_STRING, .optional = true }, [IFLA_INFO_SLAVE_KIND] = {
			.type = NL_A_STRING, .optional = true }, };

	struct nlattr *linkinfo[ARRAY_SIZE(linkinfo_policy)];

	parsed = nl_parse_nested(nla, linkinfo_policy, linkinfo,
			ARRAY_SIZE(linkinfo_policy));

	if (parsed) {
		change->master = (
				linkinfo[IFLA_INFO_KIND] ?
						nl_attr_get_string(linkinfo[IFLA_INFO_KIND]) : NULL);
		change->slave = (
				linkinfo[IFLA_INFO_SLAVE_KIND] ?
						nl_attr_get_string(linkinfo[IFLA_INFO_SLAVE_KIND]) :
						NULL);
	}

	return parsed;
}

/* Parses a rtnetlink message 'buf' into 'change'.  If 'buf' is unparseable,
 * leaves 'change' untouched and returns false.  Otherwise, populates 'change'
 * and returns true. */
bool rtnetlink_parse(struct ofpbuf *buf, struct rtnetlink_change *change) {
	const struct nlmsghdr *nlmsg = buf->data;
	bool parsed = false;

	if (rtnetlink_type_is_rtnlgrp_link(nlmsg->nlmsg_type)) {
		/* Policy for RTNLGRP_LINK messages.
		 *
		 * There are *many* more fields in these messages, but currently we
		 * only care about these fields. */
		static const struct nl_policy policy[] = { [IFLA_IFNAME] = { .type =
				NL_A_STRING, .optional = false }, [IFLA_MASTER] = { .type =
				NL_A_U32, .optional = true }, [IFLA_MTU] = { .type = NL_A_U32,
				.optional = true }, [IFLA_ADDRESS] = { .type = NL_A_UNSPEC,
				.optional = true }, [IFLA_LINKINFO] = { .type = NL_A_NESTED,
				.optional = true }, };

		struct nlattr *attrs[ARRAY_SIZE(policy)];

		parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
				policy, attrs, ARRAY_SIZE(policy));

		if (parsed) {
			const struct ifinfomsg *ifinfo;

			ifinfo = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *ifinfo);

			change->nlmsg_type = nlmsg->nlmsg_type;
			change->if_index = ifinfo->ifi_index;
			change->ifname = nl_attr_get_string(attrs[IFLA_IFNAME]);
			change->ifi_flags = ifinfo->ifi_flags;
			change->master_ifindex =
					(attrs[IFLA_MASTER] ?
							nl_attr_get_u32(attrs[IFLA_MASTER]) : 0);
			change->mtu = (
					attrs[IFLA_MTU] ? nl_attr_get_u32(attrs[IFLA_MTU]) : 0);

			if (attrs[IFLA_ADDRESS]
					&& nl_attr_get_size(attrs[IFLA_ADDRESS]) == ETH_ADDR_LEN) {
				memcpy(&change->mac, nl_attr_get(attrs[IFLA_ADDRESS]),
				ETH_ADDR_LEN);
			} else {
				memset(&change->mac, 0, ETH_ADDR_LEN);
			}

			if (attrs[IFLA_LINKINFO]) {
				parsed = rtnetlink_parse_link_info(attrs[IFLA_LINKINFO],
						change);
			} else {
				change->master = NULL;
				change->slave = NULL;
			}
		}
	} else if (rtnetlink_type_is_rtnlgrp_addr(nlmsg->nlmsg_type)) {
		/* Policy for RTNLGRP_IPV4_IFADDR/RTNLGRP_IPV6_IFADDR messages.
		 *
		 * There are *many* more fields in these messages, but currently we
		 * only care about these fields. */
		static const struct nl_policy policy[] = { [IFA_LABEL] = { .type =
				NL_A_STRING, .optional = true }, };

		struct nlattr *attrs[ARRAY_SIZE(policy)];

		parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifaddrmsg),
				policy, attrs, ARRAY_SIZE(policy));

		if (parsed) {
			const struct ifaddrmsg *ifaddr;

			ifaddr = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *ifaddr);

			change->nlmsg_type = nlmsg->nlmsg_type;
			change->if_index = ifaddr->ifa_index;
			change->ifname = (
					attrs[IFA_LABEL] ?
							nl_attr_get_string(attrs[IFA_LABEL]) : NULL);
		}
	}

	return parsed;
}

/* Return RTNLGRP_LINK on success, 0 on parse error. */
static int rtnetlink_parse_cb(struct ofpbuf *buf, void *change) {
	return rtnetlink_parse(buf, change) ? RTNLGRP_LINK : 0;
}

/* Registers 'cb' to be called with auxiliary data 'aux' with change
 * notifications.  The notifier is stored in 'notifier', which the caller must
 * not modify or free.
 *
 * This is probably not the function you want.  You should probably be using
 * message specific notifiers like rtnetlink_link_notifier_register().
 *
 * Returns an initialized nln_notifier if successful, otherwise NULL. */
void nln_run(struct nln *nln_ptr);
struct nln_notifier *
nln_notifier_create(struct nln *nln_ptr, int multicast_group,
		nln_notify_func *cb, void *aux) {
	struct nln_notifier *notifier;
	int error;

	//assert(!nln_ptr->notify_sock);
	if (!nln_ptr->notify_sock) {
		struct nl_sock *sock;

		//创建sock
		error = nl_sock_create(nln_ptr->protocol, &sock);
		if (error) {
			VLOG_WARN("could not create netlink socket: %s", strerror(error));
			return NULL;
		}
		nln_ptr->notify_sock = sock;
	}
	else {
	/* Catch up on notification work so that the new notifier won't
	 * receive any stale notifications. */
	    nln_run(nln_ptr);
	}
	//加入到组播组$multicast_group
	error = nl_sock_join_mcgroup(nln_ptr->notify_sock, multicast_group);
	if (error) {
		VLOG_WARN("could not join netlink multicast group: %s",
				strerror(error));
		return NULL;
	}

	notifier = malloc(sizeof *notifier);
	notifier->multicast_group = multicast_group;
	notifier->cb = cb;
	notifier->aux = aux;
	notifier->nln = nln_ptr;

	//将notifier加入到通知链表中
	ovs_list_push_back(&nln_ptr->all_notifiers, &notifier->node);

	return notifier;
}

/* Registers 'cb' to be called with auxiliary data 'aux' with network device
 * change notifications.  The notifier is stored in 'notifier', which the
 * caller must not modify or free.
 *
 * This is probably not the function that you want.  You should probably be
 * using dpif_port_poll() or netdev_change_seq(), which unlike this function
 * are not Linux-specific.
 *
 * xxx Joins more multicast groups when needed.
 *
 * Returns an initialized nln_notifier if successful, NULL otherwise. */
struct nln_notifier *
rtnetlink_notifier_create(rtnetlink_notify_func *cb, void *aux) {
	if (!nln) {
		nln = nln_create(NETLINK_ROUTE, rtnetlink_parse_cb, &rtn_change);
	}

	return nln_notifier_create(nln, RTNLGRP_LINK, (nln_notify_func *) cb, aux);
}

//触发notifier
void nln_report(const struct nln *nln_ptr, void *change, int group) {
	struct nln_notifier *notifier;

	if (change) {
		COVERAGE_INC(nln_changed);
	}

	//触发通知
	LIST_FOR_EACH (notifier, node, &nln_ptr->all_notifiers)
	{
		if (!change || group == notifier->multicast_group) {
			notifier->cb(change, notifier->aux);
		}
	}
}

void nln_run(struct nln *nln_ptr) {
	//static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

	if (!nln_ptr->notify_sock || nln_ptr->has_run) {
		return;
	}

	nln_ptr->has_run = true;
	for (;;) {
		uint64_t buf_stub[4096 / 8];
		struct ofpbuf buf;
		int error;

		ofpbuf_use_stub(&buf, buf_stub, sizeof buf_stub);
		//读取socket,收取数据
		error = nl_sock_recv(nln_ptr->notify_sock, &buf, NULL, false);
		if (!error) {
			//解析收取到的数据
			int group = nln_ptr->parse(&buf, nln_ptr->change);
			if (group != 0) {
				nln_report(nln_ptr, nln_ptr->change, group);	//调用回调
			} else {
				VLOG_WARN("unexpected netlink message contents");
				nln_report(nln_ptr, NULL, 0);
			}
			ofpbuf_uninit(&buf);
		} else if (error == EAGAIN) {
			return;
		} else {
			if (error == ENOBUFS) {
				/* The socket buffer might be full, there could be too many
				 * notifications, so it makes sense to call nln_report() */
				nln_report(nln_ptr, NULL, 0);
				VLOG_WARN("netlink receive buffer overflowed");
			} else {
				VLOG_WARN("error reading netlink socket: %s", strerror(error));
			}
			return;
		}
	}
}

/* Destroys netlink socket 'sock'. */
void nl_sock_destroy(struct nl_sock *sock) {
	if (sock) {
		close(sock->fd);
		free(sock);
	}
}

/* When 'enable' is true, it tries to enable 'sock' to receive netlink
 * notifications form all network namespaces that have an nsid assigned
 * into the network namespace where the socket has been opened. The
 * running kernel needs to provide support for that. When 'enable' is
 * false, it will receive netlink notifications only from the network
 * namespace where the socket has been opened.
 *
 * Returns 0 if successful, otherwise a positive errno.  */
int nl_sock_listen_all_nsid(struct nl_sock *sock, bool enable) {
	int error;
	int val = enable ? 1 : 0;

	if (setsockopt(sock->fd, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID, &val,
			sizeof val) < 0) {
		error = errno;
		VLOG_INFO("netlink: could not %s listening to all nsid (%s)",
				enable ? "enable" : "disable", strerror(error));
		return errno;
	}

	return 0;
}

/* Returns a NETLINK_ROUTE socket listening for RTNLGRP_LINK,
 * RTNLGRP_IPV4_IFADDR and RTNLGRP_IPV6_IFADDR changes, or NULL
 * if no such socket could be created. */
struct nl_sock *
netdev_linux_notify_sock(void) {
	static struct nl_sock *sock;
	unsigned int mcgroups[] = { RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR,
	RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_IFINFO };

	if (1) {
		int error;

		error = nl_sock_create(NETLINK_ROUTE, &sock);
		if (!error) {
			size_t i;

			for (i = 0; i < ARRAY_SIZE(mcgroups); i++) {
				error = nl_sock_join_mcgroup(sock, mcgroups[i]);
				if (error) {
					nl_sock_destroy(sock);
					sock = NULL;
					break;
				}
			}
		}
		nl_sock_listen_all_nsid(sock, true);
	}

	return sock;
}

/* Causes poll_block() to wake up when any of the specified 'events' (which is
 * a OR'd combination of POLLIN, POLLOUT, etc.) occur on 'sock'.
 * On Windows, 'sock' is not treated as const, and may be modified. */
void nl_sock_wait(const struct nl_sock *sock, short int events) {
#if 0
#ifdef _WIN32
	if (sock->overlapped.Internal != STATUS_PENDING) {
		int ret = pend_io_request(CONST_CAST(struct nl_sock *, sock));
		if (ret == 0) {
			poll_wevent_wait(sock->overlapped.hEvent);
		} else {
			poll_immediate_wake();
		}
	} else {
		poll_wevent_wait(sock->overlapped.hEvent);
	}
#else
	poll_fd_wait(sock->fd, events);
#endif
#else
	int rc;
	struct pollfd fds[1];
	fds[0].fd = sock->fd;
	fds[0].events = events;
	rc = poll(fds, 1, -1);
	if (rc < 0) {
		VLOG_INFO("netlink: poll fd fail (%s)", strerror(errno));
	}
#endif
}

/* Return RTNLGRP_IPV4_ROUTE or RTNLGRP_IPV6_ROUTE on success, 0 on parse
 * error. */
static int route_table_parse(struct ofpbuf *buf, struct route_table_msg *change) {
	bool parsed, ipv4 = false;

	static const struct nl_policy policy[] = { [RTA_DST] = { .type = NL_A_U32,
			.optional = true }, [RTA_OIF
			] = { .type = NL_A_U32, .optional = true }, [RTA_GATEWAY] = {
			.type = NL_A_U32, .optional = true }, [RTA_MARK] = { .type =
			NL_A_U32, .optional = true }, };

	static const struct nl_policy policy6[] = { [RTA_DST] = { .type = NL_A_IPV6,
			.optional = true }, [RTA_OIF
			] = { .type = NL_A_U32, .optional = true }, [RTA_MARK] = { .type =
			NL_A_U32, .optional = true }, [RTA_GATEWAY] = { .type = NL_A_IPV6,
			.optional = true }, };

	struct nlattr *attrs[ARRAY_SIZE(policy)];
	const struct rtmsg *rtm;

	rtm = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *rtm);

	if (rtm->rtm_family == AF_INET) {
		parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
				policy, attrs, ARRAY_SIZE(policy));
		ipv4 = true;
	} else if (rtm->rtm_family == AF_INET6) {
		parsed = nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct rtmsg),
				policy6, attrs, ARRAY_SIZE(policy6));
	} else {
		VLOG_DBG("received non AF_INET rtnetlink route message");
		return 0;
	}

	if (parsed) {
		const struct nlmsghdr *nlmsg;
		int rta_oif; /* Output interface index. */

		nlmsg = buf->data;

		memset(change, 0, sizeof *change);
		change->relevant = true;

		if (rtm->rtm_scope == RT_SCOPE_NOWHERE) {
			change->relevant = false;
		}

		if (rtm->rtm_type != RTN_UNICAST && rtm->rtm_type != RTN_LOCAL) {
			change->relevant = false;
		}
		change->nlmsg_type = nlmsg->nlmsg_type;
		change->rd.rtm_dst_len = rtm->rtm_dst_len + (ipv4 ? 96 : 0);
		change->rd.local = rtm->rtm_type == RTN_LOCAL;
		if (attrs[RTA_OIF]) {
			rta_oif = nl_attr_get_u32(attrs[RTA_OIF]);

			if (!if_indextoname(rta_oif, change->rd.ifname)) {
				int error = errno;

				VLOG_DBG("Could not find interface name[%u]: %s", rta_oif,
						strerror(error));
				if (error == ENXIO) {
					change->relevant = false;
				} else {
					return 0;
				}
			}
		}

		if (attrs[RTA_DST]) {
			if (ipv4) {
				ovs_be32 dst;
				dst = nl_attr_get_be32(attrs[RTA_DST]);
				in6_addr_set_mapped_ipv4(&change->rd.rta_dst, dst);
			} else {
				change->rd.rta_dst = nl_attr_get_in6_addr(attrs[RTA_DST]);
			}
		} else if (ipv4) {
			in6_addr_set_mapped_ipv4(&change->rd.rta_dst, 0);
		}
		if (attrs[RTA_GATEWAY]) {
			if (ipv4) {
				ovs_be32 gw;
				gw = nl_attr_get_be32(attrs[RTA_GATEWAY]);
				in6_addr_set_mapped_ipv4(&change->rd.rta_gw, gw);
			} else {
				change->rd.rta_gw = nl_attr_get_in6_addr(attrs[RTA_GATEWAY]);
			}
		}
		if (attrs[RTA_MARK]) {
			change->rd.mark = nl_attr_get_u32(attrs[RTA_MARK]);
		}
	} else {
		VLOG_DBG( "received unparseable rtnetlink route message");
		return 0;
	}

	/* Success. */
	return ipv4 ? RTNLGRP_IPV4_ROUTE : RTNLGRP_IPV6_ROUTE;
}

struct nl_pool {
    struct nl_sock *socks[16];
    int n;
};

static struct ovs_mutex pool_mutex = OVS_MUTEX_INITIALIZER;
static struct nl_pool pools[MAX_LINKS];

static int
nl_pool_alloc(int protocol, struct nl_sock **sockp)
{
    struct nl_sock *sock = NULL;
    struct nl_pool *pool;

    assert(protocol >= 0 && protocol < ARRAY_SIZE(pools));

    pthread_mutex_lock(&pool_mutex.lock);
    pool = &pools[protocol];
    if (pool->n > 0) {
        sock = pool->socks[--pool->n];
    }
    pthread_mutex_unlock(&pool_mutex.lock);

    if (sock) {
        *sockp = sock;
        return 0;
    } else {
        return nl_sock_create(protocol, sockp);
    }
}

static uint32_t
nl_sock_allocate_seq(struct nl_sock *sock, unsigned int n)
{
    uint32_t seq = sock->next_seq;

    sock->next_seq += n;

    /* Make it impossible for the next request for sequence numbers to wrap
     * around to 0.  Start over with 1 to avoid ever using a sequence number of
     * 0, because the kernel uses sequence number 0 for notifications. */
    if (sock->next_seq >= UINT32_MAX / 2) {
        sock->next_seq = 1;
    }

    return seq;
}

static int
nl_sock_send__(struct nl_sock *sock, const struct ofpbuf *msg,
               uint32_t nlmsg_seq, bool wait)
{
    struct nlmsghdr *nlmsg = nl_msg_nlmsghdr(msg);
    int error;

    nlmsg->nlmsg_len = msg->size;
    nlmsg->nlmsg_seq = nlmsg_seq;
    nlmsg->nlmsg_pid = sock->pid;
    do {
        int retval;
        retval = send(sock->fd, msg->data, msg->size,
                      wait ? 0 : MSG_DONTWAIT);
        error = retval < 0 ? errno : 0;
    } while (error == EINTR);
    //log_nlmsg(__func__, error, msg->data, msg->size, sock->protocol);
    if (!error) {
        COVERAGE_INC(netlink_sent);
    }
    return error;
}
/* Starts a Netlink "dump" operation, by sending 'request' to the kernel on a
 * Netlink socket created with the given 'protocol', and initializes 'dump' to
 * reflect the state of the operation.
 *
 * 'request' must contain a Netlink message.  Before sending the message,
 * nlmsg_len will be finalized to match request->size, and nlmsg_pid will be
 * set to the Netlink socket's pid.  NLM_F_DUMP and NLM_F_ACK will be set in
 * nlmsg_flags.
 *
 * The design of this Netlink socket library ensures that the dump is reliable.
 *
 * This function provides no status indication.  nl_dump_done() provides an
 * error status for the entire dump operation.
 *
 * The caller must eventually destroy 'request'.
 */
void
nl_dump_start(struct nl_dump *dump, int protocol, const struct ofpbuf *request)
{
    nl_msg_nlmsghdr(request)->nlmsg_flags |= NLM_F_DUMP | NLM_F_ACK;

    pthread_mutex_init(&dump->mutex.lock,NULL);
    pthread_mutex_lock(&dump->mutex.lock);
    dump->status = nl_pool_alloc(protocol, &dump->sock);
    if (!dump->status) {
        dump->status = nl_sock_send__(dump->sock, request,
                                      nl_sock_allocate_seq(dump->sock, 1),
                                      true);
    }
    dump->nl_seq = nl_msg_nlmsghdr(request)->nlmsg_seq;
    pthread_mutex_lock(&dump->mutex.lock);
}

static int
nl_dump_refill(struct nl_dump *dump, struct ofpbuf *buffer)
{
    struct nlmsghdr *nlmsghdr;
    int error;

    while (!buffer->size) {
        error = nl_sock_recv(dump->sock, buffer, NULL, false);
        if (error) {
            /* The kernel never blocks providing the results of a dump, so
             * error == EAGAIN means that we've read the whole thing, and
             * therefore transform it into EOF.  (The kernel always provides
             * NLMSG_DONE as a sentinel.  Some other thread must have received
             * that already but not yet signaled it in 'status'.)
             *
             * Any other error is just an error. */
            return error == EAGAIN ? EOF : error;
        }

        nlmsghdr = nl_msg_nlmsghdr(buffer);
        if (dump->nl_seq != nlmsghdr->nlmsg_seq) {
            VLOG_DBG("ignoring seq %#"PRIx32" != expected %#"PRIx32,
                        nlmsghdr->nlmsg_seq, dump->nl_seq);
            ofpbuf_clear(buffer);
        }
    }

    if (nl_msg_nlmsgerr(buffer, &error) && error) {
        VLOG_INFO( "netlink dump request error (%s)",
                     strerror(error));
        ofpbuf_clear(buffer);
        return error;
    }

    return 0;
}

static int
nl_dump_next__(struct ofpbuf *reply, struct ofpbuf *buffer)
{
    struct nlmsghdr *nlmsghdr = nl_msg_next(buffer, reply);
    if (!nlmsghdr) {
        VLOG_WARN( "netlink dump contains message fragment");
        return EPROTO;
    } else if (nlmsghdr->nlmsg_type == NLMSG_DONE) {
        return EOF;
    } else {
        return 0;
    }
}

/* Attempts to retrieve another reply from 'dump' into 'buffer'. 'dump' must
 * have been initialized with nl_dump_start(), and 'buffer' must have been
 * initialized. 'buffer' should be at least NL_DUMP_BUFSIZE bytes long.
 *
 * If successful, returns true and points 'reply->data' and
 * 'reply->size' to the message that was retrieved. The caller must not
 * modify 'reply' (because it points within 'buffer', which will be used by
 * future calls to this function).
 *
 * On failure, returns false and sets 'reply->data' to NULL and
 * 'reply->size' to 0.  Failure might indicate an actual error or merely
 * the end of replies.  An error status for the entire dump operation is
 * provided when it is completed by calling nl_dump_done().
 *
 * Multiple threads may call this function, passing the same nl_dump, however
 * each must provide independent buffers. This function may cache multiple
 * replies in the buffer, and these will be processed before more replies are
 * fetched. When this function returns false, other threads may continue to
 * process replies in their buffers, but they will not fetch more replies.
 */
bool
nl_dump_next(struct nl_dump *dump, struct ofpbuf *reply, struct ofpbuf *buffer)
{
    int retval = 0;

    /* If the buffer is empty, refill it.
     *
     * If the buffer is not empty, we don't check the dump's status.
     * Otherwise, we could end up skipping some of the dump results if thread A
     * hits EOF while thread B is in the midst of processing a batch. */
    if (!buffer->size) {
    	pthread_mutex_lock(&dump->mutex.lock);
        if (!dump->status) {
            /* Take the mutex here to avoid an in-kernel race.  If two threads
             * try to read from a Netlink dump socket at once, then the socket
             * error can be set to EINVAL, which will be encountered on the
             * next recv on that socket, which could be anywhere due to the way
             * that we pool Netlink sockets.  Serializing the recv calls avoids
             * the issue. */
            dump->status = nl_dump_refill(dump, buffer);
        }
        retval = dump->status;
        pthread_mutex_unlock(&dump->mutex.lock);
    }

    /* Fetch the next message from the buffer. */
    if (!retval) {
        retval = nl_dump_next__(reply, buffer);
        if (retval) {
            /* Record 'retval' as the dump status, but don't overwrite an error
             * with EOF.  */
        	pthread_mutex_lock(&dump->mutex.lock);
            if (dump->status <= 0) {
                dump->status = retval;
            }
            pthread_mutex_unlock(&dump->mutex.lock);
        }
    }

    if (retval) {
        reply->data = NULL;
        reply->size = 0;
    }
    return !retval;
}

static void
nl_pool_release(struct nl_sock *sock)
{
    if (sock) {
        struct nl_pool *pool = &pools[sock->protocol];

        pthread_mutex_lock(&pool_mutex.lock);
        if (pool->n < ARRAY_SIZE(pool->socks)) {
            pool->socks[pool->n++] = sock;
            sock = NULL;
        }
        pthread_mutex_unlock(&pool_mutex.lock);

        nl_sock_destroy(sock);
    }
}

/* Completes Netlink dump operation 'dump', which must have been initialized
 * with nl_dump_start().  Returns 0 if the dump operation was error-free,
 * otherwise a positive errno value describing the problem. */
int
nl_dump_done(struct nl_dump *dump)
{
    int status;

    pthread_mutex_lock(&dump->mutex.lock);
    status = dump->status;
    pthread_mutex_unlock(&dump->mutex.lock);

    /* Drain any remaining messages that the client didn't read.  Otherwise the
     * kernel will continue to queue them up and waste buffer space.
     *
     * XXX We could just destroy and discard the socket in this case. */
    if (!status) {
        uint64_t tmp_reply_stub[NL_DUMP_BUFSIZE / 8];
        struct ofpbuf reply, buf;

        ofpbuf_use_stub(&buf, tmp_reply_stub, sizeof tmp_reply_stub);
        while (nl_dump_next(dump, &reply, &buf)) {
            /* Nothing to do. */
        }
        ofpbuf_uninit(&buf);

        pthread_mutex_lock(&dump->mutex.lock);
        status = dump->status;
        pthread_mutex_unlock(&dump->mutex.lock);
        assert(status);
    }

    nl_pool_release(dump->sock);
    pthread_mutex_destroy(&dump->mutex.lock);

    return status == EOF ? 0 : status;
}

static void
route_table_handle_msg(const struct route_table_msg *change)
{
    if (change->relevant && change->nlmsg_type == RTM_NEWROUTE) {
        const struct route_data *rd = &change->rd;

        ovs_router_insert(rd->mark, &rd->rta_dst, rd->rtm_dst_len,
                          rd->local, rd->ifname, &rd->rta_gw);
    }
}

static void
route_map_clear(void)
{
    ovs_router_flush();
}

static int
route_table_reset(void)
{
    struct nl_dump dump;
    struct rtgenmsg *rtgenmsg;
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf request, reply, buf;

    route_map_clear();
    //netdev_get_addrs_list_flush();
    //route_table_valid = true;
    //rt_change_seq++;

    ofpbuf_init(&request, 0);

    nl_msg_put_nlmsghdr(&request, sizeof *rtgenmsg, RTM_GETROUTE,
                        NLM_F_REQUEST);

    rtgenmsg = ofpbuf_put_zeros(&request, sizeof *rtgenmsg);
    rtgenmsg->rtgen_family = AF_UNSPEC;

    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    while (nl_dump_next(&dump, &reply, &buf)) {
        struct route_table_msg msg;

        if (route_table_parse(&reply, &msg)) {
        	//处理netlink消息，进行路由表项的添加删除
            route_table_handle_msg(&msg);
        }
    }
    ofpbuf_uninit(&buf);

    return nl_dump_done(&dump);
}
//=====
static void route_table_change(const struct route_table_msg *change, void *aux) {
	VLOG_WARN("rcv table change %p ", change);
}

static void
name_table_change(const struct rtnetlink_change *change,
                  void *aux)
{
    /* Changes to interface status can cause routing table changes that some
     * versions of the linux kernel do not advertise for some reason. */
	route_table_reset();
    VLOG_WARN("rcv name table change %p ", change);
}

int main(int argc, char**argv) {
	struct nln_notifier *route_notifier = NULL;
	struct nln_notifier *name_notifier = NULL;
	nln = nln_create(NETLINK_ROUTE, (nln_parse_func *) route_table_parse,
			&rtmsg);
	//name_notifier = rtnetlink_notifier_create(name_table_change, NULL);
	//监听路由变化
	route_notifier = nln_notifier_create(nln, RTNLGRP_IPV4_ROUTE,
			(nln_notify_func *) route_table_change, NULL);
	name_notifier = rtnetlink_notifier_create(name_table_change, NULL);
	//struct rtnetlink_change rtn_change;
	//struct nln * nlnptr = nln_create(NETLINK_ROUTE, rtnetlink_parse_cb, &rtn_change);
	//name_notifier = nln_notifier_create(nln, RTNLGRP_LINK, (nln_notify_func *) cb, aux)
	while (1) {
		nl_sock_wait(nln->notify_sock, POLLIN);
		VLOG_INFO("receive event\n");
		nln_run(nln);
	}
	route_notifier = route_notifier;
	name_notifier = name_notifier;
	return 0;
}

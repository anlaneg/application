#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>

#define BIT_IP(x)    ((char*)&(x))
#define STR_IP(x)    BIT_IP(x)[0], BIT_IP(x)[1], BIT_IP(x)[2], BIT_IP(x)[3]
#define STR_IPH(x)    BIT_IP(x)[3], BIT_IP(x)[2], BIT_IP(x)[1], BIT_IP(x)[0]

#define FMT_IP        "%d.%d.%d.%d"

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n)    NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif

void arp_parse_rattr(struct rtattr **tb, int max, struct rtattr *rta, int len) {
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);

	return;
}

const char *addr_to_mac(unsigned char *addr, int alen, char *buf, ssize_t blen) {
	int i;
	int l;

	l = 0;
	for (i = 0; i < alen; i++) {
		if (i == 0) {
			snprintf(buf + l, blen, "%02x", addr[i]);
			blen -= 2;
			l += 2;
		} else {
			snprintf(buf + l, blen, ":%02x", addr[i]);
			blen -= 3;
			l += 3;
		}
	}
	return buf;
}

////////////////
static inline void* get_neighbour_field(struct rtattr **tb,int type)
{
	assert(type >= NDA_UNSPEC && type <= __NDA_MAX);
	return RTA_DATA(tb[type]);
}

static inline void* get_neighbour_field_payload(struct rtattr**tb,int type)
{
	assert(type >= NDA_UNSPEC && type <= __NDA_MAX);
	return RTA_PAYLOAD(tb[type]);
}

static inline char* print_ip1(int32_t ip)
{
	static char ipstr[16] ;//"255.255.255.255";
	char*byte = &ip;
	snprintf(ipstr,16,"%u.%u.%u.%u",byte[0],byte[1],byte[2],byte[3]);
	ipstr[15]='\0';
	return ipstr;
}

static inline char* print_mac1(char* mac)
{
	static char macstr[18];//AA:BB:CC:DD:EE:FF
	char*byte = &mac;
	snprintf(macstr,18,"%02X:%02X:%02x:%02X:%02X:%02X",byte[0],byte[1],byte[2],byte[3],byte[4],byte[5]);
	macstr[17]='\0';
	return macstr;
}

int arp_parse_log(struct rtattr **tb);
{
	struct map{
		int type;
		char*name;
		(char*)(*func)(void*);
	};
	struct map maps={
			{ NDA_UNSPEC,"NDA_UNSPEC",NULL},
			{ NDA_DST,"ip",print_ip1},
			{ NDA_LLADDR,"mac",print_mac1},
			{ NDA_CACHEINFO,"cache",NULL},

	};

		NDA_DST,
		NDA_LLADDR,
		NDA_CACHEINFO,
		NDA_PROBES,
		NDA_VLAN,
		NDA_PORT,
		NDA_VNI,
		NDA_IFINDEX,
		NDA_MASTER,
		NDA_LINK_NETNSID,
		__NDA_MAX
}



static void read_netlink_message(int fd) {
	char buff[128 * 1024] = { 0 };
	char buf[1024] = { 0 };
	struct nlmsghdr *nh;
	struct ndmsg *ndmsg;
	int read_size;
	int len = 0;
	struct rtattr *tb[NDA_MAX + 1];

	read_size = read(fd, buff, sizeof(buff));
	if (read_size < 0) {
		return;
	}

	for (nh = (struct nlmsghdr*) buff; NLMSG_OK(nh, read_size);
			nh = NLMSG_NEXT(nh, read_size)) {
		switch (nh->nlmsg_type) {
		case RTM_NEWNEIGH:
			printf("add new arp cache\n");
			ndmsg = NLMSG_DATA(nh);
			if (ndmsg->ndm_family == AF_INET) {
				len = nh->nlmsg_len - NLMSG_SPACE(sizeof(struct ndmsg));
				arp_parse_rattr(tb, NDA_MAX, NDA_RTA(ndmsg), len);
				arp_parse_log(tb);
				if (tb[NDA_DST]) {
					int addr = *(int32_t*) (RTA_DATA(tb[NDA_DST]));
					printf("%u.%u.%u.%u %d\n", STR_IP(addr),
							(int) (RTA_PAYLOAD(tb[NDA_DST])));
				}
				if (tb[NDA_LLADDR]) {
					printf("%s %d\n",
							addr_to_mac(RTA_DATA(tb[NDA_LLADDR]),
									RTA_PAYLOAD(tb[NDA_LLADDR]), buf,
									sizeof(buf)),
							(int) (RTA_PAYLOAD(tb[NDA_LLADDR])));
				}
			}
			break;
		default:
			printf("delete arp cache %d\n", nh->nlmsg_type);
			ndmsg = NLMSG_DATA(nh);
			if (ndmsg->ndm_family == AF_INET) {
				len = nh->nlmsg_len - NLMSG_SPACE(sizeof(struct ndmsg));
				arp_parse_rattr(tb, NDA_MAX, NDA_RTA(ndmsg), len);
				if (tb[NDA_DST]) {
					int addr = *(int32_t*) (RTA_DATA(tb[NDA_DST]));
					printf("%u.%u.%u.%u %d\n", STR_IP(addr),
							(int) (RTA_PAYLOAD(tb[NDA_DST])));
				}
				if (tb[NDA_LLADDR]) {
					printf("%s %d\n",
							addr_to_mac(RTA_DATA(tb[NDA_LLADDR]),
									RTA_PAYLOAD(tb[NDA_LLADDR]), buf,
									sizeof(buf)),
							(int) (RTA_PAYLOAD(tb[NDA_LLADDR])));
				}
			}
			break;
		}
	}

	return;
}

int main(void) {

	int fd;
	struct sockaddr_nl sa;
	fd_set rd_set;
	int ret;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	bzero(&sa, sizeof(sa));

	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTM_NEWNEIGH | RTM_DELNEIGH;

	if ((bind(fd, (struct sockaddr *) &sa, sizeof(sa))) != 0) {
		perror("bind");
		return -1;
	}

	while (1) {
		FD_ZERO(&rd_set);
		FD_SET(fd, &rd_set);
		ret = select(fd + 1, &rd_set, NULL, NULL, NULL);
		if (ret < 0) {
			printf("select error\n");
			break;
		} else if (ret > 0) {
			if (FD_ISSET(fd, &rd_set)) {
				//读并解析netlink消息
				read_netlink_message(fd);
			}
		}
	}

	close(fd);
	return 0;
}


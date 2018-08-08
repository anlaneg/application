/*
 * pktdump.c
 *
 *  Created on: Aug 8, 2018
 *      Author: langan
 */
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

struct tok {
	u_int v;		/* value */
	const char *s;		/* string */
};
#include "ethertype.h"
#include "pktdump.h"

typedef enum {
	S_SUCCESS = 0, /* not a libnetdissect status */
	S_ERR_HOST_PROGRAM = 1, /* not a libnetdissect status */
	S_ERR_ND_NO_PRINTER = 2,
	S_ERR_ND_MEM_ALLOC = 3,
	S_ERR_ND_OPEN_FILE = 4,
	S_ERR_ND_WRITE_FILE = 5,
	S_ERR_ND_ESP_SECRET = 6
} status_exit_codes_t;

#define PRINTFLIKE_FUNCPTR(x,y) __attribute__((__format__(__printf__,x,y)))
typedef struct netdissect_options netdissect_options;
#define NORETURN_FUNCPTR __attribute((noreturn))
#define IF_PRINTER_ARGS (netdissect_options *, const struct pcap_pkthdr *, const u_char *)
//typedef u_int (*if_printer)IF_PRINTER_ARGS;

struct netdissect_options {
	int ndo_bflag; /* print 4 byte ASes in ASDOT notation */
	//显示以太头
	int ndo_eflag; /* print ethernet header */
	int ndo_fflag; /* don't translate "foreign" IP address */
	int ndo_Kflag; /* don't check IP, TCP or UDP checksums */
	int ndo_nflag; /* leave addresses as numbers */
	int ndo_Nflag; /* remove domains from printed host names */
	int ndo_qflag; /* quick (shorter) output */
	int ndo_Sflag; /* print raw TCP sequence numbers */
	int ndo_tflag; /* print packet arrival time */
	int ndo_uflag; /* Print undecoded NFS handles */
	int ndo_vflag; /* verbosity level */
	int ndo_xflag; /* print packet in hex */
	int ndo_Xflag; /* print packet in hex/ASCII */
	//按ascii形式显示报文
	int ndo_Aflag; /* print packet only in ASCII observing TAB,
	 * LF, CR and SPACE as graphical chars
	 */
	int ndo_Hflag; /* dissect 802.11s draft mesh standard */
	const char *ndo_protocol; /* protocol */
	void *ndo_last_mem_p; /* pointer to the last allocated memory chunk */
	//行起始时是否显示收到的报文数
	int ndo_packet_number; /* print a packet number in the beginning of line */
	int ndo_suppress_default_print; /* don't use default_print() for unknown packet types */
	int ndo_tstamp_precision; /* requested time stamp precision */
	//进程名称
	const char *program_name; /* Name of the program using the library */

	char *ndo_espsecret;
	struct sa_list *ndo_sa_list_head; /* used by print-esp.c */
	struct sa_list *ndo_sa_default;

	char *ndo_sigsecret; /* Signature verification secret key */

	int ndo_packettype; /* as specified by -T */

	int ndo_snaplen;

	/*global pointers to beginning and end of current packet (during printing) */
	const u_char *ndo_packetp;
	const u_char *ndo_snapend;

	/* pointer to the if_printer function */
	//if_printer ndo_if_printer; //报文显示函数

	/* pointer to void function to output stuff */
	void (*ndo_default_print)(netdissect_options *, const u_char *bp,
			u_int length);

	/* pointer to function to do regular output */
	int (*ndo_printf)(netdissect_options *, const char *fmt, ...) PRINTFLIKE_FUNCPTR(2, 3);
	/* pointer to function to output errors */
	void NORETURN_FUNCPTR(*ndo_error) (netdissect_options *,
			status_exit_codes_t status,
			const char *fmt, ...)
	PRINTFLIKE_FUNCPTR(3, 4);
	/* pointer to function to output warnings */
	void (*ndo_warning)(netdissect_options *, const char *fmt, ...) PRINTFLIKE_FUNCPTR(2, 3);
};

const struct tok ethertype_values[] = {
    { ETHERTYPE_IP,		"IPv4" },
    { ETHERTYPE_MPLS,		"MPLS unicast" },
    { ETHERTYPE_MPLS_MULTI,	"MPLS multicast" },
    { ETHERTYPE_IPV6,		"IPv6" },
    { ETHERTYPE_8021Q,		"802.1Q" },
    { ETHERTYPE_8021Q9100,	"802.1Q-9100" },
    { ETHERTYPE_8021QinQ,	"802.1Q-QinQ" },
    { ETHERTYPE_8021Q9200,	"802.1Q-9200" },
    { ETHERTYPE_VMAN,		"VMAN" },
    { ETHERTYPE_PUP,            "PUP" },
    { ETHERTYPE_ARP,            "ARP"},
    { ETHERTYPE_REVARP,         "Reverse ARP"},
    { ETHERTYPE_NS,             "NS" },
    { ETHERTYPE_SPRITE,         "Sprite" },
    { ETHERTYPE_TRAIL,          "Trail" },
    { ETHERTYPE_MOPDL,          "MOP DL" },
    { ETHERTYPE_MOPRC,          "MOP RC" },
    { ETHERTYPE_DN,             "DN" },
    { ETHERTYPE_LAT,            "LAT" },
    { ETHERTYPE_SCA,            "SCA" },
    { ETHERTYPE_TEB,            "TEB" },
    { ETHERTYPE_LANBRIDGE,      "Lanbridge" },
    { ETHERTYPE_DECDNS,         "DEC DNS" },
    { ETHERTYPE_DECDTS,         "DEC DTS" },
    { ETHERTYPE_VEXP,           "VEXP" },
    { ETHERTYPE_VPROD,          "VPROD" },
    { ETHERTYPE_ATALK,          "Appletalk" },
    { ETHERTYPE_AARP,           "Appletalk ARP" },
    { ETHERTYPE_IPX,            "IPX" },
    { ETHERTYPE_PPP,            "PPP" },
    { ETHERTYPE_MPCP,           "MPCP" },
    { ETHERTYPE_SLOW,           "Slow Protocols" },
    { ETHERTYPE_PPPOED,         "PPPoE D" },
    { ETHERTYPE_PPPOES,         "PPPoE S" },
    { ETHERTYPE_EAPOL,          "EAPOL" },
    { ETHERTYPE_RRCP,           "RRCP" },
    { ETHERTYPE_MS_NLB_HB,      "MS NLB heartbeat" },
    { ETHERTYPE_JUMBO,          "Jumbo" },
    { ETHERTYPE_NSH,            "NSH" },
    { ETHERTYPE_LOOPBACK,       "Loopback" },
    { ETHERTYPE_ISO,            "OSI" },
    { ETHERTYPE_GRE_ISO,        "GRE-OSI" },
    { ETHERTYPE_CFM_OLD,        "CFM (old)" },
    { ETHERTYPE_CFM,            "CFM" },
    { ETHERTYPE_IEEE1905_1,     "IEEE1905.1" },
    { ETHERTYPE_LLDP,           "LLDP" },
    { ETHERTYPE_TIPC,           "TIPC"},
    { ETHERTYPE_GEONET_OLD,     "GeoNet (old)"},
    { ETHERTYPE_GEONET,         "GeoNet"},
    { ETHERTYPE_CALM_FAST,      "CALM FAST"},
    { ETHERTYPE_AOE,            "AoE" },
    { ETHERTYPE_MEDSA,          "MEDSA" },
    { 0, NULL}
};

#define ND_PRINT(...) (ndo->ndo_printf)(ndo, __VA_ARGS__)

static inline void
nd_cleanup(void)
{

}
/* VARARGS */
static void NORETURN_FUNCPTR
ndo_error(netdissect_options *ndo, status_exit_codes_t status,
	  const char *fmt, ...)
{
	va_list ap;

	if(ndo->program_name)
		(void)fprintf(stderr, "%s: ", ndo->program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	nd_cleanup();
	exit(status);
	/* NOTREACHED */
}

//向stdout格式化显示数据
static int ndo_printf(netdissect_options *ndo, const char *fmt, ...) {
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vfprintf(stdout, fmt, args);
	va_end(args);

	if (ret < 0)
		ndo_error(ndo, S_ERR_ND_WRITE_FILE, "Unable to write output: %s",
				strerror(errno));
	return (ret);
}

static const char hex[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

static const char *
etheraddr_string(netdissect_options *ndo, char buf[],const uint8_t *ep)
{
	int i;
	char *cp;

	ndo = ndo;//make gcc happy

	cp = buf;
	*cp++ = hex[*ep >> 4 ];
	*cp++ = hex[*ep++ & 0xf];
	for (i = 5; --i >= 0;) {
		*cp++ = ':';
		*cp++ = hex[*ep >> 4 ];
		*cp++ = hex[*ep++ & 0xf];
	}

	*cp = '\0';
	return buf;
}
/*
 * Convert a token value to a string; use "fmt" if not found.
 * Uses tok2strbuf() on one of four local static buffers of size TOKBUFSIZE
 * in round-robin fashion.
 */
static const char *
tok2str(const struct tok *lp, const char *fmt,
	u_int v)
{
	if (lp != NULL) {
			while (lp->s != NULL) {
				if (lp->v == v)
					return (lp->s);
				++lp;
			}
	}
	return fmt;
}

static void ether_hdr_print(netdissect_options *ndo, const u_char *bp,
		u_int length) {
	const struct ether_header *ehp;
	uint16_t length_type;

	ehp = (const struct ether_header *) bp;

	//显示源mac,目的mac
	char srcmac[18];
	char dstmac[18];
	ND_PRINT("%s > %s", etheraddr_string(ndo, srcmac,ehp->ether_shost),
			etheraddr_string(ndo, dstmac,ehp->ether_dhost));

	//取协议类型或者长度
	length_type = ntohs(ehp->ether_type);
	if (!ndo->ndo_qflag) {
		if (length_type <= MAX_ETHERNET_LENGTH_VAL) {
			//802.3型报文（表示长度）
			ND_PRINT(", 802.3");
			length = length_type;
		} else
			//表示类型
			ND_PRINT(", ethertype %s (0x%04x)",
					tok2str(ethertype_values, "Unknown", length_type),
					length_type);
	} else {
		if (length_type <= MAX_ETHERNET_LENGTH_VAL) {
			ND_PRINT(", 802.3");
			length = length_type;
		} else
			ND_PRINT(", %s",
					tok2str(ethertype_values, "Unknown Ethertype (0x%04x)",
							length_type));
	}

	//显示报文长度
	ND_PRINT(", length %u: ", length);
}

void pktdump(const u_char *bp,u_int length)
{
	netdissect_options ndo={
			.ndo_printf = ndo_printf,
			.ndo_error = ndo_error,
	};
	ether_hdr_print(&ndo,bp,length);
}

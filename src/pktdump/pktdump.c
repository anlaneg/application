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

#include "netdissect-stdinc.h"
#include "netdissect.h"
#include "print.h"


void pktdump(const u_char *bp,u_int length)
{
        netdissect_options ndo;
        memset(&ndo, 0, sizeof(ndo));
	ndo.ndo_eflag = 1;
	ndo.ndo_vflag = 2;
        ndo_set_function_pointers(&ndo);
	ndo.ndo_if_printer=get_if_printer(&ndo, DLT_EN10MB);
	static u_int packets_captured = 0;
	packets_captured ++;
	struct pcap_pkthdr h;
	gettimeofday(&h.ts,NULL);
	h.caplen = length;
	h.len = length;
	pretty_print_packet(&ndo,&h,bp,packets_captured);
        //ether_print(&ndo,bp,length,length,NULL,NULL);
}


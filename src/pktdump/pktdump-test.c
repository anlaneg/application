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
        ndo_set_function_pointers(&ndo);
        ether_print(&ndo,bp,length,length,NULL,NULL);
}


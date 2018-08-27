/*
 * arp-test.c
 *
 *  Created on: Aug 27, 2018
 *      Author: anlang
 */


#if 0
int main(int argc, char**argv) {
	char mac[6];
	char dstip[4] = {10, 10, 10, 8};
	struct nl_addr* dst;

	if(nl_arp_table_init())
	{
		return 1;
	}

	if (!(dst = nl_addr_build(AF_INET, dstip, 4))) {
		return 1;
	}

	nl_arp_table_list();
	if (nl_arp_table_lookup(dst, mac)) {
		return 1;
	}
	printf("%s\n",print_mac1(mac));
	return 0;
}
#endif

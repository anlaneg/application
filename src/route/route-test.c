/*
 * route-test.c
 *
 *  Created on: Aug 27, 2018
 *      Author: anlang
 */


#if 0
int main(int argc, char**argv) {
	uint32_t ips[] = { 0x0A0A0A0A, 0x09090909, 0x0a00000a, };
	int idx = 0;
	if (kroute_table_init()) {
		return 1;
	}
	nl_route_table_list();
	for (idx = 0; idx < sizeof(ips) / sizeof(uint32_t); ++idx) {
		uint32_t dst;
		if (kroute_table_lookup_ipv4(ips[idx], &dst)) {
			printf("to %s unreachable\n", print_ip1(&ips[idx]));
		} else {
			printf("via %s to ", print_ip1(&dst));
			printf("%s\n", print_ip1(&ips[idx]));
		}
	}

	return 0;
}
#endif

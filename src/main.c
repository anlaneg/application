#include <stdint.h>
#include <stdio.h>

#include "rte_eal.h"
#include "rte_ethdev.h"

int app_parse_args(int argc,char**argv);

int main(int argc,char**argv)
{
	int ret;
	uint16_t nb_ports;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	argc -= ret;
	argv += ret;
	ret = app_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid app arguments\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
	return 0;
}

int app_parse_args(int argc,char**argv)
{
	int i;
	for(i = 0 ; i < argc; i++)
	{
		printf("argv[%d]=%s\n",i,argv[i]);
	}
	return 0;
}

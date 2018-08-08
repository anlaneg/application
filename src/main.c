#include <stdint.h>
#include <stdio.h>

#include "rte_eal.h"
#include "rte_ethdev.h"
#include "rte_cycles.h"
#include "rte_malloc.h"

int app_parse_args(int argc,char**argv);

struct rte_mempool * app_pktmbuf_pool = NULL;
/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
#define MAX_PKT_BURST 512
#define DEF_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CRC_STRIP,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};
static inline int app_dump_args(int argc,char**argv)
{
	int i;
	printf("======app dump args======\n");
	for(i = 0 ; i < argc; i++)
	{
		printf("argv[%d]=%s\n",i,argv[i]);
	}
	printf("======end dump args======\n\n");
	return 0;
}

static int
poll_burst(void *args)
{
#define MAX_IDLE           (10000)
	struct rte_mbuf *pkts_burst[48];
	unsigned i, nb_rx = 0;
	uint64_t total;
	args=args;

	total = 48;
	printf("start to receive total expect %"PRIu64"\n", total);

	while (1) {
		nb_rx = rte_eth_rx_burst(0, 0,
				&pkts_burst[0],
					RTE_MIN(MAX_PKT_BURST, 48));
		if (unlikely(nb_rx == 0)) {
			continue;
		}
		for(i = 0 ; i < nb_rx ; ++i)
		{
			printf("recv %d packets\n",nb_rx);
			rte_pktmbuf_free(pkts_burst[i]);
		}
	}
	return 0;
}

int main(int argc,char**argv)
{
	int ret;
	uint16_t nb_ports;
	uint32_t nb_mbufs;
	uint16_t portid;

	app_dump_args(argc,argv);	
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

	/* create the mbuf pool */
	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
			RTE_MAX_LCORE * MEMPOOL_CACHE_SIZE), 8192);
	nb_mbufs = RTE_MIN(16384U,nb_mbufs);
	app_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
			MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());
	if (app_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid) {
			struct rte_eth_rxconf rxq_conf;
			struct rte_eth_txconf txq_conf;
			struct rte_eth_conf local_port_conf = port_conf;
			struct rte_eth_dev_info dev_info;

			//nb_ports_available++;

			/* init port */
			printf("Initializing port %u... ", portid);
			fflush(stdout);
			rte_eth_dev_info_get(portid, &dev_info);
			if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
				local_port_conf.txmode.offloads |=
					DEV_TX_OFFLOAD_MBUF_FAST_FREE;
			ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
					  ret, portid);

			ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
							       &nb_txd);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "Cannot adjust number of descriptors: err=%d, port=%u\n",
					 ret, portid);

			//rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);

			/* init one RX queue */
			fflush(stdout);
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = local_port_conf.rxmode.offloads;
			ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
						     rte_eth_dev_socket_id(portid),
						     &rxq_conf,
						     app_pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
					  ret, portid);

			/* init one TX queue on each port */
			fflush(stdout);
			txq_conf = dev_info.default_txconf;
			txq_conf.offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
					rte_eth_dev_socket_id(portid),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
					ret, portid);

#if 0
			/* Initialize TX buffers */
			tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
					RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
					rte_eth_dev_socket_id(portid));
			if (tx_buffer[portid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
						portid);

			rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

			ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
					rte_eth_tx_buffer_count_callback,
					&port_statistics[portid].dropped);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
				"Cannot set error callback for tx buffer on port %u\n",
					 portid);
#endif

			/* Start device */
			ret = rte_eth_dev_start(portid);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
					  ret, portid);

			printf("done: \n");

			rte_eth_promiscuous_enable(portid);
#if 0
			printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
					portid,
					l2fwd_ports_eth_addr[portid].addr_bytes[0],
					l2fwd_ports_eth_addr[portid].addr_bytes[1],
					l2fwd_ports_eth_addr[portid].addr_bytes[2],
					l2fwd_ports_eth_addr[portid].addr_bytes[3],
					l2fwd_ports_eth_addr[portid].addr_bytes[4],
					l2fwd_ports_eth_addr[portid].addr_bytes[5]);

			/* initialize port stats */
			memset(&port_statistics, 0, sizeof(port_statistics));
#endif
		}

	rte_eal_mp_remote_launch(poll_burst, NULL,CALL_MASTER);
	rte_eal_mp_wait_lcore();
	RTE_ETH_FOREACH_DEV(portid) {
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");
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

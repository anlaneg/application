#! /bin/bash

PCI_LIST="00:09.0 00:0a.0"

function dpdk_bind_interface()
{
	
	for i in $PCI_LIST;
	do
		echo "bind $i";
		./dpdk/usertools/dpdk-devbind.py --bind=igb_uio	$i
	done;
}

function prepare_env()
{
	mkdir -p /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge 
	echo 32 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	modprobe uio
	if [  `lsmod | grep -q "igb_uio"` ] ;
	then
		insmod ./dpdk/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
	fi;

	dpdk_bind_interface
	#./dpdk/usertools/dpdk-devbind.py --help
	#./dpdk/usertools/dpdk-devbind.py -b virtio_pci 00:09.0 00:0a.0
	#./dpdk/usertools/dpdk-devbind.py -s
}


prepare_env

./src/build/do

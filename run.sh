#! /bin/bash

function get_virtio_pci_addr()
{
	echo "`lspci | grep "irtio" | cut -d' ' -f 1`"

}
PCI_LIST=`get_virtio_pci_addr`

function build_pci_argment()
{
	for i in $PCI_LIST;
	do
		DPDK_PCI_LIST="$DPDK_PCI_LIST -w $i"
	done;
	echo "$DPDK_PCI_LIST"
}

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
	grep -q "mnt/huge" /proc/mounts && umount /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge 
	echo 64 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	modprobe uio
	if ! `lsmod | grep -q "igb_uio"` ;
	then
		echo "insmod igb_uio"
		insmod ./dpdk/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
	fi;

	dpdk_bind_interface
	#./dpdk/usertools/dpdk-devbind.py --help
	#./dpdk/usertools/dpdk-devbind.py -b virtio_pci 00:09.0 00:0a.0
	#./dpdk/usertools/dpdk-devbind.py -s
}


prepare_env
white_list=`build_pci_argment`

gdb --args ./src/build/do $white_list

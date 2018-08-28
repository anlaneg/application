#! /bin/bash
dirs="common arp route netlink ctrl"
for dir in `echo $dirs`;
do
	echo $dir
	make -C $dir clean
	make -C $dir all
done;

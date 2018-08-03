export RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_SDK=$(CURDIR)/dpdk

all:.dpdk-build-done
	echo $@
	make -C src all

.dpdk-build-done:
	(if [ ! -e ./dpdk/do.sh ] ;then git submodule init ; git submodule update; fi; cd dpdk; ./do.sh ;)
	touch $@

clean:
	echo $@
	make -C src clean

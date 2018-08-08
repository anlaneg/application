#export RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_SDK=$(CURDIR)/dpdk

all:.dpdk-build-done clean
	echo $@
	make V=1 -C src build

.dpdk-build-done:
	(if [ ! -e ./dpdk/do.sh ] ;then git submodule init ; git submodule update; fi; cd dpdk; ./do.sh ;)
	touch $@

clean:
	echo $@
	make V=1 -C src clean
	rm -rf src/build

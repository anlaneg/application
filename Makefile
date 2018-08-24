#export RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_SDK=$(CURDIR)/dpdk

all:submodule_init .dpdk-build-done clean
	echo $@
	make V=1 -C src build

.dpdk-build-done:
	(cd dpdk; ./do.sh ;)
	touch $@

submodule_init:
	git submodule init;
	git submodule update;

clean:
	echo $@
	make V=1 -C src clean
	rm -rf src/build


$(source configure)
include $(AMF_PROJECT_MK_ROOT)/rule.mk

#export RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_SDK=$(CURDIR)/dpdk

#MODULE_BEFORE=app_before
#MODULE_AFTER=app_end

#app_before:
#	@echo "do something before make"

#app_end:
#	@echo "do something after make"

TARGET_TYPE=
SUB_MODULE=kmod
#INCLUDE_PATH+=
#TARGET_NAME=test
include $(AMF_PROJECT_MK_ROOT)/basic.mk


all:submodule_init .dpdk-build-done #clean
	echo $@
	make V=1 -C src build

.dpdk-build-done:
	(cd dpdk; ./do.sh ;) || echo "dpdk error,ignore"
	touch $@

submodule_init:
	git submodule init;
	git submodule update;

clean:
	echo $@
	make V=1 -C src clean
	rm -rf src/build



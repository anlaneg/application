include $(AMF_PROJECT_MK_ROOT)/rule.mk
LIBPKTDUMP_PATH=$(AMF_PROJECT_ROOT)/src/lib/libpktdump
SRCS=pktdump-test.c
TARGET_TYPE=lib
TARGET_NAME=libpktdump.a
INCLUDE_PATH += -I$(LIBPKTDUMP_PATH)/tcpdump \
		-I$(LIBPKTDUMP_PATH)/libpcap \
		-L$(LIBPKTDUMP_PATH)/tcpdump
include $(AMF_PROJECT_MK_ROOT)/basic.mk


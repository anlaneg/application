include $(AMF_PROJECT_MK_ROOT)/rule.mk
LIBNL3_PATH=$(AMF_PROJECT_ROOT)/src/lib/libnl
LIBEVENT_PATH=$(AMF_PROJECT_ROOT)/src/lib/libevent
#C_COMPLIER_FLAGS+= -DSYSCONFDIR=\"/ect/libnl\"
DEPEND_LIBS += -lnl-route-3 -lnl-3 -lcommon -lnl_socket -levent
INCLUDE_PATH += -I$(LIBNL3_PATH)/include -I$(LIBEVENT_PATH)/include -I$(AMF_PROJECT_ROOT)/src/ \
	-L$(LIBNL3_PATH)/lib/.lib/ -L$(LIBEVENT_PATH)/.libs -L$(AMF_PROJECT_ROOT)/src/common/ \
	-L$(AMF_PROJECT_ROOT)/src/netlink
TARGET_TYPE=bin
TARGET_NAME=ctrl

include $(AMF_PROJECT_MK_ROOT)/basic.mk


include $(AMF_PROJECT_MK_ROOT)/rule.mk
LIBNL3_PATH=$(AMF_PROJECT_ROOT)/src/lib/libnl
LIBEVENT_PATH=$(AMF_PROJECT_ROOT)/src/lib/libevent
LIBURCU_PATH=$(AMF_PROJECT_ROOT)/src/lib/liburcu
#C_COMPLIER_FLAGS+= -DSYSCONFDIR=\"/ect/libnl\"
DEPEND_LIBS += -larp -lroute -lnl_socket -lcommon -lnl-route-3 -lnl-3 -levent -lurcu-qsbr -lpthread -lm
INCLUDE_PATH += -I$(LIBNL3_PATH)/include -I$(LIBEVENT_PATH)/include -I$(AMF_PROJECT_ROOT)/src/ \
	-L$(LIBNL3_PATH)/lib/.libs \
	-L$(LIBEVENT_PATH)/.libs \
	-L$(AMF_PROJECT_ROOT)/src/common/ \
	-L$(AMF_PROJECT_ROOT)/src/netlink \
	-L$(AMF_PROJECT_ROOT)/src/arp \
	-L$(AMF_PROJECT_ROOT)/src/route \
	-L$(LIBURCU_PATH)/src/.libs
TARGET_TYPE=bin
TARGET_NAME=ctrl

include $(AMF_PROJECT_MK_ROOT)/basic.mk


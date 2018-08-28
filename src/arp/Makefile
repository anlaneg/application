include $(AMF_PROJECT_MK_ROOT)/rule.mk
LIBNL3_PATH=$(AMF_PROJECT_ROOT)/src/lib/libnl
LIBEVENT_PATH=$(AMF_PROJECT_ROOT)/src/lib/libevent
LIBURCU_PATH=$(AMF_PROJECT_ROOT)/src/lib/liburcu
#C_COMPLIER_FLAGS+= -DSYSCONFDIR=\"/ect/libnl\"
DEPEND_LIBS += -lnl-route-3 -lnl-3 -levent
INCLUDE_PATH += -I$(LIBNL3_PATH)/include -I$(LIBEVENT_PATH)/include \
    -I$(LIBURCU_PATH)/src -I$(LIBURCU_PATH)/include \
	-I$(AMF_PROJECT_ROOT)/src/ \
    -L$(LIBNL3_PATH)/lib/.lib/ \
    -L$(LIBEVENT_PATH)/.libs \
    -L$(LIBURCU_PATH)/src/.libs/
TARGET_TYPE=lib
TARGET_NAME=libarp.a

include $(AMF_PROJECT_MK_ROOT)/basic.mk


include $(AMF_PROJECT_MK_ROOT)/rule.mk
LIBNL3_PATH=$(AMF_PROJECT_ROOT)/src/lib/libnl
LIBEVENT_PATH=$(AMF_PROJECT_ROOT)/src/lib/libevent
DEPEND_LIBS += -lnl-route-3 -lnl-3 -levent
INCLUDE_PATH += -I$(LIBNL3_PATH)/include -I$(LIBEVENT_PATH)/include \
	-I$(AMF_PROJECT_ROOT)/src/ \
	-L$(LIBNL3_PATH)/lib/.lib/ -L$(LIBEVENT_PATH)/.libs
TARGET_TYPE=lib
TARGET_NAME=libroute.a

include $(AMF_PROJECT_MK_ROOT)/basic.mk


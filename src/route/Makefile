include $(AMF_PROJECT_MK_ROOT)/rule.mk
SRCS=nl-router.c
LIBNL3_PATH=$(AMF_PROJECT_ROOT)/src/lib/libnl
DEPEND_LIBS += -lnl-route-3 -lnl-3
INCLUDE_PATH += -I$(LIBNL3_PATH)/include -L$(LIBNL3_PATH)/lib/.lib/
TARGET_TYPE=bin
TARGET_NAME=routesync

include $(AMF_PROJECT_MK_ROOT)/basic.mk


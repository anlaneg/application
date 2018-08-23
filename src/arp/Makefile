include $(AMF_PROJECT_MK_ROOT)/rule.mk
LIBNL3_PATH=$(AMF_PROJECT_ROOT)/src/lib/libnl
#C_COMPLIER_FLAGS+= -DSYSCONFDIR=\"/ect/libnl\"
DEPEND_LIBS += -lnl-route-3 -lnl-3
INCLUDE_PATH += -I$(LIBNL3_PATH)/include -L$(LIBNL3_PATH)/lib/.lib/
TARGET_TYPE=bin
TARGET_NAME=libarp.a

include $(AMF_PROJECT_MK_ROOT)/basic.mk


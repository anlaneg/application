APP = do

# all source are stored in SRCS-y
SRCS-y := main.c

RTE_TARGET ?= x86_64-native-linuxapp-gcc
include $(RTE_SDK)/mk/rte.vars.mk

# binary name


#CFLAGS += -O3
CFLAGS += -g
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk

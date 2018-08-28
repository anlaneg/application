APP = do

# all source are stored in SRCS-y
SRCS-y := main.c netif_rx.c #pktdump.c

RTE_TARGET ?= x86_64-native-linuxapp-gcc
include $(RTE_SDK)/mk/rte.vars.mk

# binary name


#CFLAGS += -O3
CFLAGS += -g 
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(AMF_PROJECT_ROOT)/src/pktdump/
LDFLAGS += -L$(AMF_PROJECT_ROOT)/src/pktdump/ -lpktdump

PREBUILD=make_other
PRECLEAN=clean_other

include $(RTE_SDK)/mk/rte.extapp.mk
make_other:
	make -C $(AMF_PROJECT_ROOT)/src/pktdump all
	#make -C $(AMF_PROJECT_ROOT)/src/arp all
clean_other:
	make -C $(AMF_PROJECT_ROOT)/src/pktdump clean
	make -C $(AMF_PROJECT_ROOT)/src/arp clean

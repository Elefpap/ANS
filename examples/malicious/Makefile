MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
CONTIKI_PROJECT = dis_attack
all: $(CONTIKI_PROJECT)

CONTIKI = ../..
MODULES += os/services/shell
CFLAGS += -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter
CFLAGS += -DMALICIOUS_NODE
include $(CONTIKI)/Makefile.include

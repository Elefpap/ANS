CONTIKI_PROJECT = hello-world
all: $(CONTIKI_PROJECT)

CONTIKI = ../..
MODULES += os/services/shell
CFLAGS += -DRPL_DIS_DEFENSE_ENABLED

include $(CONTIKI)/Makefile.include

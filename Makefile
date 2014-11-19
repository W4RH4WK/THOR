obj-m += thor.o

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

ccflags-y := -I/usr/src/linux

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean


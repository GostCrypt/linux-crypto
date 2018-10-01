KSRC ?= /lib/modules/$(shell uname -r)/build

obj-m := gost28147_generic.o

all: modules

modules modules_install clean:
	make -C $(KSRC) M=$(PWD) $@

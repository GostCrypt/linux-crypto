KSRC ?= /lib/modules/$(shell uname -r)/build

obj-m :=
obj-m += gost28147_generic.o
obj-m += gost-test.o

gost-test-y:= testmgr.o gost-test-main.o

all: modules

modules modules_install clean:
	make -C $(KSRC) M=$(PWD) $@

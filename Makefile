KSRC ?= /lib/modules/$(shell uname -r)/build

CONFIG_CRYPTO_STREEBOG ?= m

obj-m :=
obj-m += gost28147_generic.o
obj-m += gosthash94_generic.o
obj-m += kuznyechik_generic.o
obj-m += magma_generic.o
obj-$(CONFIG_CRYPTO_STREEBOG) += streebog_generic.o
obj-m += gost-test.o

gost-test-y:= testmgr.o gost-test-main.o

ccflags-y := -I $(PWD)

all: modules

modules modules_install clean:
	$(MAKE) -C $(KSRC) M=$(PWD) $@

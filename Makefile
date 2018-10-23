KSRC ?= /lib/modules/$(shell uname -r)/build
#KSRC = $(HOME)/linux/

ifeq ($(wildcard $(PWD)/streebog/*.c),)
CONFIG_CRYPTO_STREEBOG ?= n
else
CONFIG_CRYPTO_STREEBOG ?= m
endif

obj-m :=
obj-m += gost28147_generic.o
obj-m += gosthash94_generic.o
obj-m += kuznyechik_generic.o
obj-m += magma_generic.o
obj-$(CONFIG_CRYPTO_STREEBOG) += streebog_generic.o
obj-m += gost-test.o

gost28147_generic-y := gost28147_basic.o gost28147_modes.o
gost-test-y:= testmgr.o gost-test-main.o

ccflags-y := -I $(PWD)

# Make IS_ENABLED(CONFIG_CRYPTO_STREEBOG) work
ifneq ($(CONFIG_CRYPTO_STREEBOG),n)
ccflags-y += -DCONFIG_CRYPTO_STREEBOG_MODULE=1
endif

all: modules

modules modules_install clean:
	$(MAKE) -C $(KSRC) M=$(PWD) $@

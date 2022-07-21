CONFIG_MODULE_SIG=n

obj-m += ksec.o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement
PWD := $(CURDIR)/build

all:
	mkdir -p build
	cp $(CURDIR)/Makefile $(CURDIR)/build/.
	cp $(CURDIR)/kernel/ksec.c $(CURDIR)/build/.
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	-make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	-rm -rf build

cycle: clean all
	-sudo rmmod ksec
	sudo insmod ./build/ksec.ko


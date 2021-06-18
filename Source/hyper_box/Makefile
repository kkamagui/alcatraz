#
# Makefile for Hyper-box module.
#
CONFIG_MODULE_SIG=n

obj-m = hyper_box.o 
hyper_box-objs := mmu.o monitor.o hypervisor.o asm_helper.o 

KVERSION = $(shell uname -r)

# Disable function reorder
ccflags-y := -fno-toplevel-reorder

%.o: %.asm
	nasm -f elf64 -o $@ $^
	touch "$(PWD)/.asm_helper.o.cmd"

all: 
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules 

clean:
	rm -f *.o
	rm -f *.mod*
	rm -f *.ko
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean


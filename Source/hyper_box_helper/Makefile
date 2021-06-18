#
# Makefile for Hyper-box helper module.
#
CONFIG_MODULE_SIG=n

obj-m := hyper_box_helper.o 
hyper_box_helper-objs := helper.o asm_helper.o 

KVERSION = $(shell uname -r)

# Disable function reorder
ccflags-y := -fno-toplevel-reorder

%.o: %.asm
	nasm -f elf64 -o $@ $^
	touch "$(PWD)/.asm_helper.o.cmd"
all: 
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean


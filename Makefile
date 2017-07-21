obj-m      += ktsdb.o
ktsdb-objs := src/ktsdb.o
ccflags-y   = -I$(PWD)/include -Wall -O2

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	strip --strip-unneeded ktsdb.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


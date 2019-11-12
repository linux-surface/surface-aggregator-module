MODULE_NAME := "surface_sam"
MODULE_VERSION := "0.1"

KVERSION := "$(shell uname -r)"

obj-m += surface_sam.o
surface_sam-objs := surface_sam_base.o
surface_sam-objs += surface_sam_ssh.o
surface_sam-objs += surface_sam_ssh_sysfs.o
surface_sam-objs += surface_sam_san.o
surface_sam-objs += surface_sam_vhf.o
surface_sam-objs += surface_sam_dtx.o
surface_sam-objs += surface_sam_sid.o
surface_sam-objs += surface_sam_sid_gpelid.o
surface_sam-objs += surface_sam_sid_perfmode.o
surface_sam-objs += surface_sam_sid_vhf.o
surface_sam-objs += surface_sam_sid_power.o

sources := Makefile
sources += dkms.conf
sources += surface_sam_base.c
sources += surface_sam_ssh.h
sources += surface_sam_ssh.c
sources += surface_sam_ssh_sysfs.c
sources += surface_sam_san.c
sources += surface_sam_vhf.c
sources += surface_sam_dtx.c
sources += surface_sam_sid.c
sources += surface_sam_sid_gpelid.c
sources += surface_sam_sid_perfmode.c
sources += surface_sam_sid_vhf.c
sources += surface_sam_sid_power.c

ccflags-y := -DDEBUG

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

dkms-install: $(sources)
	mkdir -p /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/
	cp -t /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/ $(sources)
	dkms add $(MODULE_NAME)/$(MODULE_VERSION)
	dkms build $(MODULE_NAME)/$(MODULE_VERSION)
	dkms install $(MODULE_NAME)/$(MODULE_VERSION)

dkms-uninstall:
	modprobe -r $(MODULE_NAME) || true
	dkms uninstall $(MODULE_NAME)/$(MODULE_VERSION) || true
	dkms remove $(MODULE_NAME)/$(MODULE_VERSION) --all || true
	rm -rf /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/

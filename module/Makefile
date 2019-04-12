MODULE_NAME := "surfacegen5_acpi"
MODULE_VERSION := "0.1"

KVERSION := "$(shell uname -r)"

obj-m += surfacegen5_acpi.o
surfacegen5_acpi-objs := surfacegen5_acpi_base.o
surfacegen5_acpi-objs += surfacegen5_acpi_ssh.o
surfacegen5_acpi-objs += surfacegen5_acpi_ssh_sysfs.o
surfacegen5_acpi-objs += surfacegen5_acpi_san.o
surfacegen5_acpi-objs += surfacegen5_acpi_vhf.o
surfacegen5_acpi-objs += surfacegen5_acpi_dtx.o
surfacegen5_acpi-objs += surfacegen5_acpi_sid.o

sources := Makefile
sources += dkms.conf
sources += surfacegen5_acpi_base.c
sources += surfacegen5_acpi_ssh.h
sources += surfacegen5_acpi_ssh.c
sources += surfacegen5_acpi_ssh_sysfs.c
sources += surfacegen5_acpi_san.c
sources += surfacegen5_acpi_vhf.c
sources += surfacegen5_acpi_dtx.c
sources += surfacegen5_acpi_sid.c

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

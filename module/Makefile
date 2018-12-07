MODULE_NAME := "surfacegen5_acpi_notify"
MODULE_VERSION := "0.1"

KVERSION := "$(shell uname -r)"

obj-m += surfacegen5_acpi_notify.o
surfacegen5_acpi_notify-objs := surfacegen5_acpi_notify_base.o
surfacegen5_acpi_notify-objs += surfacegen5_acpi_notify_ssh.o
surfacegen5_acpi_notify-objs += surfacegen5_acpi_notify_san.o
surfacegen5_acpi_notify-objs += surfacegen5_acpi_notify_vhf.o

sources := Makefile
sources += dkms.conf
sources += surfacegen5_acpi_notify_base.c
sources += surfacegen5_acpi_notify_ssh.h
sources += surfacegen5_acpi_notify_ssh.c
sources += surfacegen5_acpi_notify_san.c
sources += surfacegen5_acpi_notify_vhf.c

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

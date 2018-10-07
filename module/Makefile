MODULE_NAME := "surfacegen5_acpi_notify"
MODULE_VERSION := "0.1"

KVERSION := "$(shell uname -r)"

obj-m += surfacegen5_acpi_notify.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

dkms-install: surfacegen5_acpi_notify.c dkms.conf Makefile
	mkdir -p /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/
	cp surfacegen5_acpi_notify.c /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/
	cp dkms.conf /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/
	cp Makefile /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/
	dkms add $(MODULE_NAME)/$(MODULE_VERSION)
	dkms build $(MODULE_NAME)/$(MODULE_VERSION)
	dkms install $(MODULE_NAME)/$(MODULE_VERSION)

dkms-uninstall:
	modprobe -r $(MODULE_NAME) || true
	dkms uninstall $(MODULE_NAME)/$(MODULE_VERSION) || true
	dkms remove $(MODULE_NAME)/$(MODULE_VERSION) --all || true
	rm -rf /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/

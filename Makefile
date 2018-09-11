MODULE_NAME := "sb2_mshw0153"
MODULE_VERSION := "0.1"

KVERSION := "$(shell uname -r)"

obj-m += sb2_mshw0153.o

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

dkms-install: sb2_mshw0153.c dkms.conf Makefile
	mkdir -p /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/
	cp sb2_mshw0153.c /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/
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

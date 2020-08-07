# SPDX-License-Identifier: GPL-2.0-or-later
MODULE_NAME := "surface_sam"
MODULE_VERSION := "0.1"

KVERSION := "$(shell uname -r)"

sources-dkms := dkms.conf
sources-dkms += Makefile


all:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(shell pwd)/src modules

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(shell pwd)/src clean

dkms-install: clean
	mkdir -p /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/
	cp -rt /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/ src/
	cp -rt /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/ include/
	cp -t /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/ $(sources-dkms)
	dkms add $(MODULE_NAME)/$(MODULE_VERSION)
	dkms build $(MODULE_NAME)/$(MODULE_VERSION)
	dkms install $(MODULE_NAME)/$(MODULE_VERSION)

dkms-uninstall:
	modprobe -r $(MODULE_NAME) || true
	dkms uninstall $(MODULE_NAME)/$(MODULE_VERSION) || true
	dkms remove $(MODULE_NAME)/$(MODULE_VERSION) --all || true
	rm -rf /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/

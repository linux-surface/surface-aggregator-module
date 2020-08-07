# SPDX-License-Identifier: GPL-2.0-or-later
MODULE_NAME := "surface_sam"
MODULE_VERSION := "0.1"

KVERSION := "$(shell uname -r)"
KDIR := /lib/modules/$(KVERSION)/build
MDIR := /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)


sources-dkms := dkms.conf
sources-dkms += Makefile


all:
	$(MAKE) -C $(KDIR) M=$(shell pwd)/src modules

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd)/src clean

dkms-install: clean
	mkdir -p $(MDIR)
	cp -rt $(MDIR)/ src/
	cp -rt $(MDIR)/ include/
	cp -t $(MDIR)/ $(sources-dkms)
	dkms add $(MODULE_NAME)/$(MODULE_VERSION)
	dkms build $(MODULE_NAME)/$(MODULE_VERSION)
	dkms install $(MODULE_NAME)/$(MODULE_VERSION)

dkms-uninstall:
	modprobe -r $(MODULE_NAME) || true
	dkms uninstall $(MODULE_NAME)/$(MODULE_VERSION) || true
	dkms remove $(MODULE_NAME)/$(MODULE_VERSION) --all || true
	rm -rf $(MDIR)

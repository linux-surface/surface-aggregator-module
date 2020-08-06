# SPDX-License-Identifier: GPL-2.0-or-later
MODULE_NAME := "surface_sam"
MODULE_VERSION := "0.1"

KVERSION := "$(shell uname -r)"

sources-core := Makefile
sources-core += Kbuild
sources-core += dkms.conf
sources-core += surface_sam_ssh.h
sources-core += surface_sam_ssh_trace.h
sources-core += surface_sam_ssh.c

sources-clients := clients/Kbuild
sources-clients += clients/surface_sam_san.c
sources-clients += clients/surface_sam_san.h
sources-clients += clients/surface_sam_vhf.c
sources-clients += clients/surface_sam_dtx.c
sources-clients += clients/surface_sam_hps.c
sources-clients += clients/surface_sam_sid.c
sources-clients += clients/surface_sam_sid_gpelid.c
sources-clients += clients/surface_sam_sid_perfmode.c
sources-clients += clients/surface_sam_sid_vhf.c
sources-clients += clients/surface_sam_sid_vhf.h
sources-clients += clients/surface_sam_sid_power.c
sources-clients += clients/surface_sam_sid_power.h
sources-clients += clients/surface_sam_debugfs.c

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

dkms-install: $(sources-core) $(sources-clients)
	mkdir -p /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/clients
	cp -t /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/ $(sources-core)
	cp -t /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/clients $(sources-clients)
	dkms add $(MODULE_NAME)/$(MODULE_VERSION)
	dkms build $(MODULE_NAME)/$(MODULE_VERSION)
	dkms install $(MODULE_NAME)/$(MODULE_VERSION)

dkms-uninstall:
	modprobe -r $(MODULE_NAME) || true
	dkms uninstall $(MODULE_NAME)/$(MODULE_VERSION) || true
	dkms remove $(MODULE_NAME)/$(MODULE_VERSION) --all || true
	rm -rf /usr/src/$(MODULE_NAME)-$(MODULE_VERSION)/

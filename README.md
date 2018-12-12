# Linux ACPI (Platform) Driver for 5th Gen. Surface Devices

Work in progress, use at your own risk.

Linux embedded controller driver for 5th gen. Surface devices (Surface Book 2, Surface Pro 2017, Surface Laptop), required for battery status and more.

## Testing

To test this module, you need a custom kernel with the patches found in this repository applied.
For a full set of patches including Jake's linux-surface patches, see [this][patches-linux-surface] fork.
Furthermore, you need to ensure that the following config values are set:

```
CONFIG_SERIAL_DEV_BUS=y
CONFIG_SERIAL_DEV_CTRL_TTYPORT=y
```

There is a pre-compiled kernel available [here][prebuilt-linux-surface].

If you have all the prequisites, you can

### Build/Test the module

You can build the module with `make`.
After that, you can load the module with `insmod surfacegen5_acpi_notify`, and after testing remove it with `rmmod surfacegen5_acpi_notify`.

### Permanently install the module

If you want to permanently install the module (or ensure it is loaded during boot), you can run `make dkms-install`.
To uninstall it, run `make dkms-uninstall`.

[patches-linux-surface]: https://github.com/qzed/linux-surface/tree/master/patches/4.18
[prebuilt-linux-surface]: https://github.com/qzed/linux-surface/releases/tag/v4.18.16-pre1

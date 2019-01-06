# Linux ACPI (Platform) Drivers for 5th Gen. Surface Devices

Linux embedded controller driver for 5th generation (and later) Surface devices required for battery status and more.

_This has now been integrated into [jakeday/linux-surface](https://github.com/jakeday/linux-surface/)._

## Supported Features and Devices

| Device           | Supported Features          | Unconfirmed    | Known Issues/Missing Features                  |
|------------------|-----------------------------|----------------|------------------------------------------------|
| Surface Book 2   | lid status, battery status  | thermal events | proper clipboard detach events (#7)            |
| Surface Laptop   | battery status, keyboard    |                | caps-lock indicator (#8)                       |
| Surface Laptop 2 | battery status, keyboard    |                | caps-lock indicator (#8)                       |
| Surface Pro 2017 | battery status              |                | keyboard backlight enabled during suspend (#4) |
| Surface Pro 6    | battery status              |                | keyboard backlight enabled during suspend (#4) |

If you think there's anything missing here, feel free to open an issue!

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
After that, you can load the module with `insmod surfacegen5_acpi.ko`, and after testing remove it with `rmmod surfacegen5_acpi`.

### Permanently install the module

If you want to permanently install the module (or ensure it is loaded during boot), you can run `make dkms-install`.
To uninstall it, run `make dkms-uninstall`.

[patches-linux-surface]: https://github.com/qzed/linux-surface/tree/master/patches/4.18
[prebuilt-linux-surface]: https://github.com/qzed/linux-surface/releases/tag/v4.18.16-pre1


## Donations

_I can't really guarantee you anything._
_I can't promise you the support you may want._
_I'm doing this in my free time and I only have a Surface Book 2._
_I'll try to do my best, but it may take a while or at worst, your issue may never get resolved._
_Also please do not donate if you need the money, you probably need it more than me._
If that can't stop you:
https://www.paypal.me/maximilianluz
Don't get me wrong though, I do appreciate your donations.
Thank you for your support!

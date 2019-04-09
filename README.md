# Linux Kernel Module for MSHW0153

Linux Kernel Module for the Surface Hot-Plug System (`MSHW0153`).

## Setting the dGPU Power State

The dGPU power state can be accessed via
```
/sys/bus/acpi/devices/MSHW0153:00/physical_node/dgpu_power
```
i.e. it can be queried and set via this attribute using your standard boolean parameter strings (meaning one of `off`/`0`/`n` or `on`/`1`/`y`).

## Module Parameters

- `dgpu_power_init`:
  - Description: The power-state to set when loading this module.
  - Values: `0` (off), `1` (on), `2` (as is).
  - Default: `0` (off).

- `dgpu_power_exit`:
  - Description: The power-state to set when unloading this module.
  - Values: `0` (off), `1` (on), `2` (as is).
  - Default: `0` (off).

## Building the Module

Run `make all` inside this folder.
The module can then be loaded via `insmod sb2_shps.ko` (and removed with `rmmod sb2_shps.ko`).

### Permanently Install the Module

#### On Arch-Linux

Simply run `makepkg -si` inside this folder.

#### Via DKMS

If you want to permanently install the module (or ensure it is loaded during boot), you can run `make dkms-install`.
To uninstall it, run `make dkms-uninstall`.

# Linux Kernel Module for MSHW0153

This module is currently only for trying to figure out what `MSHW0153` on the Surface Book 2 does, specifically what the GPIO interrupts and values it provides indicate.

`MSHW0153` is related to the base of the Surface Book 2, it may indicate the general connection status of the base, or devices in the base, such as the dedicated GPU.

Currently it just prints the GPIO values when loaded, and the following interrupts triggered by them.

## Building the Module

Run

```shell
make all
```

inside this folder.
The module can then be loaded via `insmod sb2_mshw0153.ko` (and removed with `rmmod sb2_mshw0153.ko`).

## Getting Debug Output

Once the module has been loaded, run

```shell
dmesg -w | grep mshw0153
```

You can now disconnect the top from the base and you should see some interrupt messages appear in the terminal.
You should see similar messages when re-attaching them.

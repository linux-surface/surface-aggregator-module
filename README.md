# Linux Driver for Surface Book 2 dGPU Hot-Plug System

_Warning: In the latest version, the name of the module and Arch Linux package has been changed to `surfacebook2_dgpu_hps` and `surfacebook2-dgpu-hps` respectively._

Allows powering on/off of the discrete GPU via sysfs.

_This is not a complete replacement of bbswitch/prime, so you need to manually unload/re-load the driver modules before/after changing the power-state.
Furthermore, you manually need to set the powerstate before running e.g. `optirun`._

## Controlling the dGPU Power State

The easiest way to change the dGPU power state is to use the [surface](https://github.com/qzed/linux-surface-control) command line utility.
With it installed, simply run `sudo surface dgpu set <state>` where `<state>` is either `on` or `off`.
Alternatively, the dGPU power state can be accessed via its sysfs attribute
```
/sys/bus/acpi/devices/MSHW0153:00/physical_node/dgpu_power
```
i.e. it can be queried and set via this attribute using your standard boolean parameter strings (meaning one of `off`/`0`/`n` or `on`/`1`/`y`).

_Warning:_
It is strongly recommended you unload the graphics driver (e.g. `nvidia` or `nouveau`) before disabling the dGPU dynamically.
While it seems possible to disable the dGPU with the `nvidia` driver loaded programs using it will crash even though the driver itself won't.
Unloading the module only succeeds when no program is using the dGPU and is therefore safe step to avoid such crashes.

### Via Module Parameters

The dGPU power-state can also be automatically set when this module is loaded or unloaded via the following module parameters:

- `dgpu_power_init`:
  - Description: The power-state to set when loading this module.
  - Values: `0` (off), `1` (on), `-1` (as is).
  - Default: `0` (off).


- `dgpu_power_exit`:
  - Description: The power-state to set when unloading this module.
  - Values: `0` (off), `1` (on), `-1` (as is).
  - Default: `0` (off).

_Warning:_
By default, the dGPU is turned off when the module loads and unloads, changing this behavior may have unwanted side-effects.
Some desktop-environments (including Gnome) claim the dGPU when it is turned on during their initialization phase.
This will result in you being unable to unload the graphics driver and ultimately crashes or hang-ups when you disable the dGPU dynamically.
Keeping the dGPU disabled during this initialization phase avoids this problem, so if you want the dGPU to be permanently powered on, you may want to write a script that runs after you log in into your desktop environment.

## Building the Module

Run `make all` inside the `module` directory.
The module can then be loaded via `insmod surfacebook2_dgpu_hps.ko` (and removed with `rmmod surfacebook2_dgpu_hps.ko`).

### Permanently Install the Module

#### On Arch-Linux

Simply run `makepkg -si` inside the `module` directory.

#### Via DKMS

If you want to permanently install the module (or ensure it is loaded during boot), you can run `make dkms-install` inside the `module` directory.
To uninstall it, run `make dkms-uninstall`.

## Setting-Up the dGPU for use with `bumblebee` and the Official Nvidia Driver on Arch Linux

This should be similar on other distributions, as always, consult your respective help-pages and wikis.
For this, I assume you have the [surface](https://github.com/qzed/linux-surface-control) command line utility installed.
Alternatively, have a look above on how to turn on/off the dGPU manually via sysfs.

To set-up the dGPU

1. Install the nvidia driver (e.g. `nvidia-dkms`).
   Note that, if you have a custom kernel, it is important you choose a locally compiled version (as usually indicated by the `-dkms` suffix).
2. Install `bumblebee`.
3. Add your user to the `bumblebee` group (e.g. `usermod -a -G bumblebee <yourusername>`).
7. Enable `bumblebeed.service` (`systemctl enable bumblebeed.service`).
   Alternatively, you can also start/stop the service before/after each use.
4. Reboot.

Now you can actually use the dGPU. I recommend putting the commands below into a simple wrapper script.

5. Turn on dGPU, e.g. via `sudo surface dgpu set on`.
6. Load the Nvidia modules (`sudo nvidia-modprobe`).
7. If you encounter a message indicating that the Bumblebee daemon has not been startet yet, you may need to wait a bit for `bumblebeed.service` to become active or alternatively run `systemctl start bumblebeed.service`.
8. Run your desired application on the dGPU with `optirun <application>`. To verify the Nvidia GPU is actually used, you can run `optirun glxgears -v`.

To fully disable the dGPU (e.g. for power-savings)

9. Close all applications using the dGPU.
10. Unload the Nvidia driver modules (`sudo modprobe -r nvidia_modeset` followed by `sudo modprobe -r nvidia`).
    If you encounter a message specifying that the `nvidia` module is in use, you either have other modules depending on the `nvidia` driver, which you need to unload, or applications using it, which you need to close.
11. Turn off the dGPU, e.g. via `sudo surface dgpu set off`.

Additionally, I recommend adjusting the performance mode of your device to your needs, e.g. by running `sudo surface performance set 4` to set the device to best-performance mode or `sudo surface performance set 1` to set the device to the default performance mode.
This has a direct influence on the cooling strategy of the device.
See the help-text printed when running `surface performance` for more details on this.

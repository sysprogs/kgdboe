# KGDBoE - Kernel Debug over Ethernet

KGDBoE is a kernel module to debug Linux kernel on a bare metal using network connection over an ethernet cable. - a kernel module that allows debugging the Linux kernel using the network connection. It is useful on modern PCs that don't have a serial port or a JTAG connector and it's much faster than using a COM port.

KGDBoE is inspired by the original kgdboe patches by Jason Wessel, but goes well beyond the capabilities of the original tool. The key features are:
* Works with stock kernels without rebuilding them. Tested on Linux Kernels: 3.8.0-5.15.0, 5.19.0, 6.3.x
* Easy configuration. No need to specify the IP or MAC addresses
* Supports modern multi-core systems
* It was tested on pcnet32, r8169 and e1000 network drivers

## Build

```sh
git clone https://github.com/sysprogs/kgdboe.git
cd kgdboe
make -C /lib/modules/$(uname -r)/build M=$(pwd)
```

## Load

```sh
sudo insmod kgdboe.ko kallsyms_lookup_name_address=0x$(sudo cat /proc/kallsyms | grep 'T kallsyms_lookup_name' | awk '{print $1}') device_name=eth0
```

Then, you should see log information whether kgdboe succeeded or failed to load in the output of `sudo dmesg --follow`.

## Use (remote)

```sh
gdb /boot/vmlinuz
target remote udp:<IP>:31337
```

Note: it is best that the GDB client is running on Linux (an attempt to use MacOS did not work). Also, prefer to use latest GDB. GDB 13.1 should work.

## Debug kernel module

Find out module address
```sh
sudo grep modulename /proc/modules
modulename 1073152 5 - Live 0xffffffffa0120000
```
In the gdb (remote)
```sh
add-symbol-file drivers/char/modulename.ko 0xffffffffa0120000
```

## Configuration / kernel module parameters

* `kallsyms_lookup_name_address=0x...` -- address of the `kallsyms_lookup_name` symbol
* `device_name=eth0` -- Ethernet device to use for debugging.
* `local_ip` -- Local IP address to bind to. Auto-detected if not specified.
* `udp_port=31337` -- UDP port to use for debugging.
* `force_single_core=1` -- Disable all cores except \#0 when the module is loaded. This setting is recommended unless you are debugging SMP-specific issues, as it avoids many synchronization problems. KGDBoE can reliably work in the SMP mode, but it has not been tested on all network drivers, so use caution if you decide to disable this.

## Limitations
KGDBoE uses some of the network stack code to communicate with GDB. Setting breakpoints in the code that is used by it would deadlock your debugging session. Follow the tips below to avoid it:
* Don't set breakpoints in the network code
* Don't set breakpoints in `mod_timer()` unless you're using the single-CPU mode
* Use the single-CPU mode unless you absolutely need SMP. Although KGDBoE includes workarounds for multi-CPU mode, they are based on making assumptions about the network driver internals and can be safely avoided by disabling all CPUs except \#0 during debugging.

## License
The source code is available under the GPL license.

Source: http://sysprogs.com/VisualKernel/kgdboe/

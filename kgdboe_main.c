/*
* A network interface for GDB for 3.x kernels.
* Inspired by the original 'kgdboe' by Jason Wessel <jason.wessel@windriver.com>
* that seems abandoned as of 2014.
*
* (c) 2014 Sysprogs OU <sysprogs@sysprogs.com>
*
* Supported kernel versions: 3.8.x - 3.15.x
*
* Usage:
*	1. Build the module: make -C /lib/modules/$(uname -r)/build M=$(pwd)
*   2. Load the module: insmod kgdboe.ko [device_name=ethX] [udp_port=Y]
*	3. Check the load status: dmesg | tail
*	4. Connect from gdb: target remote udp:<ip>:<port>
*
* WARNING! Using a network driver as a transport on multi-core systems is tricky! 
*		   KGDB does not fully know what spinlocks/resources the network driver needs
*		   and if another core has been stopped while holding them, the debugger will hang.
*		   This module does its best to avoid it by hooking resources that are likely required
*		   by the network driver, but there is no 100% guarantee that your driver does not take
*		   anything extra. It has been tested on the following network drivers:
*				pcnet32
*				e1000
*				r8169
*		   Nonetheless, by default it will disable all cores except #0 and will not do the hooking.
*		   If you absolutely need SMP while debugging, use the force_single_core=0 parameter to override,
*          but be ready to troubleshoot your network driver if it is different from the ones listed above. 
*
* This file is licensed under the terms of the GNU General Public License
* version 2. This program is licensed "as is" without any warranty of any
* kind, whether express or implied.
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include "netpoll_wrapper.h"
#include "kgdboe_io.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KGDBoE - A Network Based KGDB Extension");

#include <linux/timer.h>

#ifndef CONFIG_KGDB
#error Your kernel is built without support for KGDB (kernel debugger). Please rebuild your kernel with CONFIG_KGDB enabled.
#endif

static int udp_port = 31337;
module_param(udp_port, int, 0444);

static char *device_name = "ens33";
module_param(device_name, charp, 0444);

static char *local_ip = NULL;
module_param(local_ip, charp, 0444);

static int force_single_core = 1;
module_param(force_single_core, int, 0444);

uint64_t kallsyms_lookup_name_address;
module_param(kallsyms_lookup_name_address, ullong, 0444);

static int __init kgdboe_init(void)
{
	if (!kallsyms_lookup_name_address)
	{
		printk(KERN_ERR "kgdboe: this kernel version requires specifying the address of kallsyms_lookup_name explicitly. Please append 'kallsyms_lookup_name_address=0x...' to insmod command line.\n");
		return -EINVAL;
	}
	
	int err = kgdboe_io_init(device_name, udp_port, local_ip, force_single_core != 0);
	if (err != 0)
		return err;

	return 0;
}

static void __exit kgdboe_exit(void)
{
	kgdboe_io_cleanup();
}

module_init(kgdboe_init);
module_exit(kgdboe_exit);

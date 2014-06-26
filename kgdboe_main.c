#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include "netpoll_wrapper.h"
#include "kgdboe_io.h"

MODULE_LICENSE("GPL");

#include <linux/timer.h>

static int udp_port = 31337;
module_param(udp_port, int, 0444);

static char *device_name = "eth0";
module_param(device_name, charp, 0444);

static char *local_ip = NULL;
module_param(local_ip, charp, 0444);

static int force_single_core = 1;
module_param(force_single_core, int, 0444);

static int __init kgdboe_init(void)
{
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

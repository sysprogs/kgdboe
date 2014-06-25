#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/cpu.h>
#include "netpoll_wrapper.h"
#include "kgdboe_io.h"

MODULE_LICENSE("GPL");

#include <linux/timer.h>

void force_single_cpu_mode(void)
{
	printk(KERN_INFO "kgdboe: single-core mode enabled. Shutting down all cores except #0\n");
	for (int i = 1; i < nr_cpu_ids; i++)
		cpu_down(i);
}

static int __init kgdboe_init(void)
{
	int err = kgdboe_io_init();
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

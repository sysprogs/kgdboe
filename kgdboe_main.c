#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include "netpoll_wrapper.h"
#include "kgdboe_io.h"

MODULE_LICENSE("GPL");

#include <linux/timer.h>

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

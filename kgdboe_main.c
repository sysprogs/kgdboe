#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include "netpoll_wrapper.h"

MODULE_LICENSE("GPL");

static struct netpoll_wrapper *pWrapper;

volatile char n = 0;

static void synced_action(void *pContext)
{

}

static void rx_handler(void *pContext, int port, char *msg, int len)
{
	if (len > 0)
		n = msg[0];
}

#include <linux/timer.h>

struct timer_list s_timer;

volatile int test;

static void test_timer(unsigned long __opaque)
{
	mod_timer(&s_timer, jiffies + HZ);
	if (test)
	{
		n = 0;
		while (n == 0)
			netpoll_wrapper_poll(pWrapper);

		char ch = n + 1;
		netpoll_wrapper_send_reply(pWrapper, &n, 1);
	}
}

static int __init kgdboe_init(void)
{
	printk("kgdboe: Hello, world!\n");
	pWrapper = netpoll_wrapper_create("eth0", 31337, NULL);
	if (!pWrapper)
		return -EINVAL;

	netpoll_wrapper_set_callbacks(pWrapper, rx_handler, synced_action, NULL);

	init_timer(&s_timer);
	s_timer.function = test_timer;
	mod_timer(&s_timer, jiffies + (HZ / 10));

	return 0;
}

static void __exit kgdboe_exit(void)
{
	printk("kgdboe: Goodbye, world!\n");
	netpoll_wrapper_free(pWrapper);
	del_timer(&s_timer);
}

module_init(kgdboe_init);
module_exit(kgdboe_exit);

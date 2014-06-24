#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include "netpoll_wrapper.h"
#include "kgdboe_io.h"

MODULE_LICENSE("GPL");

#include <linux/timer.h>

struct timer_list s_timer;

volatile int test;

void nethook_service();

static void test_timer(unsigned long __opaque)
{
	mod_timer(&s_timer, jiffies + HZ / 10);
	nethook_service();


	if (test)
	{
		/*n = 0;
		while (n == 0)
			netpoll_wrapper_poll(pWrapper);*/
		
		//char ch = n + 1;
		//netpoll_wrapper_send_reply(pWrapper, &n, 1);
	}
}

static int __init kgdboe_init(void)
{
	int err = kgdboe_io_init();
	if (err != 0)
		return err;

	init_timer(&s_timer);
	s_timer.function = test_timer;
	mod_timer(&s_timer, jiffies + (HZ / 10));

	return 0;
}

static void __exit kgdboe_exit(void)
{
	kgdboe_io_cleanup();
	del_timer(&s_timer);
}

module_init(kgdboe_init);
module_exit(kgdboe_exit);

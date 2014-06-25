#include <linux/kgdb.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include "kgdboe_io.h"
#include "netpoll_wrapper.h"
#include "nethook.h"

struct netpoll_wrapper *s_pKgdboeNetpoll;

static char s_IncomingRingBuffer[4096];
static volatile int s_IncomingRingBufferReadPosition;
static volatile int s_IncomingRingBufferWritePosition;

static char s_OutgoingBuffer[30];
static volatile int s_OutgoingBufferUsed;

static bool s_StoppedInKgdb;

static void(*pkgdb_roundup_cpus)(void);

static void kgdboe_rx_handler(void *pContext, int port, char *msg, int len)
{
	BUG_ON(!s_pKgdboeNetpoll);

	bool breakpointPending = false;

	if (!kgdb_connected && (len != 1 || msg[0] == 3))
		breakpointPending = true;

	for (int i = 0; i < len; i++) 
	{
		if (msg[i] == 3)
			breakpointPending = true;

		s_IncomingRingBuffer[s_IncomingRingBufferWritePosition++] = msg[i];
		s_IncomingRingBufferWritePosition %= sizeof(s_IncomingRingBuffer);
	}

	if (breakpointPending && !s_StoppedInKgdb)
		kgdb_schedule_breakpoint();
}

static spinlock_t exception_lock;

static void kgdboe_pre_exception(void)
{
	spin_lock(&exception_lock);
	if (!kgdb_connected)
		try_module_get(THIS_MODULE);

	s_StoppedInKgdb = true;

	hold_irq_enabling();
	take_hooked_spinlocks();
	netpoll_wrapper_set_drop_flag(s_pKgdboeNetpoll, true);
}

static void kgdboe_post_exception(void)
{
	if (!kgdb_connected)
		module_put(THIS_MODULE);

	s_StoppedInKgdb = false;
	netpoll_wrapper_set_drop_flag(s_pKgdboeNetpoll, false);

	enable_queued_irqs();
	spin_unlock(&exception_lock);
}

volatile bool testReply = false;


static int kgdboe_read_char(void)
{
	save_hooked_spinlocks();

	BUG_ON(!s_pKgdboeNetpoll);
	
	while (s_IncomingRingBufferReadPosition == s_IncomingRingBufferWritePosition)
		netpoll_wrapper_poll(s_pKgdboeNetpoll);

	char result = s_IncomingRingBuffer[s_IncomingRingBufferReadPosition++];
	s_IncomingRingBufferReadPosition %= sizeof(s_IncomingRingBuffer);

	if (testReply)
	{
		netpoll_wrapper_send_reply(s_pKgdboeNetpoll, &result, 1);
	}

	restore_hooked_spinlocks();
	return result;
}

static void kgdboe_flush(void)
{
	if (s_OutgoingBufferUsed) 
	{
		save_hooked_spinlocks();
		netpoll_wrapper_send_reply(s_pKgdboeNetpoll, s_OutgoingBuffer, s_OutgoingBufferUsed);
		s_OutgoingBufferUsed = 0;
		restore_hooked_spinlocks();
	}
}

static void kgdboe_write_char(u8 chr)
{
	s_OutgoingBuffer[s_OutgoingBufferUsed++] = chr;
	if (s_OutgoingBufferUsed == sizeof(s_OutgoingBuffer))
		kgdboe_flush();
}


static struct kgdb_io kgdboe_io_ops = {
	.name = "kgdboe",
	.read_char = kgdboe_read_char,
	.write_char = kgdboe_write_char,
	.flush = kgdboe_flush,
	.pre_exception = kgdboe_pre_exception,
	.post_exception = kgdboe_post_exception
};

void hook_netdev(struct net_device *pNetDev);

int kgdboe_io_init(void)
{
	spin_lock_init(&exception_lock);
	pkgdb_roundup_cpus = kallsyms_lookup_name("kgdb_roundup_cpus");
	
	if (!pkgdb_roundup_cpus)
	{
		printk(KERN_ERR "kgdboe: cannot find kgdb_roundup_cpus(). Aborting...\n");
		return -EINVAL;
	}

	s_pKgdboeNetpoll = netpoll_wrapper_create("eth0", 6443, 6444, NULL);
	if (!s_pKgdboeNetpoll)
		return -EINVAL;

	hook_netdev(s_pKgdboeNetpoll->pDeviceWithHandler);

	int err = kgdb_register_io_module(&kgdboe_io_ops);
	if (err != 0)
	{
		netpoll_wrapper_free(s_pKgdboeNetpoll);
		s_pKgdboeNetpoll = NULL;
		return err;
	}

	netpoll_wrapper_set_callback(s_pKgdboeNetpoll, kgdboe_rx_handler, NULL);
	printk(KERN_INFO "kgdboe: Successfully initialized. Don't forget to run the flow control program on the other PC.\n");

	return 0;
}

void kgdboe_io_cleanup(void)
{
	netpoll_wrapper_free(s_pKgdboeNetpoll);
	s_pKgdboeNetpoll = NULL;
}
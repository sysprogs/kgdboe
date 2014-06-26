#include <linux/kgdb.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/cpu.h>
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

static void kgdboe_rx_handler(void *pContext, int port, char *msg, int len)
{
	bool breakpointPending = false;

	BUG_ON(!s_pKgdboeNetpoll);

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

	nethook_take_relevant_resources();
	netpoll_wrapper_set_drop_flag(s_pKgdboeNetpoll, true);
}

static void kgdboe_post_exception(void)
{
	if (!kgdb_connected)
		module_put(THIS_MODULE);

	s_StoppedInKgdb = false;
	netpoll_wrapper_set_drop_flag(s_pKgdboeNetpoll, false);

	nethook_release_relevant_resources();
	spin_unlock(&exception_lock);
}

static int kgdboe_read_char(void)
{
	char result;
	nethook_netpoll_work_starting();

	BUG_ON(!s_pKgdboeNetpoll);
	
	while (s_IncomingRingBufferReadPosition == s_IncomingRingBufferWritePosition)
		netpoll_wrapper_poll(s_pKgdboeNetpoll);

	result = s_IncomingRingBuffer[s_IncomingRingBufferReadPosition++];
	s_IncomingRingBufferReadPosition %= sizeof(s_IncomingRingBuffer);

	nethook_netpoll_work_done();
	return result;
}

static void kgdboe_flush(void)
{
	if (s_OutgoingBufferUsed) 
	{
		nethook_netpoll_work_starting();
		netpoll_wrapper_send_reply(s_pKgdboeNetpoll, s_OutgoingBuffer, s_OutgoingBufferUsed);
		s_OutgoingBufferUsed = 0;
		nethook_netpoll_work_done();
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

void force_single_cpu_mode(void)
{
	printk(KERN_INFO "kgdboe: single-core mode enabled. Shutting down all cores except #0. This is slower, but safer.\n");
	printk(KERN_INFO "kgdboe: you can try using multi-core mode by specifying the following argument:\n");
	printk(KERN_INFO "\tinsmod kgdboe.ko force_single_core = 0\n");
	for (int i = 1; i < nr_cpu_ids; i++)
		cpu_down(i);
}

int kgdboe_io_init(const char *device_name, int port, const char *local_ip, bool force_single_core)
{
	int err;
	u8 ipaddr[4];

	spin_lock_init(&exception_lock);

	s_pKgdboeNetpoll = netpoll_wrapper_create(device_name, port, local_ip);
	if (!s_pKgdboeNetpoll)
		return -EINVAL;
	
	if (force_single_core)
	{
		force_single_cpu_mode();
	}
	else if (!nethook_initialize(s_pKgdboeNetpoll->pDeviceWithHandler))
	{
		printk(KERN_ERR "kgdboe: failed to guarantee cross-CPU network API synchronization. Aborting. Try enabling single-CPU mode.\n");
		return -EINVAL;
	}

	err = kgdb_register_io_module(&kgdboe_io_ops);
	if (err != 0)
	{
		netpoll_wrapper_free(s_pKgdboeNetpoll);
		s_pKgdboeNetpoll = NULL;
		return err;
	}

	netpoll_wrapper_set_callback(s_pKgdboeNetpoll, kgdboe_rx_handler, NULL);

	memcpy(ipaddr, &ip_addr_as_int(s_pKgdboeNetpoll->netpoll_obj.local_ip), 4);
	printk(KERN_INFO "kgdboe: Successfully initialized. Use the following gdb command to attach:\n");
	printk(KERN_INFO "\ttarget remote udp:%d.%d.%d.%d:%d\n", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3], s_pKgdboeNetpoll->netpoll_obj.local_port);

	return 0;
}

void kgdboe_io_cleanup(void)
{
	/*
		We don't check for race conditions between running code by other cores and unloading the module!
		There is always a small chance that unloading this module would cause a kernel panic because
		another core is executing a function hooked by us. As normally you don't need to load/unload this
		module all the time (just execute the 'detach' command in GDB and connect back when ready), we
		don't check for it here.
	*/
	kgdb_unregister_io_module(&kgdboe_io_ops);
	netpoll_wrapper_free(s_pKgdboeNetpoll);
	nethook_cleanup();
	s_pKgdboeNetpoll = NULL;
}
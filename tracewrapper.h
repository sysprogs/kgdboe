#pragma once
#include <linux/version.h>
#include <linux/kallsyms.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)

#define register_tracepoint_wrapper(tp, func, ctx)	\
	register_trace_ ## tp(func, ctx)
	
#define unregister_tracepoint_wrapper(tp, func, ctx)	\
	unregister_trace_ ## tp(func, ctx)

#else

#define register_tracepoint_wrapper(tp, func, ctx)	\
	tracepoint_probe_register((struct tracepoint *)kallsyms_lookup_name("__tracepoint_" #tp), func, ctx)

#define unregister_tracepoint_wrapper(tp, func, ctx)	\
	tracepoint_probe_unregister((struct tracepoint *)kallsyms_lookup_name("__tracepoint_" #tp), func, ctx)

#endif
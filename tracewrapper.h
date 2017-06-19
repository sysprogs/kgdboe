#pragma once
#include <linux/version.h>
#include <linux/kallsyms.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)

#define register_tracepoint_wrapper(tp, func, ctx)	\
register_trace_ ## tp(func, ctx)
	
#define unregister_tracepoint_wrapper(tp, func, ctx)	\
	unregister_trace_ ## tp(func, ctx)

#define tracepoint_available(name) 1
    
#else
    
static struct tracepoint *do_lookup_tracepoint(const char *tracepointName, const char *tracepointPtrName)
{
    struct tracepoint *pTracepoint = (struct tracepoint *)kallsyms_lookup_name(tracepointName);
    if (!pTracepoint)
    {
        struct tracepoint **ppTracepoint = (struct tracepoint **)kallsyms_lookup_name(tracepointPtrName);
        BUG_ON(!ppTracepoint);
        pTracepoint = *ppTracepoint;
    }
    
    return pTracepoint;
}

#define register_tracepoint_wrapper(tp, func, ctx)	\
	tracepoint_probe_register(do_lookup_tracepoint("__tracepoint_" #tp, "__tracepoint_ptr_" #tp), func, ctx)

#define unregister_tracepoint_wrapper(tp, func, ctx)	\
	tracepoint_probe_unregister(do_lookup_tracepoint("__tracepoint_" #tp, "__tracepoint_ptr_" #tp), func, ctx)
    
#define tracepoint_available(tp) (kallsyms_lookup_name("__tracepoint_" #tp) || kallsyms_lookup_name("__tracepoint_ptr_" #tp))
    

#endif
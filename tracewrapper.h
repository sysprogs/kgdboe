#ifndef TRACE_WRAPPER_H
#define TRACE_WRAPPER_H

#include <linux/version.h>
#include <linux/kallsyms.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

extern uint64_t kallsyms_lookup_name_address;
#define kallsyms_lookup_name ((unsigned long(*)(const char *))kallsyms_lookup_name_address)

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0)

#define register_tracepoint_wrapper(tp, func, ctx)	\
register_trace_ ## tp(func, ctx)

#define unregister_tracepoint_wrapper(tp, func, ctx)	\
	unregister_trace_ ## tp(func, ctx)

#define tracepoint_available(name) 1

#else

static __maybe_unused struct tracepoint *do_lookup_tracepoint(const char *tracepointName, const char *tracepointPtrName)
{
    struct tracepoint *pTracepoint = (struct tracepoint *)kallsyms_lookup_name(tracepointName);
    if (!pTracepoint)
    {
        struct tracepoint **ppTracepoint = (struct tracepoint **)kallsyms_lookup_name(tracepointPtrName);
        BUG_ON(!ppTracepoint);
        pTracepoint = *ppTracepoint;
		BUG_ON(!pTracepoint);
    }

    return pTracepoint;
}

#define register_tracepoint_wrapper(tp, func, ctx)	\
	tracepoint_probe_register(do_lookup_tracepoint("__tracepoint_" #tp, "__tracepoint_ptr_" #tp), func, ctx)

#define unregister_tracepoint_wrapper(tp, func, ctx)	\
	tracepoint_probe_unregister(do_lookup_tracepoint("__tracepoint_" #tp, "__tracepoint_ptr_" #tp), func, ctx)

#define tracepoint_available(tp) (kallsyms_lookup_name("__tracepoint_" #tp) || kallsyms_lookup_name("__tracepoint_ptr_" #tp))


#endif /* LINUX_VERSION_CODE */

#endif /* TRACE_WRAPPER_H */
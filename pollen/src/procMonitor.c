#include <linux/bpf.h>

#ifdef ANDROID
#include <bpf_helpers.h>
#else
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#endif

#include <pollen/pollen.h>
#include <pollen/proc.h>

POLLEN_DEFINE_RINGBUF(proc_events, 1 << 24);

#ifdef ANDROID
DEFINE_BPF_PROG("tracepoint/sched/sched_process_fork", AID_ROOT, AID_SYSTEM, tracepoint_sched_process_fork)
#else
SEC("tracepoint/sched/sched_process_fork") int tracepoint_sched_process_fork
#endif
(struct trace_event_raw_sched_process_fork* ctx) {
    proc_event_t evt = {};
    POLLEN_INIT_EVENT(evt);

    evt.type = PROC_FORK;
    evt.ppid = ctx->pid;
    evt.pid = ctx->child_pid;

#if PRINTK
    bpf_printk("tracepoint_sched_process_fork: pid=%d, ppid=%d\n", evt.pid, evt.ppid);
#endif

    void *buf = bpf_ringbuf_reserve(&proc_events, sizeof(proc_event_t), 0);
    if (buf) {
        __builtin_memcpy(buf, &evt, sizeof(evt));
        bpf_ringbuf_submit(buf, 0);
    }

#if PRINTK
    if(!buf){
        bpf_printk("tracepoint_sched_process_fork: buf is NULL, perhaps bpf_ringbuf_reserve failure\n");
    }
#endif

    return 0;
}

#ifdef ANDROID
DEFINE_BPF_PROG("tracepoint/sched/sched_process_exit", AID_ROOT, AID_SYSTEM, tracepoint_sched_process_exit)
#else
SEC("tracepoint/sched/sched_process_exit") int tracepoint_sched_process_exit
#endif
/* We do not need ctx as we use bpf call to get pid */
#ifdef ANDROID
(void* __unused _ctx)
#else
(void* _ctx)
#endif
{
    proc_event_t evt = {};
    POLLEN_INIT_EVENT(evt);

    evt.type = PROC_EXIT;
    evt.ppid = 0;

    void* buf = bpf_ringbuf_reserve(&proc_events, sizeof(proc_event_t), 0);
    if (buf) {
        __builtin_memcpy(buf, &evt, sizeof(evt));
        bpf_ringbuf_submit(buf, 0);
    }

#if PRINTK
    if(!buf){
        bpf_printk("tracepoint_sched_process_exit: buf is NULL, perhaps bpf_ringbuf_reserve failure\n");
    }
#endif

    return 0;
}


char LICENSE[] SEC("license") = "GPL";

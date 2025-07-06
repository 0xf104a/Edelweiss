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

#ifdef ANDROID
struct bpf_map_def SEC("maps") proc_events = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1<<24, //16MB
	.min_kver = 0x0,
	.max_kver = 0xffffffff,
};
#else
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} proc_events SEC(".maps");
#endif

#ifdef ANDROID
DEFINE_BPF_PROG("tracepoint/sched/sched_process_fork", AID_ROOT, AID_SYSTEM, tracepoint_sched_process_fork)
#else
SEC("tracepoint/sched/sched_process_fork") int tracepoint_sched_process_fork
#endif
(struct trace_event_raw_sched_process_fork* ctx) {
    proc_event_t evt = {};

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
(void* _ctx) { /* We do not need ctx as we use bpf call to get pid */
    proc_event_t evt = {};

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;

    evt.type = PROC_EXIT;
    evt.ppid = 0;
    evt.pid = pid;

    void *buf = bpf_ringbuf_reserve(&proc_events, sizeof(proc_event_t), 0);
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

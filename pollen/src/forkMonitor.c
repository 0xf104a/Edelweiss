#include <linux/bpf.h>

#ifdef ANDROID
#include <bpf_helpers.h>
#else
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#endif

#include <pollen/pollen.h>
#include <pollen/fork.h>

#ifdef ANDROID
struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(fork_event_t),
	.max_entries = 1<<16,
};
#else
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(fork_event_t));
    __uint(max_entries, 1<<16);
} events SEC(".maps");
#endif


SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct sched_process_fork_args *ctx) {
    fork_event_t evt = {};

    evt.ppid = ctx->parent_pid;
    evt.pid = ctx->child_pid;

#ifdef bpf_printk
    bpf_printk("handle_fork: pid=%d, ppid=%d\n", evt.pid, evt.ppid);
    int ret = POLLEN_SUBMIT(&events, &evt);
    if (ret){
       bpf_printk("perf_event_output failed: %d\n", ret);
    }
#else
    POLLEN_SUBMIT(&events, &evt);
#endif
    return 0;
}


char LICENSE[] SEC("license") = "GPL";

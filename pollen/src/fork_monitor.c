#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <pollen/pollen.h>
#include <pollen/fork.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct sched_process_fork_args *ctx) {
    struct event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->ppid = ctx->parent_pid;
    evt->pid = ctx->child_pid;

    bpf_printk("pid=%d, ppid=%d\n", evt->pid, evt->pid);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}


char LICENSE[] SEC("license") = "GPL";

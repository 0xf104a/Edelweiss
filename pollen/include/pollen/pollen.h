/**
 * This file stores macros and structs which may be undefined
 * with usual bpf include
 */
#ifndef POLLEN_H
#define POLLEN_H

#include <linux/bpf.h>

#define POLLEN_TRACE_TAG "pollen" /* common tag for bpf_printk */

#ifndef SEC /* if current environment still does not has SEC */
#define SEC(NAME) __attribute__((section(NAME), used)) /* define our own SEC macro */
#endif

/* Helper macro to submit event to perf array */
#define POLLEN_SUBMIT(array, event) \
	bpf_perf_event_output(ctx, array, BPF_F_CURRENT_CPU, event, sizeof(event));

/* Process fork */
#ifndef sched_process_fork_args
struct sched_process_fork_args {
    __u64 unused;
    __u32 parent_pid;
    __u32 parent_tgid;
    __u32 child_pid;
    __u32 child_tgid;
};
#endif

/**
 *  Perf event output function
 *  @see https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/
 */
#ifndef bpf_perf_event_output
static long (* const bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
#endif

#endif //POLLEN_H

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

#ifndef TASK_COMM_LEN
/* We do not have TASK_COMM_LEN, fallback to default */
#define TASK_COMM_LEN 16
#endif

/* Helper macro to submit event to perf array */
#define POLLEN_PERF_SUBMIT(array, event) \
	bpf_perf_event_output(ctx, array, BPF_F_CURRENT_CPU, event, sizeof(event));

/* Process fork */
struct trace_event_raw_sched_process_fork {
    __u64 unused;
     char parent_comm[TASK_COMM_LEN];
    __u32 pid;
    char child_comm[TASK_COMM_LEN];
    __u32 child_pid;
};
/**
 *  Perf event output function
 *  @see https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/
 */
#ifdef ANDROID //Android does not have those functions in headers
static long (* const bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
#endif

/**
 * Android considered production env, so no use from printk there
 */
#ifdef ANDROID
#define PRINTK 0
#else
#define PRINTK 1
#endif

#endif //POLLEN_H

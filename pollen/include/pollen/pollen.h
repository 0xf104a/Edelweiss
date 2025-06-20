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
#define POLLEN_PERF_SUBMIT(array, event) \
	bpf_perf_event_output(ctx, array, BPF_F_CURRENT_CPU, event, sizeof(event));

/* Process fork */
struct sched_process_fork_args {
    __u64 unused;
    __u32 parent_pid;
    __u32 parent_tgid;
    __u32 child_pid;
    __u32 child_tgid;
};

#ifdef ANDROID //Android does not have those functions in headers
/**
 *  Perf event output function
 *  @see https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/
 */
static long (* const bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;

/*
 * bpf_ringbuf_submit
 *
 * 	Submit reserved ring buffer sample, pointed to by *data*.
 * 	If **BPF_RB_NO_WAKEUP** is specified in *flags*, no notification
 * 	of new data availability is sent.
 * 	If **BPF_RB_FORCE_WAKEUP** is specified in *flags*, notification
 * 	of new data availability is sent unconditionally.
 * 	If **0** is specified in *flags*, an adaptive notification
 * 	of new data availability is sent.
 *
 * 	See 'bpf_ringbuf_output()' for the definition of adaptive notification.
 *
 * Returns
 * 	Nothing. Always succeeds.
 */
static void (* const bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;

/*
 * bpf_ringbuf_reserve
 *
 * 	Reserve *size* bytes of payload in a ring buffer *ringbuf*.
 * 	*flags* must be 0.
 *
 * Returns
 * 	Valid pointer with *size* bytes of memory available; NULL,
 * 	otherwise.
 */
static void *(* const bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
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

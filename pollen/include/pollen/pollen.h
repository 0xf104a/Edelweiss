/**
 * This file stores macros and structs which may be undefined
 * with usual bpf include
 */
#ifndef POLLEN_H
#define POLLEN_H

#ifndef __VMLINUX_H__
#include <linux/sched.h>
#include <linux/bpf.h>
#endif

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

#ifndef __VMLINUX_H__
/* Process fork */
struct trace_event_raw_sched_process_fork {
    __u64 unused;
     char parent_comm[TASK_COMM_LEN];
    __u32 pid;
    char child_comm[TASK_COMM_LEN];
    __u32 child_pid;
};

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

/* sys_enter tracepoints */
struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

typedef short unsigned int __kernel_sa_family_t;
typedef __kernel_sa_family_t sa_family_t;

struct in_addr {
	__be32 s_addr;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct sockaddr_in6 {
	short unsigned int sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};
#endif

#ifdef ANDROID //Android does not have those functions in headers
#include <pollen/bpf_endian.h>
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

#ifndef bpf_printk
#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif
#endif

/**
 * A macro to define ringbuf of given name and size
 */
#ifdef ANDROID
#define POLLEN_DEFINE_RINGBUF(name, size) \
struct bpf_map_def SEC("maps") name = { \
	.type = BPF_MAP_TYPE_RINGBUF, \
	.max_entries = size, \
	.min_kver = 0x0, \
	.max_kver = 0xffffffff, \
};
#else
#define POLLEN_DEFINE_RINGBUF(name, size) \
struct { \
    __uint(type, BPF_MAP_TYPE_RINGBUF); \
    __uint(max_entries, size); \
    __uint(pinning, LIBBPF_PIN_BY_NAME); \
} name SEC(".maps");
#endif

/**
 * Android considered production env, so no use from printk there
 */
#ifdef ANDROID
#define PRINTK 0
#else
#define PRINTK 1
#endif

/**
 * Put PID/UID to event
 */
#define POLLEN_INIT_EVENT(event)\
    event.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;\
    event.uid = bpf_get_current_uid_gid();

#endif //POLLEN_H

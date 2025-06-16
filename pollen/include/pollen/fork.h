#ifndef POLLEN_FORK_H
#define POLLEN_FORK_H

#include <linux/bpf.h>

struct fork_event {
    __u32 pid;
    __u32 ppid;
};

struct sched_process_fork_args {
    __u64 unused;
    __u32 parent_pid;
    __u32 parent_tgid;
    __u32 child_pid;
    __u32 child_tgid;
};

#endif
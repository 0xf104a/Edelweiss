#ifndef POLLEN_FORK_H
#define POLLEN_FORK_H

#include <linux/bpf.h>

#define PROC_FORK 1
#define PROC_EXIT 2

typedef struct proc_event_t {
    __u32 type;
    __u32 pid;
    __u32 ppid;
} proc_event_t;

#endif
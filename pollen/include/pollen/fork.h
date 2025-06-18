#ifndef POLLEN_FORK_H
#define POLLEN_FORK_H

#include <linux/bpf.h>

typedef struct fork_event_t {
    __u32 pid;
    __u32 ppid;
} fork_event_t;

#endif

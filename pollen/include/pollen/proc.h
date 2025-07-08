#ifndef POLLEN_FORK_H
#define POLLEN_FORK_H

#ifndef __VMLINUX_H__
#include <linux/bpf.h>
#endif

#define PROC_FORK 1
#define PROC_EXIT 2

typedef struct proc_event_t {
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u32 ppid;
} proc_event_t;

#endif
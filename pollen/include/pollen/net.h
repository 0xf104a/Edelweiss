#ifndef POLLEN_NET_H
#define POLLEN_NET_H

#include <linux/bpf.h>

#define NET_EVENT_LISTEN 1
#define NET_EVENT_BIND   2

typedef struct net_event_t {
    __u32 type;
    __u32 pid;
    __u32 port;
    unsigned int addr;
} net_event_t;

struct sock_common {
    unsigned short skc_family;
    unsigned short skc_state;
    int skc_bound_dev_if;
    unsigned int skc_rcv_saddr;
    unsigned int skc_daddr;
    __be16 skc_num; // local port
    __be16 skc_dport; // remote port (only valid for some sockets)
};

struct sock {
    struct sock_common __sk_common;
};

#endif

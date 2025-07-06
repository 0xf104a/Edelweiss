#ifndef POLLEN_NET_H
#define POLLEN_NET_H

#include <linux/bpf.h>

#define NET_EVENT_LISTEN 1
#define NET_EVENT_BIND   2

typedef struct net_event_t {
    __u32 type;
    __u32 pid;
    __u32 port;
    __u32 remote_port;
    __u32 ip4_addr;
    __u32 ip6_addr[4];
    __u32 remote_ip4;
    __u32 remote_ip6[4];
} net_event_t;

#endif

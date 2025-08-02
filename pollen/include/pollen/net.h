#ifndef POLLEN_NET_H
#define POLLEN_NET_H
/**
#ifndef __VMLINUX_H__
#include <linux/bpf.h>
#endif
**/

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif

#ifndef AF_NFC
#define AF_NFC 39
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

#define NET_EVENT_OTHER  0
#define NET_EVENT_LISTEN 1
#define NET_EVENT_BIND   2

struct socket_shadow {
    struct sock *sk;
};

typedef struct net_event_t {
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u32 family;
    __u16 port;
    __u16 sock_type;
    __u32 remote_port;
    __u32 ip4_addr;
    __u32 ip6_addr[4];
    __u32 remote_ip4;
    __u32 remote_ip6[4];
} net_event_t;

#endif

#ifdef ANDROID
#define __POLLEN_BPF_FUNCS_DEFINED
#define __TARGET_ARCH_x86 //FIXME: Define in soong
#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf_helpers.h>
#else
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#endif

#include <pollen/pollen.h>
#include <pollen/net.h>
#include <pollen/arch.h>

POLLEN_DEFINE_RINGBUF(net_events, 1 << 24);

#ifdef ANDROID
DEFINE_BPF_PROG("kprobe/__sys_bind", AID_ROOT, AID_SYSTEM, __sys_bind)
#else
SEC("kprobe/__sys_bind")
int __sys_bind
#endif
(struct pt_regs* __unused ctx) {
    net_event_t evt = {};
    POLLEN_INIT_EVENT(evt);

    evt.type = NET_EVENT_BIND;

    void* uaddr = (void*)PT_REGS_PARM2(ctx);

    if (!uaddr) {
#if PRINTK
        bpf_printk("__sys_bind: uaddr is NULL\n");
#endif
        return 0;
    }

    sa_family_t family = 0;
    bpf_probe_read_user(&family, sizeof(family), uaddr);
    evt.family = family;

    if (family == AF_INET) {
        struct sockaddr_in sa4 = {};
        bpf_probe_read_user(&sa4, sizeof(sa4), uaddr);
#if PRINTK
        bpf_printk("__sys_bind: sa4.sin_addr.s_addr=%d\n", sa4.sin_addr.s_addr);
        bpf_printk("__sys_bind: sa4.sin_port=%d\n", sa4.sin_port);
#endif
        evt.port = bpf_ntohs(sa4.sin_port);
        evt.ip4_addr = sa4.sin_addr.s_addr;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), uaddr);
        evt.port = bpf_ntohs(sa6.sin6_port);
        __builtin_memcpy(evt.ip6_addr, sa6.sin6_addr.in6_u.u6_addr32, sizeof(evt.ip6_addr));
    }

    void *buf = bpf_ringbuf_reserve(&net_events, sizeof(evt), 0);
    if (buf) {
        __builtin_memcpy(buf, &evt, sizeof(evt));
        bpf_ringbuf_submit(buf, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

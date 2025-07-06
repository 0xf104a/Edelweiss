#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>

#ifdef ANDROID
#include <bpf_helpers.h>
#else
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#endif

#include <pollen/pollen.h>
#include <pollen/net.h>

POLLEN_DEFINE_RINGBUF(net_events, 1 << 24);

#ifdef ANDROID
DEFINE_BPF_PROG("kprobe/inet_listen", AID_ROOT, AID_SYSTEM, kprobe_inet_listen)
#else
SEC("kprobe/inet_listen") int kprobe_inet_listen
#endif
(struct __sk_buff* sock){
    net_event_t evt = {};
    evt.type = NET_EVENT_LISTEN;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    evt.pid = pid;

    //struct sock* socket = (struct sock*)PT_REGS_PARM1(ctx);
    evt.port = sock->local_port;
    evt.addr = sock->local_ip4;

    void* buf = bpf_ringbuf_reserve(&net_events, sizeof(net_event_t), 0);
    if (buf) {
        __builtin_memcpy(buf, &evt, sizeof(evt));
        bpf_ringbuf_submit(buf, 0);
    }

#if PRINTK
    if(!buf){
        bpf_printk("kprobe_inet_listen: buf is NULL, perhaps bpf_ringbuf_reserve failure\n");
    }
#endif

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
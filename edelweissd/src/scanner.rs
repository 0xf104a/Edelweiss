/**
 * The ForkEvent sent by forkMonitor eBPF program
 */
#[derive(Clone, Debug)]
#[repr(C)]
pub(crate) struct ForkEvent{
    pid: u32,
    ppid: u32,
}

use std::ffi::CString;
use std::ptr::{null, null_mut};
use libc::close;
use crate::bpf;
use crate::bpf::{ring_buffer__new, ring_buffer__poll, RingBuffer};
use crate::bpf::ringbuf::RingBufferStreamer;

pub(crate) struct Scanner{
    r_buffer: RingBuffer,
}

#[cfg(feature = "linux_bpf")]
pub(crate) const BPF_MAP_PATH: &str = "/sys/fs/bpf/fork_events";
#[cfg(feature = "android_bpf")]
pub(crate) const BPF_MAP_PATH: &str = "/sys/fs/bpf/map_forkMonitor_fork_events";
#[cfg(feature = "linux_bpf")]
pub(crate) const BPF_TP_PROG_PATH: &str = "/sys/fs/bpf/pollenFork";
#[cfg(feature = "android_bpf")]
pub(crate) const BPF_TP_PROG_PATH: &str = "/sys/fs/bpf/prog_forkMonitor_tracepoint_sched_sched_process_fork";

const BPF_TP_CATEGORY: &str = "sched";
const BPF_TP_NAME: &str = "sched_process_fork";

/// Process filter trait. Used by scanner to filter out processes which are not for inspection
/// like systemd on Linux or system processes on AOSP
pub(crate) trait ProcFilter{
    fn filter(&self, event: ForkEvent) -> bool;
}

pub(crate) struct ProcScanner<T: ProcFilter>{
    filter: T,
    streamer: RingBufferStreamer<ForkEvent, tokio::sync::mpsc::Sender<ForkEvent>>,
    rx: tokio::sync::mpsc::Receiver<ForkEvent>,
}

impl<T: ProcFilter> ProcScanner<T> {
    pub fn new(filter: T) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(65536);
        Self{
            filter,
            rx,
            streamer: RingBufferStreamer::<ForkEvent, tokio::sync::mpsc::Sender<ForkEvent>>::new(
                BPF_TP_PROG_PATH.to_string(), 
                BPF_MAP_PATH.to_string(), 
                BPF_TP_CATEGORY.to_string(), 
                BPF_TP_NAME.to_string(),
                tx),
        }
    }
    
    pub async fn scan(&mut self){
        
    }
}
pub mod filter;

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
use crate::bpf::streamer::Streamer;
use crate::utils::tokio::{init_tokio, tokio_block_on};

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
pub(crate) trait ProcFilter: Send + Sync{
    fn filter(&self, event: ForkEvent) -> bool;
}

#[derive(Debug)]
pub(crate) struct Process{
    pid: u32,
    parent_pid: u32,
}

impl Process{
    pub fn new(pid: u32, parent_pid: u32) -> Self{
        Self{
            pid,
            parent_pid,
        }
    }
}

pub(crate) struct ProcScanner<T: ProcFilter>{
    filter: T,
    streamer: RingBufferStreamer<ForkEvent, tokio::sync::mpsc::Sender<ForkEvent>>,
    rx: tokio::sync::mpsc::Receiver<ForkEvent>,
    tx: tokio::sync::mpsc::Sender<Process>,
}

impl<T: ProcFilter + 'static> ProcScanner<T> {
    pub fn new(filter: T, sender: tokio::sync::mpsc::Sender<Process>) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(65536);
        Self{
            filter,
            rx,
            tx: sender,
            streamer: RingBufferStreamer::<ForkEvent, tokio::sync::mpsc::Sender<ForkEvent>>::new(
                BPF_TP_PROG_PATH.to_string(), 
                BPF_MAP_PATH.to_string(), 
                BPF_TP_CATEGORY.to_string(), 
                BPF_TP_NAME.to_string(),
                tx),
        }
    }
    
    pub async fn scan(&mut self){
        self.streamer.start();
        while let Some(event) = self.rx.recv().await {
            let proc =  Process::new(event.pid,
                                     event.ppid);
            if self.filter.filter(event){
                self.tx.send(proc).await.expect("Can not send process info");
            }
        }
    }

    pub fn start(mut my_self: ProcScanner<T>){
        std::thread::spawn(move || {
            init_tokio();
            tokio_block_on(my_self.scan());
        });
    }
}
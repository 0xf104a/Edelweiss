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

use crate::bpf::ringbuf::RingBufferStreamer;
use crate::bpf::streamer::Streamer;
use crate::utils::notifier::AsyncNotifier;
use crate::utils::startable::Startable;
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
    /// Returns true if event should pass and false otherwise
    fn filter(&self, event: ForkEvent) -> bool;
}

#[derive(Debug)]
pub(crate) struct Process{
    pub pid: u32,
    pub parent_pid: u32,
}

impl Process{
    pub fn new(pid: u32, parent_pid: u32) -> Self{
        Self{
            pid,
            parent_pid,
        }
    }
}

pub(crate) struct ProcScanner<T: ProcFilter, N: AsyncNotifier<Process>>{
    filter: T,
    streamer: RingBufferStreamer<ForkEvent, tokio::sync::mpsc::Sender<ForkEvent>>,
    rx: tokio::sync::mpsc::Receiver<ForkEvent>,
    notifier: N,
}

impl<T: ProcFilter + 'static, N: AsyncNotifier<Process> + 'static> ProcScanner<T, N> {
    pub fn new(filter: T, notifier: N) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(65536);
        Self{
            filter,
            rx,
            notifier,
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
                self.notifier.notify(proc).await;
            }
        }
    }
}

impl<T: ProcFilter + 'static, N: AsyncNotifier<Process> + 'static> Startable for ProcScanner<T, N>{
    fn run(&mut self) {
        tokio_block_on(self.scan());
    }
}
pub mod filter;

/**
 * The ForkEvent sent by forkMonitor eBPF program
 */
#[derive(Clone, Debug)]
#[repr(C)]
pub(crate) struct ProcEvent {
    event_type: u32,
    pid: u32,
    uid: u32,
    ppid: u32,
}

use crate::bpf::ringbuf::RingBufferStreamer;
use crate::bpf::streamer::Streamer;
use crate::utils::notifier::AsyncNotifier;
use crate::utils::startable::Startable;
use crate::utils::tokio::{init_tokio, tokio_block_on};

#[cfg(feature = "linux_bpf")]
const BPF_MAP_PATH: &str = "/sys/fs/bpf/proc_events";
#[cfg(feature = "android_bpf")]
pub(crate) const BPF_MAP_PATH: &str = "/sys/fs/bpf/map_procMonitor_proc_events";
#[cfg(feature = "linux_bpf")]
const BPF_TP_PROG_PATH: &str = "/sys/fs/bpf/pollenProc";
#[cfg(feature = "android_bpf")]
pub(crate) const BPF_TP_PROG_PATH: &str = "/sys/fs/bpf/prog_procMonitor_tracepoint_sched_sched_process_fork";

const EVENT_TYPE_NEW: u32 = 1;
const EVENT_TYPE_EXIT: u32 = 2;

const BPF_TP_CATEGORY: &str = "sched";
const BPF_TP_NAME: &str = "sched_process_fork";

/// Process filter trait. Used by scanner to filter out processes which are not for inspection
/// like systemd on Linux or system processes on AOSP
pub(crate) trait ProcFilter: Send + Sync{
    /// Returns true if event should pass and false otherwise
    fn filter(&self, event: ProcEvent) -> bool;
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


pub(crate) enum ProcessEvent{
    ProcessCreated(Process),
    ProcessExited(usize),
}

pub(crate) struct ProcScanner<T: ProcFilter, N: AsyncNotifier<ProcessEvent>>{
    filter: T,
    streamer: RingBufferStreamer<ProcEvent, tokio::sync::mpsc::Sender<ProcEvent>>,
    rx: tokio::sync::mpsc::Receiver<ProcEvent>,
    notifier: N,
}

impl<T: ProcFilter + 'static, N: AsyncNotifier<ProcessEvent> + 'static> ProcScanner<T, N> {
    pub fn new(filter: T, notifier: N) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel(65536);
        Self{
            filter,
            rx,
            notifier,
            streamer: RingBufferStreamer::<ProcEvent, tokio::sync::mpsc::Sender<ProcEvent>>::new(
                BPF_TP_PROG_PATH.to_string(), 
                BPF_MAP_PATH.to_string(), 
                BPF_TP_CATEGORY.to_string(), 
                BPF_TP_NAME.to_string(),
                tx),
        }
    }

    async fn handle_proc_new(&mut self, event: ProcEvent){
        let proc =  Process::new(event.pid,
                                 event.ppid);
        if self.filter.filter(event){
            self.notifier.notify(ProcessEvent::ProcessCreated(proc)).await;
        }
    }

    async fn handle_proc_dead(&mut self, event: ProcEvent){
        let pid = event.pid;
        if self.filter.filter(event){
            self.notifier.notify(ProcessEvent::ProcessExited(pid as usize)).await;
        }
    }
    
    pub async fn scan(&mut self){
        self.streamer.start();
        while let Some(event) = self.rx.recv().await {
            log::trace!("Received event: {:?}", event);
            match event.event_type {
                EVENT_TYPE_NEW => self.handle_proc_new(event).await,
                EVENT_TYPE_EXIT => self.handle_proc_dead(event).await,
                _ => log::error!("Unknown event type: {}", event.event_type),
            }
        }
    }
}

impl<T: ProcFilter + 'static, N: AsyncNotifier<ProcessEvent> + 'static> Startable for ProcScanner<T, N>{
    fn run(&mut self) {
        tokio_block_on(self.scan());
    }
}
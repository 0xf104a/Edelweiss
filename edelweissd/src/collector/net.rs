use std::future::Future;
use libc::atoi;
use crate::bpf::ringbuf::RingBufferStreamer;
use crate::bpf::streamer::Streamer;
use crate::controller::ControllerMessage;
use crate::scanner::ProcEvent;
use crate::utils::boxable::{Boxable, Boxed};
use crate::utils::startable::{Startable, Starter};
use crate::utils::tokio::tokio_block_on;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct NetEvent {
    pub event_type: u32,
    pub pid: u32,
    pub port: u32,
    pub remote_port: u32,
    pub ip4_addr: u32,
    pub ip6_addr: [u32; 4],
    pub remote_ip4: u32,
    pub remote_ip6: [u32; 4],
}

const NET_EVENT_LISTEN: u32 = 1;

pub(crate) enum PortType {
    TCP,
    UDP,
}

pub(crate) struct NetListenPort {
    port_type: PortType,
    port: u32,
}

pub(crate) struct NetPhenotype {
    listen_ports: Vec<NetListenPort>,
}

pub(crate) struct NetPhenotypeCollector {
    controller_tx: tokio::sync::mpsc::Sender<ControllerMessage>,
    streamer: RingBufferStreamer<NetEvent, tokio::sync::mpsc::Sender<NetEvent>>,
    rx: tokio::sync::mpsc::Receiver<NetEvent>,
}

#[cfg(feature = "linux_bpf")]
const BPF_MAP_PATH: &str = "/sys/fs/bpf/net_events";
#[cfg(feature = "android_bpf")]
const BPF_MAP_PATH: &str = "/sys/fs/bpf/map_netMonitor_net_events";
#[cfg(feature = "linux_bpf")]
const BPF_TP_PROG_PATH: &str = "/sys/fs/bpf/pollenNet";
#[cfg(feature = "android_bpf")]
const BPF_TP_PROG_PATH: &str = "/sys/fs/bpf/prog_netMonitor_kprobe_inet_listen";

const BPF_TP_CATEGORY: &str = "kprobe";
const BPF_TP_NAME: &str = "inet_listen";

impl NetPhenotypeCollector{
    pub fn new(controller_tx: tokio::sync::mpsc::Sender<ControllerMessage>) -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel::<NetEvent>(65536);
        Self{
            controller_tx,
            rx,
            streamer: RingBufferStreamer::<NetEvent, tokio::sync::mpsc::Sender<NetEvent>>::new(
                BPF_TP_PROG_PATH.to_string(),
                BPF_MAP_PATH.to_string(),
                BPF_TP_CATEGORY.to_string(),
                BPF_TP_NAME.to_string(),
                tx),
        }
    }
}

impl Startable for NetPhenotypeCollector {
    fn run(&mut self) {
        tokio_block_on(async {
            self.streamer.start();
            loop {
                let event = self.rx.recv().await.expect("Can not get net event");
                log::trace!("Net event: {:?}", event);
                match event.event_type {
                    NET_EVENT_LISTEN => {}
                    _ => {
                        log::error!("Unknown net event type: {}", event.event_type);
                    }
                }
            }
        });
    }
}
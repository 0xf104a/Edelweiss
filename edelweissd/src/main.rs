use crate::bpf::ringbuf::RingBufferStreamer;
use crate::bpf::RingBuffer;
use crate::bpf::streamer::Streamer;
use crate::scanner::{ForkEvent, ProcScanner, Process, BPF_MAP_PATH, BPF_TP_PROG_PATH};
use crate::scanner::filter::default::DefaultFilter;
use crate::utils::startable::Starter;

mod phenotype;
mod utils;
mod controller;
mod receptor;
mod collector;
mod scanner;
mod bpf;

#[cfg(all(
    not(any(feature = "android_bpf", feature = "linux_bpf")),
    not(all(feature = "android_bpf", feature = "linux_bpf"))
))]
compile_error!("Invalid BPF feature selection");

#[cfg(feature = "android_logging")]
const TAG: &str = "edelweissd";

#[cfg(all(debug_assertions, feature = "env_logging"))]
fn setup_env_logging() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Trace)
        .init();
}

#[cfg(all(not(debug_assertions), feature = "env_logging"))]
fn setup_env_logging() {
    env_logger::Builder::from_default_env()
        .init();
}

#[cfg(all(debug_assertions, feature = "android_logging"))]
fn setup_android_logging() {
    android_log::LogBuilder::new()
        .filter_level(log::LevelFilter::Trace)
        .init();
}

#[cfg(all(not(debug_assertions), feature = "android_logging"))]
fn setup_android_logging() {
    android_log::init(TAG);
}

///
/// Main function
/// Written as an asynchronous since we are not going to use threads
/// 
#[tokio::main]
async fn main() {
    #[cfg(feature = "env_logging")]
    setup_env_logging();
    #[cfg(feature = "android_logging")]
    setup_android_logging();
    log::info!("Starting edelweissd");
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Process>(65536);
    let scanner = ProcScanner::new(DefaultFilter::new(), tx);
    Starter::start(scanner);
    loop{
        log::trace!("event = {:?}", rx.recv().await);
    }
}

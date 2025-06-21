use crate::scanner::Scanner;

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

///
/// Main function
/// Written as an asynchronous since we are not going to use threads
/// 
#[tokio::main]
async fn main() {
    println!("Starting EdelweissD");
    unsafe {
        Scanner::run();
    }
}

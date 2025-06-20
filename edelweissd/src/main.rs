use crate::scanner::Scanner;

mod phenotype;
mod utils;
mod controller;
mod receptor;
mod collector;
mod scanner;
mod bpf;

///
/// Main function
/// Written as an asynchronous since we are not going to use threads
/// 
#[tokio::main]
async fn main() {
    unsafe {
        Scanner::run();
    }
}

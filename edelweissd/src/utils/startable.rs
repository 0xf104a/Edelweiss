use crate::utils::tokio::init_tokio;

pub(crate) trait Startable: Send + Sync {
    /// Runs in current thread.
    fn run(&mut self);
}

pub(crate) struct Starter{}

impl Starter{
    pub(crate) fn start<T: Startable + 'static>(mut startable: T) -> std::thread::JoinHandle<()>{
        std::thread::spawn(move || {
            init_tokio();
            startable.run();
        })
    }
}

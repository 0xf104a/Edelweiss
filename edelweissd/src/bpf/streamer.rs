use crate::utils::tokio::tokio_block_on;

pub(crate) trait Streamer<T>{
    /// Starts steamer in separate thread
    fn start(&mut self);
}

/// Trait which allows to notify that something happens
pub(crate) trait StreamerNotifier<T>{
    fn notify(&mut self, obj: T);
}

impl<T: Clone> StreamerNotifier<T> for tokio::sync::mpsc::Sender<T>{
    #[inline]
    fn notify(&mut self, obj: T) {
        tokio_block_on(async { self.send(obj).await.expect("send() failed"); });
    }
}
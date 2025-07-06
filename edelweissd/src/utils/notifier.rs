/// Asynchronously notify other thread coroutine some event happend
#[async_trait::async_trait]
pub(crate) trait AsyncNotifier<T: Send + Sync>: Send + Sync {
     async fn notify(&self, event: T);
}

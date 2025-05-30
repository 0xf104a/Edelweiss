use crate::controller::ControllerMessage;
use crate::utils::boxable::Boxed;

///
/// Stores a single update of phenotype key
/// 
pub(crate) struct PhenotypeUpdate{
   key: u64,
   new_data: Boxed
}

///
/// A reader which inspects process for phenotype
/// 
pub(crate) trait PhenotypeCollector{
    ///
    /// This called when new process appears
    /// 
    fn on_new_process(&mut self, pid: usize) -> Vec<PhenotypeUpdate>;
    
    ///
    /// Lists all keys that this collector may write.
    /// The keys are reserved for **single** collector
    /// 
    fn get_keys(&self) -> Vec<u64>;
}

pub enum CollectorMessage{
    NewProcess(usize),
}

pub(crate) struct CollectorHolder<T: PhenotypeCollector>{
    collector: T,
    contoller_tx: tokio::sync::mpsc::Sender<ControllerMessage>,
    rx: tokio::sync::mpsc::Receiver<CollectorMessage>,
}
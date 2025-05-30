use std::collections::HashMap;
use crate::collector::PhenotypeUpdate;
use crate::phenotype::Phenotype;
use crate::receptor::ReceptorMessage;
use crate::utils::boxable::Boxed;

///
/// A message controller may receive
/// 
pub(crate) enum ControllerMessage{
    /// Phenotype data updates <pid, updates>
    PhenodataUpdate(usize, Vec<PhenotypeUpdate>),
    /// Process compromising security detected <pid, confidence>
    UnsafeProcDetected(usize, f32),
}

///
/// Responsible for discovering new processes and handling phenotype updates
/// 
pub(crate) struct Controller {
    pid_to_phenotype: HashMap<usize, Phenotype>,
    receptor_transmitters: tokio::sync::mpsc::Sender<ReceptorMessage>,
    rx: tokio::sync::mpsc::Receiver<ControllerMessage>,
    tx: tokio::sync::mpsc::Sender<ControllerMessage>,
}

impl Controller {
    
}
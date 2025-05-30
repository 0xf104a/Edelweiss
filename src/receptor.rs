use crate::controller::ControllerMessage;
use crate::phenotype::Phenotype;

pub(crate) enum ReceptorMessage{
    /// 
    /// Phenotype key updated. 
    /// Stores trigger key and phenotype itself
    /// 
    PhenotypeUpdate(u64, Phenotype),
}

///
/// Receptor is a detector for harmful agents
///
pub(crate) trait Receptor{
    ///
    /// Tries to recognize harmful agent from its phenotype
    /// Returns confidence scaled from 0.0 to 1.0
    /// 
    fn recognize(&mut self, phenotype: &Phenotype) -> f32;
}

///
/// Stores a receptor and handles updates from controller
/// 
pub(crate) struct ReceptorHolder<T: Receptor>{
    receptor: T,
    controller_tx: tokio::sync::mpsc::Sender<ControllerMessage>,
    rx: tokio::sync::mpsc::Receiver<ReceptorMessage>,
    keys: Vec<u64>,
    min_confidence: f32,
}

impl<T: Receptor> ReceptorHolder<T>{
    async fn run(mut self) {
        let need_check_keys = self.keys.len() > 0;
        loop{
            let msg = self.rx.recv().await;
            if msg.is_none(){
                // We're likely shutting down
                break;
            }
            let msg = msg.unwrap();
            match msg { 
                ReceptorMessage::PhenotypeUpdate(key, phenotype) => {
                    if need_check_keys{
                        if !self.keys.contains(&key){
                           continue; 
                        }
                    }
                    let confidence = self.receptor.recognize(&phenotype);
                    if confidence > self.min_confidence{
                        self.controller_tx.send(
                            ControllerMessage::UnsafeProcDetected(phenotype.pid, confidence))
                            .await
                            .expect("Can not communicate with controller");
                    }
                } 
            }
        }
    }
}
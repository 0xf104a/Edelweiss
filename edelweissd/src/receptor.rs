use crate::controller::ControllerMessage;
use crate::phenotype::Phenotype;
use crate::utils::startable::Startable;
use crate::utils::tokio::tokio_block_on;

pub(crate) enum ReceptorMessage {
    ///
    /// Phenotype key updated.
    /// Stores trigger key and phenotype itself
    ///
    PhenotypeUpdate(u64, Phenotype),

    ///
    /// Process died: receptors must clear its' phenotypee
    ///
    ProcDead(usize),
}

///
/// Receptor is a detector for harmful agents
/// It is supposed that it may do asynchronous operations, e.g. querying database,
/// reading files, calling NPU, etc. so it is marked as async_trait
///
#[async_trait::async_trait]
pub(crate) trait Receptor {
    ///
    /// Tries to recognize harmful agent from its phenotype
    /// Returns confidence scaled from 0.0 to 1.0
    ///
    async fn recognize(&mut self, phenotype: &Phenotype) -> f32;

    ///
    /// Called when process dies
    /// Should clean-up all the data which are associated with process
    ///
    async fn on_process_dead(&mut self, pid: usize);
}

///
/// Stores a receptor and handles updates from controller
///
pub(crate) struct ReceptorHolder<T: Receptor> {
    receptor: T,
    controller_tx: tokio::sync::mpsc::Sender<ControllerMessage>,
    rx: tokio::sync::mpsc::Receiver<ReceptorMessage>,
    keys: Vec<u64>,
    min_confidence: f32,
}

impl<T: Receptor + Send + Sync + 'static> Startable for ReceptorHolder<T> {
    fn run(&mut self) {
        tokio_block_on(async {
            let need_check_keys = self.keys.len() > 0;
            loop {
                let msg = self.rx.recv().await;
                if msg.is_none() {
                    // We're likely shutting down
                    break;
                }
                let msg = msg.unwrap();
                match msg {
                    ReceptorMessage::PhenotypeUpdate(key, phenotype) => {
                        if need_check_keys {
                            if !self.keys.contains(&key) {
                                continue;
                            }
                        }
                        let confidence = self.receptor.recognize(&phenotype).await;
                        if confidence > self.min_confidence {
                            self.controller_tx
                                .send(ControllerMessage::UnsafeProcDetected(
                                    phenotype.pid,
                                    confidence,
                                ))
                                .await
                                .expect("Can not communicate with controller");
                        }
                    }
                    ReceptorMessage::ProcDead(pid) => {
                        self.receptor.on_process_dead(pid).await;
                    }
                }
            }
        });
    }
}

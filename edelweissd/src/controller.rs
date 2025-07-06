use std::collections::HashMap;
use crate::collector::PhenotypeUpdate;
use crate::phenotype::Phenotype;
use crate::receptor::ReceptorMessage;
use crate::scanner::{Process, ProcessEvent};
use crate::utils::notifier::AsyncNotifier;

///
/// A message controller may receive
/// 
pub(crate) enum ControllerMessage{
    /// Phenotype data updates <pid, updates>
    PhenodataUpdate(usize, Vec<PhenotypeUpdate>),
    /// Process compromising security detected <pid, confidence>
    UnsafeProcDetected(usize, f32),
    /// Process died <pid>
    ProcDead(usize),
    /// New process detected
    NewProc(Process),
}

///
/// Responsible for discovering new processes and handling phenotype updates
/// 
pub(crate) struct Controller {
    pid_to_phenotype: HashMap<usize, Phenotype>,
    receptor_transmitters: Vec<tokio::sync::mpsc::Sender<ReceptorMessage>>,
    rx: tokio::sync::mpsc::Receiver<ControllerMessage>,
    tx: tokio::sync::mpsc::Sender<ControllerMessage>,
}

impl Controller {
    #[inline]
    pub fn new() -> Self{
        let (tx, rx) = tokio::sync::mpsc::channel::<ControllerMessage>(65536);
        Controller{
            tx, rx,
            pid_to_phenotype: HashMap::new(),
            receptor_transmitters: Vec::new(),
        }
    }

    #[inline]
    pub fn get_transmitter(&self) -> tokio::sync::mpsc::Sender<ControllerMessage>{
        self.tx.clone()
    }
    
    #[inline]
    async fn handle_dead_proc(&mut self, pid: usize){
        self.pid_to_phenotype.remove(&pid);
        for receptor in &self.receptor_transmitters {
            receptor.send(ReceptorMessage::ProcDead(pid))
                .await
                .expect("Receptor seem to be dead");
        }
    }
    
    #[inline]
    async fn handle_phenodata_updates(&mut self, pid: usize, updates: Vec<PhenotypeUpdate>){
        let phenotype = self.pid_to_phenotype.get_mut(&pid).unwrap();
        let mut updated_keys = Vec::<u64>::new();
        for update in updates { //clone() since we still need it for receptors
            let key = update.key;
            updated_keys.push(key);
            phenotype.on_update(update);
        }
        for receptor in &self.receptor_transmitters {
            for key in &updated_keys {
                receptor.send(ReceptorMessage::PhenotypeUpdate(*key,
                                                               phenotype.clone()))
                    .await
                    .expect("Receptor seem to be dead");
            }
        }
        
    }

    #[inline]
    fn ensure_phenotype(&mut self, pid: usize){
        if !self.pid_to_phenotype.contains_key(&pid) {
            self.pid_to_phenotype.insert(pid, Phenotype::new(pid, "".to_string()));
        }
    }
    
    #[inline]
    async fn tick(&mut self) {
        let msg = self.rx.recv().await;
        let msg = msg.expect("WTF: rx must live same time as tx and tx same time as controller, but we recieved None!");
        match msg {
            ControllerMessage::PhenodataUpdate(pid, updates) => {
                self.ensure_phenotype(pid);
                self.handle_phenodata_updates(pid, updates).await;
            }
            ControllerMessage::UnsafeProcDetected(pid, confidence) => {}
            ControllerMessage::ProcDead(pid) => {
                log::debug!("Process died: {:?}", pid);
                self.handle_dead_proc(pid).await;
            }
            ControllerMessage::NewProc(proc) => {
                log::debug!("New process detected: {:?}", proc);
                self.ensure_phenotype(proc.pid as usize);
            }
        }
    }
    
    /// Runs controller forever
    pub async fn run(&mut self){
        loop{
            self.tick().await;
        }
    }
}

#[async_trait::async_trait]
impl AsyncNotifier<ProcessEvent> for tokio::sync::mpsc::Sender<ControllerMessage> {
    async fn notify(&self, event: ProcessEvent) {
        match event {
            ProcessEvent::ProcessCreated(proc) => {
                self.send(ControllerMessage::NewProc(proc)).await.unwrap();
            }
            ProcessEvent::ProcessExited(pid) => {
                self.send(ControllerMessage::ProcDead(pid)).await.unwrap();
            }
        }
    }
}
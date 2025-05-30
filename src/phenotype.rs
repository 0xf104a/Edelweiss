use std::collections::HashMap;
use crate::{any, sum};
use crate::utils::boxable::{Boxable, Boxed, ByteBox, ByteBoxReader, Unboxable};

///
/// Phenotype is a description of process features united in single place
/// PhenoData is collected by data collectors and as soon it is updated it
/// is sent to receptors to check whether phenotype looks like harmful
/// 
#[derive(Clone)]
pub struct Phenotype{
    pub pid: usize,
    pub package_name: String,
    pheno_data: HashMap<u64, Boxed>
}

impl Boxable for Phenotype {
    fn boxed(&self) -> Boxed {
        let mut boxed = Boxed::new();
        boxed.pack(&self.pid);
        boxed.pack(&self.package_name);
        boxed.pack(&self.pheno_data);
        boxed
    }
}

impl Unboxable for Phenotype {
    fn from_boxed(boxed: &Boxed) -> Option<Self> {
        let mut reader = ByteBoxReader::from_boxed(boxed);
        let pid = reader.read::<usize>();
        let package_name = reader.read::<String>();
        let pheno_data = reader.read::<HashMap<u64, Boxed>>();
        if any!(
            pheno_data.is_none(), 
            package_name.is_none(), 
            pheno_data.is_none()) {
            return None;
        }
        Some(
            Self{
                pid: pid.unwrap(),
                package_name: package_name.unwrap(),
                pheno_data: pheno_data.unwrap(),
            }
        )
    }

    fn size_in_boxed_bytes(&self) -> usize {
        sum!(
            self.pid.size_in_boxed_bytes(),
            self.package_name.size_in_boxed_bytes(),
            self.pheno_data.size_in_boxed_bytes(),
        )
    }
}
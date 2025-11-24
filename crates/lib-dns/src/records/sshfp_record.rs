use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::hex;

#[derive(Clone, Debug)]
pub struct SshFpRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) algorithm: u8,
    pub(crate) fingerprint_type: u8,
    pub(crate) fingerprint: Vec<u8>
}

impl Default for SshFpRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            algorithm: 0,
            fingerprint_type: 0,
            fingerprint: Vec::new()
        }
    }
}

impl RecordBase for SshFpRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let algorithm = buf[off+8];
        let fingerprint_type = buf[off+9];

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;

        let fingerprint = buf[off+10..data_length].to_vec();

        Self {
            class,
            ttl,
            algorithm,
            fingerprint_type,
            fingerprint
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 10];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf[8] = self.algorithm;
        buf[9] = self.fingerprint_type;

        buf.extend_from_slice(&self.fingerprint);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::SshFp
    }

    fn upcast(self) -> Box<dyn RecordBase> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }
}

impl SshFpRecord {

    pub fn new(ttl: u32, class: RRClasses) -> Self {
        Self {
            class,
            ttl,
            ..Self::default()
        }
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn get_algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_fingerprint_type(&mut self, fingerprint_type: u8) {
        self.fingerprint_type = fingerprint_type;
    }

    pub fn get_fingerprint_type(&self) -> u8 {
        self.fingerprint_type
    }

    pub fn set_fingerprint(&mut self, fingerprint: &[u8]) {
        self.fingerprint = fingerprint.to_vec();
    }

    pub fn get_fingerprint(&self) -> &[u8] {
        self.fingerprint.as_ref()
    }
}

impl fmt::Display for SshFpRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.algorithm,
               self.fingerprint_type,
               hex::encode(&self.fingerprint))
    }
}

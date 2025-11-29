use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::hex;

#[derive(Clone, Debug)]
pub struct SmimeaRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) usage: u8,
    pub(crate) selector: u8,
    pub(crate) matching_type: u8,
    pub(crate) certificate: Vec<u8>
}

impl Default for SmimeaRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            usage: 0,
            selector: 0,
            matching_type: 0,
            certificate: Vec::new()
        }
    }
}

impl RecordBase for SmimeaRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let usage = buf[off+8];
        let selector = buf[off+9];
        let matching_type = buf[off+10];

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;

        let certificate = buf[off+11..data_length].to_vec();

        Self {
            class,
            ttl,
            usage,
            selector,
            matching_type,
            certificate
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 11];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf[8] = self.usage;
        buf[9] = self.selector;
        buf[10] = self.matching_type;

        buf.extend_from_slice(&self.certificate);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Smimea
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

impl SmimeaRecord {

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

    pub fn set_usage(&mut self, usage: u8) {
        self.usage = usage;
    }

    pub fn get_usage(&self) -> u8 {
        self.usage
    }

    pub fn set_selector(&mut self, selector: u8) {
        self.selector = selector;
    }

    pub fn get_selector(&self) -> u8 {
        self.selector
    }

    pub fn set_matching_type(&mut self, matching_type: u8) {
        self.matching_type = matching_type;
    }

    pub fn get_matching_type(&self) -> u8 {
        self.matching_type
    }

    pub fn set_certificate(&mut self, certificate: &[u8]) {
        self.certificate = certificate.to_vec();
    }

    pub fn get_certificate(&self) -> &[u8] {
        self.certificate.as_ref()
    }
}

impl fmt::Display for SmimeaRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} {} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.usage,
               self.selector,
               self.matching_type,
               hex::encode(&self.certificate))
    }
}

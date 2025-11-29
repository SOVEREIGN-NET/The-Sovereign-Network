use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;

#[derive(Clone, Debug)]
pub struct UriRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) target: Option<String>
}

impl Default for UriRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            priority: 0,
            weight: 0,
            target: None
        }
    }
}

impl RecordBase for UriRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let priority = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        let weight = u16::from_be_bytes([buf[off+10], buf[off+11]]);

        let length = u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;

        let target = String::from_utf8(buf[off+12..off+8+length].to_vec()).unwrap();

        Self {
            class,
            ttl,
            priority,
            weight,
            target: Some(target)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 12];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.splice(8..10, self.priority.to_be_bytes());
        buf.splice(10..12, self.weight.to_be_bytes());

        buf.extend_from_slice(self.target.as_ref().unwrap().as_bytes());

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Uri
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

impl UriRecord {

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

    pub fn set_priority(&mut self, priority: u16) {
        self.priority = priority;
    }

    pub fn get_priority(&self) -> u16 {
        self.priority
    }

    pub fn set_weight(&mut self, weight: u16) {
        self.weight = weight;
    }

    pub fn get_weight(&self) -> u16 {
        self.weight
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn get_target(&self) -> Option<String> {
        self.target.clone()
    }
}

impl fmt::Display for UriRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} \"{}\"", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.priority,
               self.weight,
               self.target.as_ref().unwrap())
    }
}

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;

#[derive(Clone, Debug)]
pub struct HInfoRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) cpu: Option<String>,
    pub(crate) os: Option<String>
}

impl Default for HInfoRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            cpu: None,
            os: None
        }
    }
}

impl RecordBase for HInfoRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let length = buf[off+8] as usize;
        let cpu = String::from_utf8(buf[off+9..off+9+length].to_vec()).unwrap();
        let off = off+9+length;

        let length = buf[off] as usize;
        let os = String::from_utf8(buf[off+1..off+1+length].to_vec()).unwrap();

        Self {
            class,
            ttl,
            cpu: Some(cpu),
            os: Some(os)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 8];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        let cpu = self.cpu.as_ref().unwrap().as_bytes();
        buf.push(cpu.len() as u8);
        buf.extend_from_slice(cpu);

        let os = self.os.as_ref().unwrap().as_bytes();
        buf.push(os.len() as u8);
        buf.extend_from_slice(os);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::HInfo
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

impl HInfoRecord {

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

    pub fn set_cpu(&mut self, cpu: &str) {
        self.cpu = Some(cpu.to_string());
    }

    pub fn get_cpu(&self) -> Option<String> {
        self.cpu.clone()
    }

    pub fn set_os(&mut self, os: &str) {
        self.os = Some(os.to_string());
    }

    pub fn get_os(&self) -> Option<String> {
        self.os.clone()
    }
}

impl fmt::Display for HInfoRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}\"{}\" \"{}\"", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.cpu.as_ref().unwrap(),
               self.os.as_ref().unwrap())
    }
}

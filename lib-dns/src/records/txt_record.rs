use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;

#[derive(Clone, Debug)]
pub struct TxtRecord {
    class: RRClasses,
    cache_flush: bool,
    ttl: u32,
    pub(crate) data: Vec<String>
}

impl Default for TxtRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            cache_flush: false,
            ttl: 0,
            data: Vec::new()
        }
    }
}

impl RecordBase for TxtRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = u16::from_be_bytes([buf[off], buf[off+1]]);
        let cache_flush = (class & 0x8000) != 0;
        let class = RRClasses::from_code(class & 0x7FFF).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += 8;

        let mut data = Vec::new();

        while off < data_length {
            let length = buf[off] as usize;
            let record = String::from_utf8(buf[off + 1..off + 1 + length].to_vec()).unwrap();
            data.push(record);
            off += length+1;
        }

        Self {
            class,
            cache_flush,
            ttl,
            data
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 8];

        let mut class = self.class.get_code();
        if self.cache_flush {
            class = class | 0x8000;
        }

        buf.splice(0..2, class.to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        for record in &self.data {
            buf.push(record.len() as u8);
            buf.extend_from_slice(record.as_bytes());
        }

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Txt
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

impl TxtRecord {

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

    pub fn add_data(&mut self, data: &str) {
        self.data.push(data.to_string());
    }

    pub fn get_data(&self) -> &Vec<String> {
        self.data.as_ref()
    }

    pub fn get_data_mut(&mut self) -> &mut Vec<String> {
        self.data.as_mut()
    }
}

impl fmt::Display for TxtRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.data.iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(" "))
    }
}

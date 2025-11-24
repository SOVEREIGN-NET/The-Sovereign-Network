use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::naptr_flags::NaptrFlags;
use crate::records::inter::record_base::RecordBase;

#[derive(Clone, Debug)]
pub struct NaptrRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) order: u16,
    pub(crate) preference: u16,
    pub(crate) flags: Vec<NaptrFlags>,
    pub(crate) service: Option<String>,
    pub(crate) regex: Option<String>,
    pub(crate) replacement: Option<String>
}

impl Default for NaptrRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            order: 0,
            preference: 0,
            flags: Vec::new(),
            service: None,
            regex: None,
            replacement: None
        }
    }
}

impl RecordBase for NaptrRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let order = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        let preference = u16::from_be_bytes([buf[off+10], buf[off+11]]);

        let length = buf[off+12] as usize;
        let f = String::from_utf8(buf[off + 13..off + 13 + length].to_vec()).unwrap();
        let mut flags = Vec::new();
        for flag in f.split(',') {
            flags.push(NaptrFlags::from_str(flag).unwrap());
        }

        let mut off = off+13+length;

        let length = buf[off] as usize;
        let service = String::from_utf8(buf[off + 1..off + 1 + length].to_vec()).unwrap();

        off += 1+length;

        let length = buf[off] as usize;
        let regex = String::from_utf8(buf[off + 1..off + 1 + length].to_vec()).unwrap();

        off += 1+length;

        let length = buf[off] as usize;
        let replacement = String::from_utf8(buf[off + 1..off + 1 + length].to_vec()).unwrap();

        Self {
            class,
            ttl,
            order,
            preference,
            flags,
            service: Some(service),
            regex: Some(regex),
            replacement: Some(replacement)
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 12];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.splice(8..10, self.order.to_be_bytes());
        buf.splice(10..12, self.preference.to_be_bytes());

        let length = self.flags.len();
        buf.push(((length * 2) - 1) as u8);
        for (i, flag) in self.flags.iter().enumerate() {
            buf.push(flag.get_code());
            if i < length - 1 {
                buf.push(b',');
            }
        }

        let service = self.service.as_ref().unwrap().as_bytes();
        buf.push(service.len() as u8);
        buf.extend_from_slice(service);

        let regex = self.regex.as_ref().unwrap().as_bytes();
        buf.push(regex.len() as u8);
        buf.extend_from_slice(regex);

        let replacement = self.replacement.as_ref().unwrap().as_bytes();
        buf.push(replacement.len() as u8);
        buf.extend_from_slice(replacement);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Naptr
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

impl NaptrRecord {

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

    pub fn set_order(&mut self, order: u16) {
        self.order = order;
    }

    pub fn get_order(&self) -> u16 {
        self.order
    }

    pub fn set_preference(&mut self, preference: u16) {
        self.preference = preference;
    }

    pub fn get_preference(&self) -> u16 {
        self.preference
    }

    pub fn add_flags(&mut self, flags: NaptrFlags) {
        self.flags.push(flags);
    }

    pub fn get_flags(&self) -> &Vec<NaptrFlags> {
        self.flags.as_ref()
    }

    pub fn get_flags_mut(&mut self) -> &mut Vec<NaptrFlags> {
        self.flags.as_mut()
    }

    pub fn set_service(&mut self, service: &str) {
        self.service = Some(service.to_string());
    }

    pub fn get_service(&self) -> Option<String> {
        self.service.clone()
    }

    pub fn set_regex(&mut self, regex: &str) {
        self.regex = Some(regex.to_string());
    }

    pub fn get_regex(&self) -> Option<String> {
        self.regex.clone()
    }

    pub fn set_replacement(&mut self, replacement: &str) {
        self.replacement = Some(replacement.to_string());
    }

    pub fn get_replacement(&self) -> Option<String> {
        self.replacement.clone()
    }
}

impl fmt::Display for NaptrRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} \"{:?}\" \"{}\" \"{}\" {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.order,
               self.preference,
               self.flags,
               self.service.as_ref().unwrap(),
               self.regex.as_ref().unwrap(),
               self.replacement.as_ref().unwrap())
    }
}

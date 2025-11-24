use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::base64;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Clone, Debug)]
pub struct TKeyRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) algorithm_name: Option<String>,
    pub(crate) inception: u32,
    pub(crate) expiration: u32,
    pub(crate) mode: u16, //ENUM PLEASE
    pub(crate) error: u16,
    pub(crate) key: Vec<u8>,
    pub(crate) data: Vec<u8>
}

impl Default for TKeyRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            algorithm_name: None,
            inception: 0,
            expiration: 0,
            mode: 0,
            error: 0,
            key: Vec::new(),
            data: Vec::new()
        }
    }
}

impl RecordBase for TKeyRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let (algorithm_name, algorithm_name_length) = unpack_fqdn(buf, off+8);
        off += 8+algorithm_name_length;

        let inception = u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        let expiration = u32::from_be_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);

        let mode = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        let error = u16::from_be_bytes([buf[off+10], buf[off+11]]);

        let key_length = 14+u16::from_be_bytes([buf[off+12], buf[off+13]]) as usize;
        let key = buf[off + 14.. off + key_length].to_vec();
        off += key_length;

        let data_length = off+2+u16::from_be_bytes([buf[off], buf[off+1]]) as usize;
        let data = buf[off + 2..data_length].to_vec();

        Self {
            class,
            ttl,
            algorithm_name: Some(algorithm_name),
            inception,
            expiration,
            mode,
            error,
            key,
            data
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 8];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.algorithm_name.as_ref().unwrap().as_str(), label_map, off+8, true)); //PROBABLY NO COMPRESS

        buf.extend_from_slice(&self.inception.to_be_bytes());
        buf.extend_from_slice(&self.expiration.to_be_bytes());

        buf.extend_from_slice(&self.mode.to_be_bytes());
        buf.extend_from_slice(&self.error.to_be_bytes());

        buf.extend_from_slice(&(self.key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.key);

        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::TKey
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

impl TKeyRecord {

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
}

impl fmt::Display for TKeyRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} {} {} {} {} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               format!("{}.", self.algorithm_name.as_ref().unwrap()),
               self.inception,
               self.expiration,
               self.mode,
               self.error,
               base64::encode(&self.key),
               base64::encode(&self.data)) //IF EMPTY USE -
    }
}

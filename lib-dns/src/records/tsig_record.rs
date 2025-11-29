use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::utils::hex;

#[derive(Clone, Debug)]
pub struct TSigRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) algorithm_name: Option<String>,
    pub(crate) time_signed: u64,
    pub(crate) fudge: u16,
    pub(crate) mac: Vec<u8>,
    pub(crate) original_id: u16,
    pub(crate) error: u16,
    pub(crate) data: Vec<u8>
}

impl Default for TSigRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            algorithm_name: None,
            time_signed: 0,
            fudge: 0,
            mac: Vec::new(),
            original_id: 0,
            error: 0,
            data: Vec::new()
        }
    }
}

impl RecordBase for TSigRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        //let length = u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;

        let (algorithm_name, algorithm_name_length) = unpack_fqdn(buf, off+8);
        off += 8+algorithm_name_length;

        let time_signed = ((buf[off] as u64) << 40)
                | ((buf[off+1] as u64) << 32)
                | ((buf[off+2] as u64) << 24)
                | ((buf[off+3] as u64) << 16)
                | ((buf[off+4] as u64) << 8)
                |  (buf[off+5] as u64);
        let fudge = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let mac_length = 10+u16::from_be_bytes([buf[off+8], buf[off+9]]) as usize;
        let mac = buf[off + 10..off + mac_length].to_vec();
        off += mac_length;

        let original_id = u16::from_be_bytes([buf[off], buf[off+1]]);
        let error = u16::from_be_bytes([buf[off+2], buf[off+3]]);

        let data_length = off+6+u16::from_be_bytes([buf[off+4], buf[off+5]]) as usize;
        let data = buf[off + 6..data_length].to_vec();

        Self {
            class,
            ttl,
            algorithm_name: Some(algorithm_name),
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            data
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 8];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.algorithm_name.as_ref().unwrap().as_str(), label_map, off+8, true)); //PROBABLY NO COMPRESS

        buf.extend_from_slice(&[
            ((self.time_signed >> 40) & 0xFF) as u8,
            ((self.time_signed >> 32) & 0xFF) as u8,
            ((self.time_signed >> 24) & 0xFF) as u8,
            ((self.time_signed >> 16) & 0xFF) as u8,
            ((self.time_signed >>  8) & 0xFF) as u8,
            ( self.time_signed        & 0xFF) as u8
        ]);
        buf.extend_from_slice(&self.fudge.to_be_bytes());

        buf.extend_from_slice(&(self.mac.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.mac);

        buf.extend_from_slice(&self.original_id.to_be_bytes());
        buf.extend_from_slice(&self.error.to_be_bytes());

        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::TSig
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

impl TSigRecord {

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

impl fmt::Display for TSigRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} {} {} {} {} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               format!("{}.", self.algorithm_name.as_ref().unwrap()),
               self.time_signed,
               self.fudge,
               hex::encode(&self.mac),
               self.original_id,
               self.error,
               hex::encode(&self.data))
    }
}

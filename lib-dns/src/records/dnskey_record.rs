use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;

#[derive(Clone, Debug)]
pub struct DnsKeyRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) flags: u16,
    pub(crate) protocol: u8,
    pub(crate) algorithm: u8,
    pub(crate) public_key: Vec<u8>
}

impl Default for DnsKeyRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            flags: 0,
            protocol: 0,
            algorithm: 0,
            public_key: Vec::new()
        }
    }
}

impl RecordBase for DnsKeyRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let flags = u16::from_be_bytes([buf[off+8], buf[off+9]]);
        /*
        Flags: 0x0100
            .... ...1 .... .... = Zone Key: This is the zone key for specified zone
            .... .... 0... .... = Key Revoked: No
            .... .... .... ...0 = Key Signing Key: No
            0000 000. .000 000. = Key Signing Key: 0x0000
        */

        let protocol = buf[off+10];
        let algorithm = buf[off+11];

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += 12;

        let public_key = buf[off..data_length].to_vec();

        Self {
            class,
            ttl,
            flags,
            protocol,
            algorithm,
            public_key
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 12];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.splice(8..10, self.flags.to_be_bytes());
        buf[10] = self.protocol;
        buf[11] = self.algorithm;

        buf.extend_from_slice(&self.public_key);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::DnsKey
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

impl DnsKeyRecord {

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

impl fmt::Display for DnsKeyRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "type {:?}, class {:?}", self.get_type(), self.class)
    }
}

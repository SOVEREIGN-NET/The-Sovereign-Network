use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv6Addr;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;

#[derive(Clone, Debug)]
pub struct AaaaRecord {
    class: RRClasses,
    cache_flush: bool,
    ttl: u32,
    pub(crate) address: Option<Ipv6Addr>
}

impl Default for AaaaRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            cache_flush: false,
            ttl: 0,
            address: None
        }
    }
}

impl RecordBase for AaaaRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let class = u16::from_be_bytes([buf[off], buf[off+1]]);
        let cache_flush = (class & 0x8000) != 0;
        let class = RRClasses::from_code(class & 0x7FFF).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let length = u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        let record = &buf[off + 8..off + 8 + length];

        let address = match record.len() {
            16 => Ipv6Addr::from(<[u8; 16]>::try_from(record).expect("Invalid IPv6 address")),
            _ => panic!("Invalid Inet Address")
        };

        Self {
            class,
            cache_flush,
            ttl,
            address: Some(address)
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

        buf.extend_from_slice(&self.address.as_ref().unwrap().octets().to_vec());

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Aaaa
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

impl AaaaRecord {

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

    pub fn set_address(&mut self, address: Ipv6Addr) {
        self.address = Some(address);
    }

    pub fn get_address(&self) -> Option<Ipv6Addr> {
        self.address
    }
}

impl fmt::Display for AaaaRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.address.as_ref().unwrap())
    }
}

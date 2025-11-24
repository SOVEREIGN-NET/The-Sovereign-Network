use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Clone, Debug)]
pub struct SoaRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) fqdn: Option<String>,
    pub(crate) mailbox: Option<String>,
    pub(crate) serial: u32,
    pub(crate) refresh: u32,
    pub(crate) retry: u32,
    pub(crate) expire: u32,
    pub(crate) minimum_ttl: u32
}

impl Default for SoaRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            fqdn: None,
            mailbox: None,
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum_ttl: 0
        }
    }
}

impl RecordBase for SoaRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        //let z = u16::from_be_bytes([buf[off+6], buf[off+7]]);

        let (fqdn, length) = unpack_fqdn(buf, off+8);
        off += length+8;

        let (mailbox, length) = unpack_fqdn(buf, off);
        off += length;

        let serial = u32::from_be_bytes([buf[off], buf[off+1], buf[off+2], buf[off+3]]);
        let refresh = u32::from_be_bytes([buf[off+4], buf[off+5], buf[off+6], buf[off+7]]);
        let retry = u32::from_be_bytes([buf[off+8], buf[off+9], buf[off+10], buf[off+11]]);
        let expire = u32::from_be_bytes([buf[off+12], buf[off+13], buf[off+14], buf[off+15]]);
        let minimum_ttl = u32::from_be_bytes([buf[off+16], buf[off+17], buf[off+18], buf[off+19]]);

        Self {
            class,
            ttl,
            fqdn: Some(fqdn),
            mailbox: Some(mailbox),
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut off = off;

        let mut buf = vec![0u8; 8];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        let fqdn = pack_fqdn(self.fqdn.as_ref().unwrap().as_str(), label_map, off+8, true);
        buf.extend_from_slice(&fqdn);

        off += fqdn.len()+8;

        let mailbox = pack_fqdn(self.mailbox.as_ref().unwrap().as_str(), label_map, off, true);
        buf.extend_from_slice(&mailbox);

        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.refresh.to_be_bytes());
        buf.extend_from_slice(&self.retry.to_be_bytes());
        buf.extend_from_slice(&self.expire.to_be_bytes());
        buf.extend_from_slice(&self.minimum_ttl.to_be_bytes());

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Soa
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

impl SoaRecord {

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

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = Some(fqdn.to_string());
    }

    pub fn get_fqdn(&self) -> Option<String> {
        self.fqdn.clone()
    }

    pub fn set_mailbox(&mut self, mailbox: &str) {
        self.mailbox = Some(mailbox.to_string());
    }

    pub fn get_mailbox(&self) -> Option<String> {
        self.mailbox.clone()
    }

    pub fn set_serial(&mut self, serial: u32) {
        self.serial = serial;
    }

    pub fn get_serial(&self) -> u32 {
        self.serial
    }

    pub fn set_refresh(&mut self, refresh: u32) {
        self.refresh = refresh;
    }

    pub fn get_refresh(&self) -> u32 {
        self.refresh
    }

    pub fn set_retry(&mut self, retry: u32) {
        self.retry = retry;
    }

    pub fn get_retry(&self) -> u32 {
        self.retry
    }

    pub fn set_expire(&mut self, expire: u32) {
        self.expire = expire;
    }

    pub fn get_expire(&self) -> u32 {
        self.expire
    }

    pub fn set_minimum_ttl(&mut self, minimum_ttl: u32) {
        self.minimum_ttl = minimum_ttl;
    }

    pub fn get_minimum_ttl(&self) -> u32 {
        self.minimum_ttl
    }
}

impl fmt::Display for SoaRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} {} {} {} {} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               format!("{}.", self.fqdn.as_ref().unwrap()),
               format!("{}.", self.mailbox.as_ref().unwrap()),
               self.serial,
               self.refresh,
               self.retry,
               self.expire,
               self.minimum_ttl)
    }
}

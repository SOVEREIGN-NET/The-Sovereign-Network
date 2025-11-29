use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::utils::base64;
use crate::utils::time_utils::TimeUtils;

#[derive(Clone, Debug)]
pub struct RRSigRecord {
    class: RRClasses,
    ttl: u32,
    pub(crate) type_covered: RRTypes,
    pub(crate) algorithm: u8,
    pub(crate) labels: u8,
    pub(crate) original_ttl: u32,
    pub(crate) expiration: u32,
    pub(crate) inception: u32,
    pub(crate) key_tag: u16,
    pub(crate) signer_name: Option<String>,
    pub(crate) signature: Vec<u8>
}

impl Default for RRSigRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            ttl: 0,
            type_covered: RRTypes::default(),
            algorithm: 0,
            labels: 0,
            original_ttl: 0,
            expiration: 0,
            inception: 0,
            key_tag: 0,
            signer_name: None,
            signature: Vec::new()
        }
    }
}

impl RecordBase for RRSigRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = RRClasses::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let type_covered = RRTypes::from_code(u16::from_be_bytes([buf[off+8], buf[off+9]])).unwrap();

        let algorithm = buf[off+10];
        let labels = buf[off+11];

        let original_ttl = u32::from_be_bytes([buf[off+12], buf[off+13], buf[off+14], buf[off+15]]);
        let expiration = u32::from_be_bytes([buf[off+16], buf[off+17], buf[off+18], buf[off+19]]);
        let inception = u32::from_be_bytes([buf[off+20], buf[off+21], buf[off+22], buf[off+23]]);
        let key_tag = u16::from_be_bytes([buf[off+24], buf[off+25]]);

        let (signer_name, length) = unpack_fqdn(buf, off+26);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += length+26;

        let signature = buf[off..data_length].to_vec();

        Self {
            class,
            ttl,
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name: Some(signer_name),
            signature
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 26];

        buf.splice(0..2, self.class.get_code().to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.splice(8..10, self.type_covered.get_code().to_be_bytes());

        buf[10] = self.algorithm;
        buf[11] = self.labels;

        buf.splice(12..16, self.original_ttl.to_be_bytes());
        buf.splice(16..20, self.expiration.to_be_bytes());
        buf.splice(20..24, self.inception.to_be_bytes());
        buf.splice(24..26, self.key_tag.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.signer_name.as_ref().unwrap(), label_map, off+26, true));

        buf.extend_from_slice(&self.signature);

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::RRSig
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

impl RRSigRecord {

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

    pub fn set_type_covered(&mut self, type_covered: RRTypes) {
        self.type_covered = type_covered;
    }

    pub fn get_type_covered(&self) -> RRTypes {
        self.type_covered
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn get_algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_labels(&mut self, labels: u8) {
        self.labels = labels;
    }

    pub fn get_labels(&self) -> u8 {
        self.labels
    }

    pub fn set_original_ttl(&mut self, original_ttl: u32) {
        self.original_ttl = original_ttl;
    }

    pub fn get_original_ttl(&self) -> u32 {
        self.original_ttl
    }

    pub fn set_expiration(&mut self, expiration: u32) {
        self.expiration = expiration;
    }

    pub fn get_expiration(&self) -> u32 {
        self.expiration
    }

    pub fn set_inception(&mut self, inception: u32) {
        self.inception = inception;
    }

    pub fn get_inception(&self) -> u32 {
        self.inception
    }

    pub fn set_key_tag(&mut self, key_tag: u16) {
        self.key_tag = key_tag;
    }

    pub fn get_key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn set_signer_name(&mut self, signer_name: &str) {
        self.signer_name = Some(signer_name.to_string());
    }

    pub fn get_signer_name(&self) -> Option<&String> {
        self.signer_name.as_ref()
    }

    pub fn set_signature(&mut self, signature: &[u8]) {
        self.signature = signature.to_vec();
    }

    pub fn get_signature(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

impl fmt::Display for RRSigRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<8}{:<8}{:<8}{} {} {} {} {} {} {} {} {}", self.ttl,
               self.class.to_string(),
               self.get_type().to_string(),
               self.type_covered.to_string(),
               self.algorithm,
               self.labels,
               self.original_ttl,
               self.expiration.to_time_format(),
               self.inception.to_time_format(),
               self.key_tag,
               format!("{}.", self.signer_name.as_ref().unwrap()),
               base64::encode(&self.signature))
    }
}

use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::utils::base64;
use crate::utils::time_utils::TimeUtils;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RRSigRRData {
    type_covered: Option<RRTypes>,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: Option<String>,
    signature: Vec<u8>
}

impl Default for RRSigRRData {

    fn default() -> Self {
        Self {
            type_covered: None,
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

impl RRData for RRSigRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let type_covered = RRTypes::try_from(u16::from_be_bytes([buf[0], buf[1]]))
            .map_err(|e| RRDataError(e.to_string()))?;

        let algorithm = buf[2];
        let labels = buf[3];

        let original_ttl = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let expiration = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let inception = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let key_tag = u16::from_be_bytes([buf[16], buf[17]]);

        let (signer_name, signer_name_length) = unpack_fqdn(buf, 18);

        let signature = buf[18+signer_name_length..buf.len()].to_vec();

        Ok(Self {
            type_covered: Some(type_covered),
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name: Some(signer_name),
            signature
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = vec![0u8; 18]; //190 (ECDSA/Ed25519) / 318 (RSA)

        buf.splice(0..2, self.type_covered.as_ref()
            .ok_or_else(|| RRDataError("type_covered param was not set".to_string()))?.code().to_be_bytes());

        buf[2] = self.algorithm;
        buf[3] = self.labels;

        buf.splice(4..8, self.original_ttl.to_be_bytes());
        buf.splice(8..12, self.expiration.to_be_bytes());
        buf.splice(12..16, self.inception.to_be_bytes());
        buf.splice(16..18, self.key_tag.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.signer_name.as_ref()
            .ok_or_else(|| RRDataError("signer_name param was not set".to_string()))?));

        buf.extend_from_slice(&self.signature);

        Ok(buf)
    }

    fn upcast(self) -> Box<dyn RRData> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RRData> {
        Box::new(self.clone())
    }

    fn eq_box(&self, other: &dyn RRData) -> bool {
        other.as_any().downcast_ref::<Self>().map_or(false, |o| self == o)
    }
}

impl RRSigRRData {

    pub fn new(type_covered: RRTypes, algorithm: u8, labels: u8, original_ttl: u32, expiration: u32, inception: u32, key_tag: u16, signer_name: &str, signature: &[u8]) -> Self {
        Self {
            type_covered: Some(type_covered),
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name: Some(signer_name.to_string()),
            signature: signature.to_vec()
        }
    }

    pub fn set_type_covered(&mut self, type_covered: RRTypes) {
        self.type_covered = Some(type_covered);
    }

    pub fn type_covered(&self) -> Option<&RRTypes> {
        self.type_covered.as_ref()
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_labels(&mut self, labels: u8) {
        self.labels = labels;
    }

    pub fn labels(&self) -> u8 {
        self.labels
    }

    pub fn set_original_ttl(&mut self, original_ttl: u32) {
        self.original_ttl = original_ttl;
    }

    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    pub fn set_expiration(&mut self, expiration: u32) {
        self.expiration = expiration;
    }

    pub fn expiration(&self) -> u32 {
        self.expiration
    }

    pub fn set_inception(&mut self, inception: u32) {
        self.inception = inception;
    }

    pub fn inception(&self) -> u32 {
        self.inception
    }

    pub fn set_key_tag(&mut self, key_tag: u16) {
        self.key_tag = key_tag;
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn set_signer_name(&mut self, signer_name: &str) {
        self.signer_name = Some(signer_name.to_string());
    }

    pub fn signer_name(&self) -> Option<&String> {
        self.signer_name.as_ref()
    }

    pub fn set_signature(&mut self, signature: &[u8]) {
        self.signature = signature.to_vec();
    }

    pub fn signature(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

impl FromWireLen for RRSigRRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        let type_covered = RRTypes::try_from(u16::from_wire(context)?)
            .map_err(|e| WireError::Format(e.to_string()))?;

        let algorithm = u8::from_wire(context)?;
        let labels = u8::from_wire(context)?;

        let original_ttl = u32::from_wire(context)?;
        let expiration = u32::from_wire(context)?;
        let inception = u32::from_wire(context)?;
        let key_tag = u16::from_wire(context)?;

        let pos = context.pos();
        let signer_name = context.name()?;

        let signature = context.take(len as usize - (context.pos() - pos) - 18)?.to_vec();

        Ok(Self {
            type_covered: Some(type_covered),
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name: Some(signer_name),
            signature
        })
    }
}

impl ToWire for RRSigRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        self.type_covered.as_ref()
            .ok_or_else(|| WireError::Format("type_covered param was not set".to_string()))?.code().to_wire(context)?;

        self.algorithm.to_wire(context)?;
        self.labels.to_wire(context)?;

        self.original_ttl.to_wire(context)?;
        self.expiration.to_wire(context)?;
        self.inception.to_wire(context)?;
        self.key_tag.to_wire(context)?;

        context.write_name(self.signer_name.as_ref()
            .ok_or_else(|| WireError::Format("signer_name param was not set".to_string()))?, true)?;

        context.write(&self.signature)
    }
}

impl ZoneRRData for RRSigRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.type_covered = Some(RRTypes::from_str(value).map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse type_covered param for record type RRSIG"))?),
            1 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse algorithm param for record type RRSIG"))?,
            2 => self.labels = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse labels param for record type RRSIG"))?,
            3 => self.original_ttl = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse original_ttl param for record type RRSIG"))?,
            4 => self.expiration = u32::from_time_format(value),
            5 => self.inception = u32::from_time_format(value),
            6 => self.key_tag = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse key_tag param for record type RRSIG"))?,
            7 => self.signer_name = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "signer_name param is not fully qualified (missing trailing dot) for record type RRSIG"))?.to_string()),
            8 => self.signature = base64::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse signature param for record type RRSIG"))?,
            _ => self.signature.extend_from_slice(&base64::decode(value).unwrap())
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for RRSigRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {} {} {}", self.type_covered.as_ref().map(|t| t.to_string()).unwrap_or(String::new()),
               self.algorithm,
               self.labels,
               self.original_ttl,
               self.expiration.to_time_format(),
               self.inception.to_time_format(),
               self.key_tag,
               format!("{}.", self.signer_name.as_ref().unwrap_or(&String::new())),
               base64::encode(&self.signature))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x2f, 0xd, 0x2, 0x0, 0x0, 0x7, 0x8, 0x68, 0xe7, 0x3c, 0x8d, 0x68, 0xe4, 0x7d, 0x6d, 0x86, 0xc9, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xf4, 0xd0, 0x3b, 0x11, 0x97, 0x31, 0x45, 0x12, 0x23, 0x4c, 0x45, 0x1a, 0xef, 0x28, 0xc0, 0x3c, 0xf7, 0xfc, 0x1b, 0x6b, 0xa7, 0x21, 0x1f, 0xe1, 0xc9, 0xb, 0x2f, 0x76, 0xc7, 0xb8, 0x52, 0x9, 0x83, 0x96, 0xbc, 0x69, 0x10, 0x43, 0x73, 0xe, 0x5c, 0x1, 0xf4, 0x78, 0x4e, 0x49, 0x86, 0xe7, 0xdf, 0xf6, 0xa, 0xa3, 0x1a, 0x75, 0xc2, 0x27, 0x53, 0xfb, 0x59, 0x52, 0x99, 0xb1, 0x44, 0xff ];
    let record = RRSigRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

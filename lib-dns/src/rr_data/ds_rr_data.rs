use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::hex;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DsRRData {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>
}

impl Default for DsRRData {

    fn default() -> Self {
        Self {
            key_tag: 0,
            algorithm: 0,
            digest_type: 0,
            digest: Vec::new()
        }
    }
}

impl RRData for DsRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let key_tag = 0;
        let algorithm = 0;
        let digest_type = 0;
        let digest = Vec::new();

        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(62);

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

impl DsRRData {

    pub fn new(key_tag: u16, algorithm: u8, digest_type: u8, digest: &[u8]) -> Self {
        Self {
            key_tag,
            algorithm,
            digest_type,
            digest: digest.to_vec()
        }
    }
}

impl FromWireLen for DsRRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        todo!()
    }
}

impl ToWire for DsRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        todo!()
    }
}

impl ZoneRRData for DsRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.key_tag = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse key_tag param for record type DS"))?,
            1 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse algorithm param for record type DS"))?,
            2 => self.digest_type = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse digest_type param for record type DS"))?,
            3 => self.digest = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse digest param for record type DS"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type DS"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for DsRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}", self.key_tag,
               self.algorithm,
               self.digest_type,
               hex::encode(&self.digest))
    }
}

#[test]
fn test() {
    let buf = vec![ ];
    let record = DsRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

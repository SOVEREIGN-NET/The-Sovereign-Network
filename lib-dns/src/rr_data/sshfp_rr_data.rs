use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::wire::{FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::hex;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshFpRRData {
    algorithm: u8,
    fingerprint_type: u8,
    fingerprint: Vec<u8>
}

impl Default for SshFpRRData {

    fn default() -> Self {
        Self {
            algorithm: 0,
            fingerprint_type: 0,
            fingerprint: Vec::new()
        }
    }
}

impl RRData for SshFpRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let algorithm = buf[0];
        let fingerprint_type = buf[1];

        let fingerprint = buf[2..buf.len()].to_vec();

        Ok(Self {
            algorithm,
            fingerprint_type,
            fingerprint
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(40);

        buf.push(self.algorithm);
        buf.push(self.fingerprint_type);

        buf.extend_from_slice(&self.fingerprint);

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

impl SshFpRRData {

    pub fn new() -> Self {
        Self {
            ..Self::default()
        }
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_fingerprint_type(&mut self, fingerprint_type: u8) {
        self.fingerprint_type = fingerprint_type;
    }

    pub fn fingerprint_type(&self) -> u8 {
        self.fingerprint_type
    }

    pub fn set_fingerprint(&mut self, fingerprint: &[u8]) {
        self.fingerprint = fingerprint.to_vec();
    }

    pub fn fingerprint(&self) -> &[u8] {
        self.fingerprint.as_ref()
    }
}

impl FromWireLen for SshFpRRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        todo!()
    }
}

impl ToWire for SshFpRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        todo!()
    }
}

impl ZoneRRData for SshFpRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse algorithm param for record type SSHFP"))?,
            1 => self.fingerprint_type = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse fingerprint_type param for record type SSHFP"))?,
            2 => self.fingerprint = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse fingerprint param for record type SSHFP"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type SSHFP"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for SshFpRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.algorithm,
               self.fingerprint_type,
               hex::encode(&self.fingerprint))
    }
}

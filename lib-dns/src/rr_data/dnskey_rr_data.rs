use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::base64;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsKeyRRData {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: Vec<u8>
}

impl Default for DnsKeyRRData {

    fn default() -> Self {
        Self {
            flags: 0,
            protocol: 0,
            algorithm: 0,
            public_key: Vec::new()
        }
    }
}

impl RRData for DnsKeyRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        /*
        Flags: 0x0100
            .... ...1 .... .... = Zone Key: This is the zone key for specified zone
            .... .... 0... .... = Key Revoked: No
            .... .... .... ...0 = Key Signing Key: No
            0000 000. .000 000. = Key Signing Key: 0x0000
        */

        let protocol = buf[2];
        let algorithm = buf[3];

        let public_key = buf[4..buf.len()].to_vec();

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(94);

        buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.push(self.protocol);
        buf.push(self.algorithm);

        buf.extend_from_slice(&self.public_key);

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

impl DnsKeyRRData {

    pub fn new(flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8>) -> Self {
        Self {
            flags,
            protocol,
            algorithm,
            public_key
        }
    }

    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn set_protocol(&mut self, protocol: u8) {
        self.protocol = protocol;
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_public_key(&mut self, public_key: &[u8]) {
        self.public_key = public_key.to_vec();
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl FromWireLen for DnsKeyRRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        let flags = u16::from_wire(context)?;
        /*
        Flags: 0x0100
            .... ...1 .... .... = Zone Key: This is the zone key for specified zone
            .... .... 0... .... = Key Revoked: No
            .... .... .... ...0 = Key Signing Key: No
            0000 000. .000 000. = Key Signing Key: 0x0000
        */

        let protocol = u8::from_wire(context)?;
        let algorithm = u8::from_wire(context)?;

        let public_key = context.take(len as usize - 4)?.to_vec();

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key
        })
    }
}

impl ToWire for DnsKeyRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        self.flags.to_wire(context)?;
        self.protocol.to_wire(context)?;
        self.algorithm.to_wire(context)?;

        context.write(&self.public_key)
    }
}

impl ZoneRRData for DnsKeyRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.flags = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse flags param for record type DNSKEY"))?,
            1 => self.protocol = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse protocol param for record type DNSKEY"))?,
            2 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse algorithm param for record type DNSKEY"))?,
            3 => self.public_key = base64::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse public_key param for record type DNSKEY"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type DNSKEY"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for DnsKeyRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}", self.flags,
               self.protocol,
               self.algorithm,
               base64::encode(&self.public_key))
    }
}

#[test]
fn test() {
    let buf = vec![ ];
    let record = DnsKeyRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

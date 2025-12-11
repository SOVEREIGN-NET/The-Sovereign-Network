use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv6Addr;
use crate::messages::wire::{FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AaaaRRData {
    address: Option<Ipv6Addr>
}

impl Default for AaaaRRData {

    fn default() -> Self {
        Self {
            address: None
        }
    }
}

impl RRData for AaaaRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let address = match buf.len() {
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf);
                Ipv6Addr::from(octets)
            }
            _ => return Err(RRDataError("invalid inet address".to_string()))
        };

        Ok(Self {
            address: Some(address)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(16);

        buf.extend_from_slice(&self.address.ok_or_else(|| RRDataError("address param was not set".to_string()))?.octets());

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

impl AaaaRRData {

    pub fn new(address: Ipv6Addr) -> Self {
        Self {
            address: Some(address)
        }
    }

    pub fn set_address(&mut self, address: Ipv6Addr) {
        self.address = Some(address);
    }

    pub fn address(&self) -> Option<Ipv6Addr> {
        self.address
    }
}

impl FromWireLen for AaaaRRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        let address = match len {
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(context.take(len as usize)?);
                Ipv6Addr::from(octets)
            }
            _ => return Err(WireError::Format("invalid inet address".to_string()))
        };

        Ok(Self {
            address: Some(address)
        })
    }
}

impl ToWire for AaaaRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write(&self.address.ok_or_else(|| WireError::Format("address param was not set".to_string()))?.octets())
    }
}

impl ZoneRRData for AaaaRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.address = Some(value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse address param for record type AAAA"))?),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type AAAA"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for AaaaRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address.map(|a| a.to_string()).unwrap_or_default())
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 ];
    let record = AaaaRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

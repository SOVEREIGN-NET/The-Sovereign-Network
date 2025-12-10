use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::net::Ipv4Addr;
use crate::messages::wire::{FromWireLen, FromWireContext, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InARRData {
    address: Option<Ipv4Addr>
}

impl Default for InARRData {

    fn default() -> Self {
        Self {
            address: None
        }
    }
}

impl RRData for InARRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let address = match buf.len() {
            4 => Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]),
            _ => return Err(RRDataError("invalid inet address".to_string()))
        };

        Ok(Self {
            address: Some(address)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(4);

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

impl InARRData {

    pub fn new(address: Ipv4Addr) -> Self {
        Self {
            address: Some(address)
        }
    }

    pub fn set_address(&mut self, address: Ipv4Addr) {
        self.address = Some(address);
    }

    pub fn address(&self) -> Option<Ipv4Addr> {
        self.address
    }
}

impl FromWireLen for InARRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        let address = match len {
            4 => {
                let buf = context.take(len as usize)?;
                Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])
            },
            _ => return Err(WireError::Format("invalid inet address".to_string()))
        };

        Ok(Self {
            address: Some(address)
        })
    }
}

impl ToWire for InARRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write(&self.address.ok_or_else(|| WireError::Format("address param was not set".to_string()))?.octets())
    }
}

impl ZoneRRData for InARRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.address = Some(value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse address param for record type A"))?),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type A"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for InARRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address.map(|a| a.to_string()).unwrap_or_default())
    }
}

#[test]
fn test() {
    let buf = vec![ 0x7f, 0x0, 0x0, 0x1 ];
    let record = InARRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

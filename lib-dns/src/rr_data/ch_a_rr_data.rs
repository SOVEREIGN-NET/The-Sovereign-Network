use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::utils::octal;
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChARRData {
    network: Option<String>,
    address: u16
}

impl Default for ChARRData {

    fn default() -> Self {
        Self {
            network: None,
            address: 0
        }
    }
}

impl RRData for ChARRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let (network, network_length) = unpack_fqdn(buf, 0);

        let address = u16::from_be_bytes([buf[network_length], buf[1+network_length]]);

        Ok(Self {
            network: Some(network),
            address
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(34);

        buf.extend_from_slice(&pack_fqdn(self.network.as_ref()
            .ok_or_else(|| RRDataError("network param was not set".to_string()))?));

        buf.extend_from_slice(&self.address.to_be_bytes());

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

impl ChARRData {

    pub fn new(network: &str, address: u16) -> Self {
        Self {
            network: Some(network.to_string()),
            address
        }
    }

    pub fn set_network(&mut self, network: &str) {
        self.network = Some(network.to_string());
    }

    pub fn network(&self) -> Option<&String> {
        self.network.as_ref()
    }

    pub fn set_address(&mut self, address: u16) {
        self.address = address;
    }

    pub fn address(&self) -> u16 {
        self.address
    }
}

impl FromWireLen for ChARRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let network = context.name()?;
        let address = u16::from_wire(context)?;

        Ok(Self {
            network: Some(network),
            address
        })
    }
}

impl ToWire for ChARRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(self.network.as_ref()
            .ok_or_else(|| WireError::Format("network param was not set".to_string()))?, true)?;
        self.address.to_wire(context)
    }
}

impl ZoneRRData for ChARRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.network = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "network param is not fully qualified (missing trailing dot) for record type CH A"))?.to_string()),
            1 => self.address = octal::from_octal(value).map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse address param for record type CH A"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type CH A"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for ChARRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", format!("{}.", self.network.as_ref().unwrap_or(&String::new())),
               octal::to_octal(self.address))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x7, 0x43, 0x48, 0x2d, 0x41, 0x44, 0x44, 0x52, 0x0, 0x6, 0x61 ];
    let record = ChARRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

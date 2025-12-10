use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MxRRData {
    priority: u16,
    server: Option<String>
}

impl Default for MxRRData {

    fn default() -> Self {
        Self {
            priority: 0,
            server: None
        }
    }
}

impl RRData for MxRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let priority = u16::from_be_bytes([buf[0], buf[1]]);

        let (server, _) = unpack_fqdn(buf, 2);

        Ok(Self {
            priority,
            server: Some(server)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(46);

        buf.extend_from_slice(&self.priority.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.server.as_ref()
            .ok_or_else(|| RRDataError("server param was not set".to_string()))?));

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

impl MxRRData {

    pub fn new(priority: u16, server: &str) -> Self {
        Self {
            priority,
            server: Some(server.to_string())
        }
    }

    pub fn set_priority(&mut self, priority: u16) {
        self.priority = priority;
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn set_server(&mut self, server: &str) {
        self.server = Some(server.to_string());
    }

    pub fn server(&self) -> Option<&String> {
        self.server.as_ref()
    }
}

impl FromWireLen for MxRRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let priority = u16::from_wire(context)?;

        let server = context.name()?;

        Ok(Self {
            priority,
            server: Some(server)
        })
    }
}

impl ToWire for MxRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        self.priority.to_wire(context)?;

        context.write_name(self.server.as_ref()
            .ok_or_else(|| WireError::Format("server param was not set".to_string()))?, true)
    }
}

impl ZoneRRData for MxRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse priority param for record type MX"))?,
            1 => self.server = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "server param is not fully qualified (missing trailing dot) for record type MX"))?.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type MX"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for MxRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.priority,
               format!("{}.", self.server.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x1, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0 ];
    let record = MxRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

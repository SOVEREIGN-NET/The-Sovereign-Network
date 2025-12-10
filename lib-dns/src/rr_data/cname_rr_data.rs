use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CNameRRData {
    target: Option<String>
}

impl Default for CNameRRData {

    fn default() -> Self {
        Self {
            target: None
        }
    }
}

impl RRData for CNameRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let (target, _) = unpack_fqdn(buf, 0);

        Ok(Self {
            target: Some(target)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(32);

        buf.extend_from_slice(&pack_fqdn(self.target.as_ref()
            .ok_or_else(|| RRDataError("target param was not set".to_string()))?));

        Ok(buf)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn upcast(self) -> Box<dyn RRData> {
        Box::new(self)
    }

    fn clone_box(&self) -> Box<dyn RRData> {
        Box::new(self.clone())
    }

    fn eq_box(&self, other: &dyn RRData) -> bool {
        other.as_any().downcast_ref::<Self>().map_or(false, |o| self == o)
    }
}

impl CNameRRData {

    pub fn new(target: &str) -> Self {
        Self {
            target: Some(target.to_string())
        }
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn target(&self) -> Option<&String> {
        self.target.as_ref()
    }
}

impl FromWireLen for CNameRRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let target = context.name()?;

        Ok(Self {
            target: Some(target)
        })
    }
}

impl ToWire for CNameRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(self.target.as_ref()
            .ok_or_else(|| WireError::Format("target param was not set".to_string()))?, true)
    }
}

impl ZoneRRData for CNameRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.target = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "network param is not fully qualified (missing trailing dot) for record type CNAME"))?.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type CNAME"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for CNameRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{}.", self.target.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x2, 0x78, 0x32, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0 ];
    let record = CNameRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtrRRData {
    fqdn: Option<String>
}

impl Default for PtrRRData {

    fn default() -> Self {
        Self {
            fqdn: None
        }
    }
}

impl RRData for PtrRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let (fqdn, _) = unpack_fqdn(buf, 0);

        Ok(Self {
            fqdn: Some(fqdn)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(32);

        buf.extend_from_slice(&pack_fqdn(self.fqdn.as_ref().unwrap()));

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

impl PtrRRData {

    pub fn new(fqdn: &str) -> Self {
        Self {
            fqdn: Some(fqdn.to_string())
        }
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = Some(fqdn.to_string());
    }

    pub fn fqdn(&self) -> Option<&String> {
        self.fqdn.as_ref()
    }
}

impl FromWireLen for PtrRRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let fqdn = context.name()?;

        Ok(Self {
            fqdn: Some(fqdn)
        })
    }
}

impl ToWire for PtrRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(self.fqdn.as_ref()
            .ok_or_else(|| WireError::Format("fqdn param was not set".to_string()))?, true)
    }
}

impl ZoneRRData for PtrRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.fqdn = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "fqdn param is not fully qualified (missing trailing dot) for record type PTR"))?.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type PTR"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for PtrRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{}.", self.fqdn.as_ref().unwrap()))
    }
}

#[test]
fn test() {
    let buf = vec![ ];
    let record = PtrRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

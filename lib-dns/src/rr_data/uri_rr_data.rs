use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UriRRData {
    priority: u16,
    weight: u16,
    target: Option<String>
}

impl Default for UriRRData {

    fn default() -> Self {
        Self {
            priority: 0,
            weight: 0,
            target: None
        }
    }
}

impl RRData for UriRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let priority = u16::from_be_bytes([buf[0], buf[1]]);
        let weight = u16::from_be_bytes([buf[2], buf[3]]);

        let target = String::from_utf8(buf[4..buf.len()].to_vec())
            .map_err(|e| RRDataError(e.to_string()))?;

        Ok(Self {
            priority,
            weight,
            target: Some(target)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(94);

        buf.extend_from_slice(&self.priority.to_be_bytes());
        buf.extend_from_slice(&self.weight.to_be_bytes());

        buf.extend_from_slice(self.target.as_ref().ok_or_else(|| RRDataError("target param was not set".to_string()))?.as_bytes());

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

impl UriRRData {

    pub fn new(priority: u16, weight: u16, target: &str) -> Self {
        Self {
            priority,
            weight,
            target: Some(target.to_string())
        }
    }

    pub fn set_priority(&mut self, priority: u16) {
        self.priority = priority;
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn set_weight(&mut self, weight: u16) {
        self.weight = weight;
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn target(&self) -> Option<&String> {
        self.target.as_ref()
    }
}

impl FromWireLen for UriRRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        let priority = u16::from_wire(context)?;
        let weight = u16::from_wire(context)?;

        let target = String::from_utf8(context.take(len as usize - 4)?.to_vec())
            .map_err(|e| WireError::Format(e.to_string()))?;

        Ok(Self {
            priority,
            weight,
            target: Some(target)
        })
    }
}

impl ToWire for UriRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        self.priority.to_wire(context)?;
        self.weight.to_wire(context)?;

        context.write(self.target.as_ref().ok_or_else(|| WireError::Format("target param was not set".to_string()))?.as_bytes())
    }
}

impl ZoneRRData for UriRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse priority param for record type URI"))?,
            1 => self.weight = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse weight param for record type URI"))?,
            2 => self.target = Some(value.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type URI"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for UriRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} \"{}\"", self.priority,
               self.weight,
               self.target.as_ref().unwrap_or(&String::new()))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x1, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3a, 0x2f, 0x2f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 ];
    let record = UriRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

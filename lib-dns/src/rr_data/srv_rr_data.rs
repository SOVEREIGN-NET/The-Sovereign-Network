use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SrvRRData {
    priority: u16,
    weight: u16,
    port: u16,
    target: Option<String>
}

impl Default for SrvRRData {

    fn default() -> Self {
        Self {
            priority: 0,
            weight: 0,
            port: 0,
            target: None
        }
    }
}

impl RRData for SrvRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let priority = u16::from_be_bytes([buf[0], buf[1]]);
        let weight = u16::from_be_bytes([buf[2], buf[3]]);
        let port = u16::from_be_bytes([buf[4], buf[5]]);

        let (target, _) = unpack_fqdn(buf, 6);

        Ok(Self {
            priority,
            weight,
            port,
            target: Some(target)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(62);

        buf.extend_from_slice(&self.priority.to_be_bytes());
        buf.extend_from_slice(&self.weight.to_be_bytes());
        buf.extend_from_slice(&self.port.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.target.as_ref()
            .ok_or_else(|| RRDataError("target param was not set".to_string()))?));

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

impl SrvRRData {

    pub fn new(priority: u16, weight: u16, port: u16, target: &str) -> Self {
        Self {
            priority,
            weight,
            port,
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

    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn target(&self) -> Option<&String> {
        self.target.as_ref()
    }
}

impl FromWireLen for SrvRRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let priority = u16::from_wire(context)?;
        let weight = u16::from_wire(context)?;
        let port = u16::from_wire(context)?;

        let target = context.name()?;

        Ok(Self {
            priority,
            weight,
            port,
            target: Some(target)
        })
    }
}

impl ToWire for SrvRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        self.priority.to_wire(context)?;
        self.weight.to_wire(context)?;
        self.port.to_wire(context)?;

        context.write_name(self.target.as_ref()
            .ok_or_else(|| WireError::Format("target param was not set".to_string()))?, true)
    }
}

impl ZoneRRData for SrvRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse priority param for record type SRV"))?,
            1 => self.weight = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to weight port param for record type SRV"))?,
            2 => self.port = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse port param for record type SRV"))?,
            3 => self.target = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "target param is not fully qualified (missing trailing dot) for record type SRV"))?.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type SRV"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for SrvRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}", self.priority,
               self.weight,
               self.port,
               format!("{}.", self.target.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x0, 0x0, 0x0, 0x4, 0xaa, 0x7, 0x6f, 0x70, 0x65, 0x6e, 0x76, 0x70, 0x6e, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0 ];
    let record = SrvRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

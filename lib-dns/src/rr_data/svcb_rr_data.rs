use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::rr_data::inter::svc_param::SvcParams;
use crate::rr_data::inter::svc_param_keys::SvcParamKeys;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SvcbRRData {
    priority: u16,
    target: Option<String>,
    params: Vec<SvcParams>
}

impl Default for SvcbRRData {

    fn default() -> Self {
        Self {
            priority: 0,
            target: None,
            params: Vec::new()
        }
    }
}

impl RRData for SvcbRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let priority = u16::from_be_bytes([buf[0], buf[1]]);

        let (target, target_length) = unpack_fqdn(&buf, 2);

        let mut i = 2+target_length;
        let mut params = Vec::new();

        while i < buf.len() {
            let key = SvcParamKeys::try_from(u16::from_be_bytes([buf[i], buf[i+1]]))
                .map_err(|e| RRDataError(e.to_string()))?;
            let length = u16::from_be_bytes([buf[i+2], buf[i+3]]) as usize;
            params.push(SvcParams::from_bytes(key, &buf[i+4..i+4+length])
                .map_err(|e| RRDataError(e.to_string()))?);

            i += length+4;
        }

        Ok(Self {
            priority,
            target: Some(target),
            params
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(158);

        buf.extend_from_slice(&self.priority.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.target.as_ref()
            .ok_or_else(|| RRDataError("target param was not set".to_string()))?));

        for param in self.params.iter() {
            buf.extend_from_slice(&param.code().to_be_bytes());
            let param_buf = param.to_bytes();
            buf.extend_from_slice(&(param_buf.len() as u16).to_be_bytes());
            buf.extend_from_slice(&param_buf);
        }

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

impl SvcbRRData {

    pub fn new(priority: u16, target: &str, params: Vec<SvcParams>) -> Self {
        Self {
            priority,
            target: Some(target.to_string()),
            params
        }
    }

    pub fn set_priority(&mut self, priority: u16) {
        self.priority = priority;
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn set_target(&mut self, target: &str) {
        self.target = Some(target.to_string());
    }

    pub fn target(&self) -> Option<&String> {
        self.target.as_ref()
    }

    pub fn add_param(&mut self, param: SvcParams) {
        self.params.push(param);
    }

    pub fn params_mut(&mut self) -> &mut Vec<SvcParams> {
        self.params.as_mut()
    }
}

impl FromWireLen for SvcbRRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        let priority = u16::from_wire(context)?;

        let checkpoint = context.pos();
        let target = context.name()?;

        let mut i = (context.pos()-checkpoint) as u16;
        let mut params = Vec::new();

        while i < len {
            let key = SvcParamKeys::try_from(u16::from_wire(context)?)
                .map_err(|e| WireError::Format(e.to_string()))?;
            let length = u16::from_wire(context)?;
            params.push(SvcParams::from_bytes(key, context.take(length as usize)?)
                .map_err(|e| WireError::Format(e.to_string()))?);

            i += length+4;
        }

        Ok(Self {
            priority,
            target: Some(target),
            params
        })
    }
}

impl ToWire for SvcbRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        self.priority.to_wire(context)?;

        context.write_name(self.target.as_ref()
            .ok_or_else(|| WireError::Format("target param was not set".to_string()))?, true)?;

        for param in self.params.iter() {
            param.code().to_wire(context)?;
            let param_buf = param.to_bytes();
            (param_buf.len() as u16).to_wire(context)?;
            context.write(&param_buf)?;
        }

        Ok(())
    }
}

impl ZoneRRData for SvcbRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.priority = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse priority param for record type SVCB"))?,
            1 => self.target = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "target param is not fully qualified (missing trailing dot) for record type SVCB"))?.to_string()),
            _ => self.params.push(SvcParams::from_str(value)
                .map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse svc_params param for record type SVCB"))?)
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for SvcbRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.priority,
               format!("{}.", self.target.as_ref().unwrap_or(&String::new())),
               self.params.iter()
                   .map(|s| s.to_string())
                   .collect::<Vec<_>>()
                   .join(" "))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x1, 0x3, 0x77, 0x77, 0x77, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x1, 0x0, 0x6, 0x2, 0x68, 0x33, 0x2, 0x68, 0x32, 0x0, 0x4, 0x0, 0x4, 0x7f, 0x0, 0x0, 0x1, 0x0, 0x6, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 ];
    let record = SvcbRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

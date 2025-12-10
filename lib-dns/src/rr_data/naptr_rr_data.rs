use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::naptr_flags::NaptrFlags;
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NaptrRRData {
    order: u16,
    preference: u16,
    flags: Vec<NaptrFlags>,
    service: Option<String>,
    regex: Option<String>,
    replacement: Option<String>
}

impl Default for NaptrRRData {

    fn default() -> Self {
        Self {
            order: 0,
            preference: 0,
            flags: Vec::new(),
            service: None,
            regex: None,
            replacement: None
        }
    }
}

impl RRData for NaptrRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let order = u16::from_be_bytes([buf[0], buf[1]]);
        let preference = u16::from_be_bytes([buf[2], buf[3]]);

        let flags_length = buf[4] as usize;
        let mut flags = Vec::new();

        for flag in String::from_utf8(buf[5..5 + flags_length].to_vec())
            .map_err(|e| RRDataError(e.to_string()))?.split(",") {
            let tok = flag.trim();
            if tok.is_empty() {
                continue;
            }

            flags.push(NaptrFlags::try_from(flag.chars()
                .next()
                .ok_or_else(|| RRDataError("empty NAPTR flag token".to_string()))?).map_err(|e| RRDataError(e.to_string()))?);
        }

        let mut off = 5+flags_length;

        let service_length = buf[off] as usize;
        let service = String::from_utf8(buf[off + 1..off + 1 + service_length].to_vec())
            .map_err(|e| RRDataError(e.to_string()))?;

        off += 1+service_length;

        let regex_length = buf[off] as usize;
        let regex = String::from_utf8(buf[off + 1..off + 1 + regex_length].to_vec())
            .map_err(|e| RRDataError(e.to_string()))?;

        off += 1+regex_length;

        let (replacement, _) = unpack_fqdn(buf, off);

        Ok(Self {
            order,
            preference,
            flags,
            service: Some(service),
            regex: Some(regex),
            replacement: Some(replacement)
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(126);

        buf.extend_from_slice(&self.order.to_be_bytes());
        buf.extend_from_slice(&self.preference.to_be_bytes());

        let length = self.flags.len();
        buf.push(((length * 2) - 1) as u8);
        for (i, flag) in self.flags.iter().enumerate() {
            buf.push(flag.code());
            if i < length - 1 {
                buf.push(b',');
            }
        }

        let service = self.service.as_ref().ok_or_else(|| RRDataError("service param was not set".to_string()))?.as_bytes();
        buf.push(service.len() as u8);
        buf.extend_from_slice(service);

        let regex = self.regex.as_ref().ok_or_else(|| RRDataError("regex param was not set".to_string()))?.as_bytes();
        buf.push(regex.len() as u8);
        buf.extend_from_slice(regex);

        buf.extend_from_slice(&pack_fqdn(self.replacement.as_ref()
            .ok_or_else(|| RRDataError("replacement param was not set".to_string()))?));

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

impl NaptrRRData {

    pub fn new(order: u16, preference: u16, flags: Vec<NaptrFlags>, service: &str, regex: &str, replacement: &str) -> Self {
        Self {
            order,
            preference,
            flags,
            service: Some(service.to_string()),
            regex: Some(regex.to_string()),
            replacement: Some(replacement.to_string())
        }
    }

    pub fn set_order(&mut self, order: u16) {
        self.order = order;
    }

    pub fn order(&self) -> u16 {
        self.order
    }

    pub fn set_preference(&mut self, preference: u16) {
        self.preference = preference;
    }

    pub fn preference(&self) -> u16 {
        self.preference
    }

    pub fn add_flags(&mut self, flags: NaptrFlags) {
        self.flags.push(flags);
    }

    pub fn flags(&self) -> &Vec<NaptrFlags> {
        self.flags.as_ref()
    }

    pub fn flags_mut(&mut self) -> &mut Vec<NaptrFlags> {
        self.flags.as_mut()
    }

    pub fn set_service(&mut self, service: &str) {
        self.service = Some(service.to_string());
    }

    pub fn service(&self) -> Option<&String> {
        self.service.as_ref()
    }

    pub fn set_regex(&mut self, regex: &str) {
        self.regex = Some(regex.to_string());
    }

    pub fn regex(&self) -> Option<&String> {
        self.regex.as_ref()
    }

    pub fn set_replacement(&mut self, replacement: &str) {
        self.replacement = Some(replacement.to_string());
    }

    pub fn replacement(&self) -> Option<&String> {
        self.replacement.as_ref()
    }
}

impl FromWireLen for NaptrRRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let order = u16::from_wire(context)?;
        let preference = u16::from_wire(context)?;

        let flags_length = u8::from_wire(context)? as usize;
        let mut flags = Vec::new();

        for flag in String::from_utf8(context.take(flags_length)?.to_vec())
            .map_err(|e| WireError::Format(e.to_string()))?.split(",") {
            let tok = flag.trim();
            if tok.is_empty() {
                continue;
            }

            flags.push(NaptrFlags::try_from(flag.chars()
                .next()
                .ok_or_else(|| WireError::Format("empty NAPTR flag token".to_string()))?).map_err(|e| WireError::Format(e.to_string()))?);
        }

        //let mut off = off+5+data_length;

        let service_length = u8::from_wire(context)? as usize;
        let service = String::from_utf8(context.take(service_length)?.to_vec())
            .map_err(|e| WireError::Format(e.to_string()))?;

        let regex_length = u8::from_wire(context)? as usize;
        let regex = String::from_utf8(context.take(regex_length)?.to_vec())
            .map_err(|e| WireError::Format(e.to_string()))?;

        let replacement = context.name()?;

        Ok(Self {
            order,
            preference,
            flags,
            service: Some(service),
            regex: Some(regex),
            replacement: Some(replacement)
        })
    }
}

impl ToWire for NaptrRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        self.order.to_wire(context)?;
        self.preference.to_wire(context)?;

        let flags_length = self.flags.len();
        (((flags_length * 2) - 1) as u8).to_wire(context)?;

        for (i, flag) in self.flags.iter().enumerate() {
            flag.code().to_wire(context)?;
            if i < flags_length - 1 {
                b','.to_wire(context)?;
            }
        }

        let service = self.service.as_ref().ok_or_else(|| WireError::Format("service param was not set".to_string()))?.as_bytes();
        (service.len() as u8).to_wire(context)?;
        context.write(&service)?;

        let regex = self.regex.as_ref().ok_or_else(|| WireError::Format("regex param was not set".to_string()))?.as_bytes();
        (regex.len() as u8).to_wire(context)?;
        context.write(&regex)?;

        context.write_name(self.replacement.as_ref()
            .ok_or_else(|| WireError::Format("replacement param was not set".to_string()))?, false)
    }
}

impl ZoneRRData for NaptrRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.order = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse order param for record type NAPTR"))?,
            1 => self.preference = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse preference param for record type NAPTR"))?,
            2 => {
                let mut flags = Vec::new();

                for flag in value.split(",") {
                    let tok = flag.trim();
                    if tok.is_empty() {
                        continue;
                    }

                    flags.push(NaptrFlags::try_from(flag.chars()
                        .next()
                        .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "empty NAPTR flag token for record type NAPTR"))?)
                        .map_err(|e|ZoneReaderError::new(ErrorKind::Format, &e.to_string()))?);
                }

                self.flags = flags;
            }
            3 => self.service = Some(value.to_string()),
            4 => self.regex = Some(value.to_string()),
            5 => self.replacement = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "replacement param is not fully qualified (missing trailing dot) for record type NAPTR"))?.to_string()),
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type NAPTR"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for NaptrRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} \"{}\" \"{}\" \"{}\" {}", self.order,
               self.preference,
               self.flags.iter()
                   .map(|f| f.to_string())
                   .collect::<Vec<_>>()
                   .join(","),
               self.service.as_ref().unwrap_or(&String::new()),
               self.regex.as_ref().unwrap_or(&String::new()),
               format!("{}.", self.replacement.as_ref().unwrap_or(&String::new())))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x0, 0x64, 0x0, 0xa, 0x3, 0x55, 0x2c, 0x50, 0x7, 0x45, 0x32, 0x55, 0x2b, 0x73, 0x69, 0x70, 0x19, 0x21, 0x5e, 0x2e, 0x2a, 0x24, 0x21, 0x73, 0x69, 0x70, 0x3a, 0x69, 0x6e, 0x66, 0x6f, 0x40, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x2e, 0x6e, 0x65, 0x74, 0x21, 0x0 ];
    let record = NaptrRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

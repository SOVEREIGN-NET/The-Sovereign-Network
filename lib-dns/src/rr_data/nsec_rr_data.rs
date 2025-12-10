use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::wire::{FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NSecRRData {
    next_domain: Option<String>,
    types: Vec<RRTypes>
}

impl Default for NSecRRData {

    fn default() -> Self {
        Self {
            next_domain: None,
            types: Vec::new()
        }
    }
}

impl RRData for NSecRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let (next_domain, next_domain_length) = unpack_fqdn(buf, 0);

        let mut i = next_domain_length;
        let mut types = Vec::new();

        while i < buf.len() {
            if i+2 > buf.len() {
                return Err(RRDataError("truncated NSEC window header".to_string()));
            }

            let window = buf[i];
            let data_length = buf[i+1] as usize;
            i += 2;

            if data_length == 0 || data_length > 32 {
                return Err(RRDataError("invalid NSEC window length".to_string()));
            }

            if i+data_length > buf.len() {
                return Err(RRDataError("truncated NSEC bitmap".to_string()));
            }

            for (i, &byte) in buf[i..i+data_length].iter().enumerate() {
                for bit in 0..8 {
                    if (byte & (1 << (7 - bit))) != 0 {
                        let _type = RRTypes::try_from((window as u16) * 256 + (i as u16 * 8 + bit as u16))
                            .map_err(|e| RRDataError(e.to_string()))?;
                        types.push(_type);
                    }
                }
            }

            i += data_length;
        }

        Ok(Self {
            next_domain: Some(next_domain),
            types
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(94);

        buf.extend_from_slice(&pack_fqdn(self.next_domain.as_ref()
            .ok_or_else(|| RRDataError("mailbox param was not set".to_string()))?));

        let mut windows: Vec<Vec<u8>> = vec![Vec::new(); 256];

        for _type in self.types.iter() {
            let code = _type.code();
            let w = (code >> 8) as usize;
            let low = (code & 0xFF) as u8;
            let byte_i = (low >> 3) as usize;
            let bit_in_byte = 7 - (low & 0x07);

            let bm = &mut windows[w];
            if bm.len() <= byte_i {
                bm.resize(byte_i + 1, 0);
            }
            bm[byte_i] |= 1 << bit_in_byte;
        }

        for (win, bm) in windows.into_iter().enumerate() {
            let mut used = bm.len();
            while used > 0 && bm[used - 1] == 0 {
                used -= 1;
            }
            if used == 0 {
                continue;
            }

            buf.push(win as u8);
            buf.push(used as u8);
            buf.extend_from_slice(&bm[..used]);
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

impl NSecRRData {

    pub fn new(next_domain: &str, types: Vec<RRTypes>) -> Self {
        Self {
            next_domain: Some(next_domain.to_string()),
            types
        }
    }

    pub fn set_next_domain(&mut self, next_domain: &str) {
        self.next_domain = Some(next_domain.to_string());
    }

    pub fn next_domain(&self) -> Option<&String> {
        self.next_domain.as_ref()
    }

    pub fn add_type(&mut self, _type: RRTypes) {
        self.types.push(_type);
    }

    pub fn types(&self) -> &Vec<RRTypes> {
        self.types.as_ref()
    }

    pub fn types_mut(&mut self) -> &mut Vec<RRTypes> {
        self.types.as_mut()
    }
}

impl FromWireLen for NSecRRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        todo!()
    }
}

impl ToWire for NSecRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        todo!()
    }
}

impl ZoneRRData for NSecRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.next_domain = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "next_domain param is not fully qualified (missing trailing dot) for record type NSEC"))?.to_string()),
            _ => self.types.push(RRTypes::from_str(value)
                .map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse types param for record type NSEC"))?)
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for NSecRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", format!("{}.", self.next_domain.as_ref().unwrap_or(&String::new())),
               self.types.iter()
                   .map(|t| t.to_string())
                   .collect::<Vec<_>>()
                   .join(" "))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x1, 0x0, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x9, 0x62, 0x5, 0x80, 0xc, 0x54, 0xb, 0x8d, 0x1c, 0xc0, 0x1, 0x1, 0xc0 ];
    let record = NSecRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::{base32, hex};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NSec3RRData {
    algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
    next_hash: Vec<u8>,
    types: Vec<RRTypes>
}

impl Default for NSec3RRData {

    fn default() -> Self {
        Self {
            algorithm: 0,
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
            next_hash: Vec::new(),
            types: Vec::new()
        }
    }
}

impl RRData for NSec3RRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let algorithm = buf[0];
        let flags = buf[1];
        let iterations = u16::from_be_bytes([buf[2], buf[3]]);

        let salt_length = buf[4] as usize;
        let salt = buf[5..5 + salt_length].to_vec();

        let mut i = 5+salt_length;
        let next_hash_length = buf[i+1] as usize;
        let next_hash = buf[i+1..i+1+next_hash_length].to_vec();
        i += 1+next_hash_length;


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
            algorithm,
            flags,
            iterations,
            salt,
            next_hash,
            types
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(126);

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

impl NSec3RRData {

    pub fn new(algorithm: u8, flags: u8, iterations: u16, salt: &[u8], next_hash: &[u8], types: Vec<RRTypes>) -> Self {
        Self {
            algorithm,
            flags,
            iterations,
            salt: salt.to_vec(),
            next_hash: next_hash.to_vec(),
            types
        }
    }

    pub fn set_algorithm(&mut self, algorithm: u8) {
        self.algorithm = algorithm;
    }

    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn set_iterations(&mut self, iterations: u16) {
        self.iterations = iterations;
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn set_next_hash(&mut self, next_hash: &[u8]) {
        self.next_hash = next_hash.to_vec();
    }

    pub fn next_hash(&self) -> &[u8] {
        &self.next_hash
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

impl FromWireLen for NSec3RRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        let algorithm = u8::from_wire(context)?;
        let flags = u8::from_wire(context)?;
        let iterations = u16::from_wire(context)?;

        let salt_length = u8::from_wire(context)? as usize;
        let salt = context.take(salt_length)?.to_vec();

        let next_hash_length = u8::from_wire(context)? as usize;
        let next_hash = context.take(next_hash_length)?.to_vec();

        let mut types = Vec::new();

        /*
        let mut i = len-6-salt_length as u16-next_hash_length as u16;
        while i < len {
            if i+2 > len {
                return Err(RRDataError("truncated NSEC window header".to_string()));
            }

            let window = buf[off];
            let data_length = buf[off + 1] as usize;
            off += 2;

            if data_length == 0 || data_length > 32 {
                return Err(RRDataError("invalid NSEC window length".to_string()));
            }

            if off + data_length > len {
                return Err(RRDataError("truncated NSEC bitmap".to_string()));
            }

            for (i, &byte) in buf[off..off + data_length].iter().enumerate() {
                for bit in 0..8 {
                    if (byte & (1 << (7 - bit))) != 0 {
                        let _type = RRTypes::try_from((window as u16) * 256 + (i as u16 * 8 + bit as u16))
                            .map_err(|e| RRDataError(e.to_string()))?;
                        types.push(_type);
                    }
                }
            }

            off += data_length;
        }
        */

        Ok(Self {
            algorithm,
            flags,
            iterations,
            salt,
            next_hash,
            types
        })
    }
}

impl ToWire for NSec3RRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        todo!()
    }
}

impl ZoneRRData for NSec3RRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.algorithm = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse algorithm param for record type NSEC3"))?,
            1 => self.flags = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse flags param for record type NSEC3"))?,
            2 => self.iterations = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse iterations param for record type NSEC3"))?,
            3 => {
                if !value.eq("-") {
                    self.salt = hex::decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse salt param for record type NSEC3"))?
                }
            }
            4 => self.next_hash = base32::hex_decode(value).map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse next_hash param for record type NSEC3"))?,
            _ => self.types.push(RRTypes::from_str(value)
                .map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse types param for record type NSEC3"))?)
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for NSec3RRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {} {}", self.algorithm,
               self.flags,
               self.iterations,
               base32::hex_encode_nopad(&self.salt),
               self.types.iter()
                   .map(|t| t.to_string())
                   .collect::<Vec<_>>()
                   .join(" "))
    }
}

#[test]
fn test() {
    let buf = vec![ ];
    let record = NSec3RRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

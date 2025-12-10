use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::ZoneReaderError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxtRRData {
    data: Vec<String>
}

impl Default for TxtRRData {

    fn default() -> Self {
        Self {
            data: Vec::new()
        }
    }
}

impl RRData for TxtRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let mut data = Vec::new();
        let mut i = 0;

        while i < buf.len() {
            let data_length = buf[i] as usize;
            let record = String::from_utf8(buf[i+1..i+1+data_length].to_vec())
                .map_err(|e| RRDataError(e.to_string()))?;
            data.push(record);
            i += data_length+1;
        }

        Ok(Self {
            data
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(78);

        for record in &self.data {
            let record_bytes = record.as_bytes();
            buf.push(record_bytes.len() as u8);
            buf.extend_from_slice(record_bytes);
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

impl TxtRRData {

    pub fn new(data: Vec<String>) -> Self {
        Self {
            data
        }
    }

    pub fn add_data(&mut self, data: &str) {
        self.data.push(data.to_string());
    }

    pub fn data(&self) -> &Vec<String> {
        self.data.as_ref()
    }

    pub fn data_mut(&mut self) -> &mut Vec<String> {
        self.data.as_mut()
    }
}

impl FromWireLen for TxtRRData {

    fn from_wire_len(context: &mut FromWireContext, len: u16) -> Result<Self, WireError> {
        let mut data = Vec::new();

        let mut i = 0;
        while i < len {
            let data_length = u8::from_wire(context)? as usize;
            let record = String::from_utf8(context.take(data_length)?.to_vec())
                .map_err(|e| WireError::Format(e.to_string()))?;
            data.push(record);
            i += data_length as u16 +1;
        }

        Ok(Self {
            data
        })
    }
}

impl ToWire for TxtRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        for record in &self.data {
            let record_bytes = record.as_bytes();
            (record_bytes.len() as u8).to_wire(context)?;
            context.write(record_bytes)?;
        }

        Ok(())
    }
}

impl ZoneRRData for TxtRRData {

    fn set_data(&mut self, _index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(self.data.push(value.to_string()))
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for TxtRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.data.iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(" "))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x9, 0x76, 0x3d, 0x62, 0x6c, 0x61, 0x20, 0x62, 0x6c, 0x61 ];
    let record = TxtRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

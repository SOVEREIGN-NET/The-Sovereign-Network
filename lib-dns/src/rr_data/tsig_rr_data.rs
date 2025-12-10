use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use crate::keyring::inter::algorithms::Algorithms;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::utils::hex;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TSigRRData {
    algorithm: Option<Algorithms>,
    time_signed: u64,
    fudge: u16,
    mac: Option<Vec<u8>>,
    original_id: u16,
    error: u16,
    data: Vec<u8>
}

impl Default for TSigRRData {

    fn default() -> Self {
        Self {
            algorithm: None,
            time_signed: 0,
            fudge: 0,
            mac: None,
            original_id: 0,
            error: 0,
            data: Vec::new()
        }
    }
}

impl RRData for TSigRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let (algorithm, algorithm_length) = unpack_fqdn(buf, 0);
        let algorithm = Algorithms::from_str(&algorithm)
            .map_err(|e| RRDataError(e.to_string()))?;
        let mut i = algorithm_length;

        let time_signed = ((buf[i] as u64) << 40)
                | ((buf[i+1] as u64) << 32)
                | ((buf[i+2] as u64) << 24)
                | ((buf[i+3] as u64) << 16)
                | ((buf[i+4] as u64) << 8)
                |  (buf[i+5] as u64);
        let fudge = u16::from_be_bytes([buf[i+6], buf[i+7]]);

        let mac_length = 10+u16::from_be_bytes([buf[i+8], buf[i+9]]) as usize;
        let mac = buf[i+10..i+mac_length].to_vec();
        i += mac_length;

        let original_id = u16::from_be_bytes([buf[i], buf[i+1]]);
        let error = u16::from_be_bytes([buf[i+2], buf[i+3]]);

        let data_length = i+6+u16::from_be_bytes([buf[i+4], buf[i+5]]) as usize;
        let data = buf[i+6..data_length].to_vec();

        Ok(Self {
            algorithm: Some(algorithm),
            time_signed,
            fudge,
            mac: Some(mac),
            original_id,
            error,
            data
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(158);

        buf.extend_from_slice(&pack_fqdn(&self.algorithm.as_ref()
            .ok_or_else(|| RRDataError("algorithm param was not set".to_string()))?.to_string())); //PROBABLY NO COMPRESS

        buf.extend_from_slice(&[
            ((self.time_signed >> 40) & 0xFF) as u8,
            ((self.time_signed >> 32) & 0xFF) as u8,
            ((self.time_signed >> 24) & 0xFF) as u8,
            ((self.time_signed >> 16) & 0xFF) as u8,
            ((self.time_signed >>  8) & 0xFF) as u8,
            ( self.time_signed        & 0xFF) as u8
        ]);
        buf.extend_from_slice(&self.fudge.to_be_bytes());

        buf.extend_from_slice(&(self.mac.as_ref()
            .ok_or_else(|| RRDataError("mac param was not set".to_string()))?.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.mac.as_ref()
            .ok_or_else(|| RRDataError("mac param was not set".to_string()))?);

        buf.extend_from_slice(&self.original_id.to_be_bytes());
        buf.extend_from_slice(&self.error.to_be_bytes());

        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.data);

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

impl TSigRRData {

    pub fn new(algorithm: Algorithms, time_signed: u64, fudge: u16, original_id: u16, error: u16, data: &[u8]) -> Self {
        Self {
            algorithm: Some(algorithm),
            time_signed,
            fudge,
            mac: None,
            original_id,
            error,
            data: data.to_vec()
        }
    }

    pub fn set_algorithm(&mut self, algorithm: Algorithms) {
        self.algorithm = Some(algorithm);
    }

    pub fn algorithm(&self) -> Option<&Algorithms> {
        self.algorithm.as_ref()
    }

    pub fn set_time_signed(&mut self, time_signed: u64) {
        self.time_signed = time_signed;
    }

    pub fn time_signed(&self) -> u64 {
        self.time_signed
    }

    pub fn set_fudge(&mut self, fudge: u16) {
        self.fudge = fudge;
    }

    pub fn fudge(&self) -> u16 {
        self.fudge
    }

    pub fn set_mac(&mut self, mac: &[u8]) {
        self.mac = Some(mac.to_vec());
    }

    pub fn mac(&self) -> Option<&Vec<u8>> {
        self.mac.as_ref()
    }

    pub fn set_original_id(&mut self, original_id: u16) {
        self.original_id = original_id;
    }

    pub fn original_id(&self) -> u16 {
        self.original_id
    }

    pub fn set_error(&mut self, error: u16) {
        self.error = error;
    }

    pub fn error(&self) -> u16 {
        self.error
    }

    pub fn set_data(&mut self, data: &[u8]) {
        self.data = data.to_vec();
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl FromWireLen for TSigRRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let algorithm = Algorithms::from_str(&context.name()?)
            .map_err(|e| WireError::Format(e.to_string()))?;

        let time_signed = context.take(6)?;
        let time_signed = ((time_signed[0] as u64) << 40)
            | ((time_signed[1] as u64) << 32)
            | ((time_signed[2] as u64) << 24)
            | ((time_signed[3] as u64) << 16)
            | ((time_signed[4] as u64) << 8)
            |  (time_signed[5] as u64);
        let fudge = u16::from_wire(context)?;

        let mac_length = u16::from_wire(context)? as usize;
        let mac = context.take(mac_length)?.to_vec();

        let original_id = u16::from_wire(context)?;
        let error = u16::from_wire(context)?;

        let data_length = u16::from_wire(context)? as usize;
        let data = context.take(data_length)?.to_vec();

        Ok(Self {
            algorithm: Some(algorithm),
            time_signed,
            fudge,
            mac: Some(mac),
            original_id,
            error,
            data
        })
    }
}

impl ToWire for TSigRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(&self.algorithm.as_ref()
            .ok_or_else(|| WireError::Format("algorithm param was not set".to_string()))?.to_string(), false)?; //PROBABLY NO COMPRESS

        context.write(&[
            ((self.time_signed >> 40) & 0xFF) as u8,
            ((self.time_signed >> 32) & 0xFF) as u8,
            ((self.time_signed >> 24) & 0xFF) as u8,
            ((self.time_signed >> 16) & 0xFF) as u8,
            ((self.time_signed >>  8) & 0xFF) as u8,
            ( self.time_signed        & 0xFF) as u8
        ])?;
        self.fudge.to_wire(context)?;

        (self.mac.as_ref()
            .ok_or_else(|| WireError::Format("mac param was not set".to_string()))?.len() as u16).to_wire(context)?;
        context.write(&self.mac.as_ref()
            .ok_or_else(|| WireError::Format("mac param was not set".to_string()))?)?;

        self.original_id.to_wire(context)?;
        self.error.to_wire(context)?;

        (self.data.len() as u16).to_wire(context)?;
        context.write(&self.data)
    }
}

impl fmt::Display for TSigRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {}", format!("{}.", self.algorithm.as_ref().unwrap()),
               self.time_signed,
               self.fudge,
               hex::encode(&self.mac.as_ref().unwrap()),
               self.original_id,
               self.error,
               hex::encode(&self.data))
    }
}

#[test]
fn test() {
    let buf = vec![ 0x8, 0x67, 0x73, 0x73, 0x2d, 0x74, 0x73, 0x69, 0x67, 0x0, 0x0, 0x0, 0x50, 0xf8, 0xcf, 0xbb, 0x8c, 0xa0, 0x0, 0x1c, 0x4, 0x4, 0x5, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x73, 0x28, 0x5d, 0xa, 0x2d, 0xf4, 0xa3, 0x34, 0x2f, 0xcf, 0x1, 0x6f, 0x3c, 0x9f, 0x76, 0x82, 0x2, 0x34, 0x0, 0x0, 0x0, 0x0 ];
    let record = TSigRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

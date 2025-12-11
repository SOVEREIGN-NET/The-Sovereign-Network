use std::any::Any;
use std::fmt;
use std::fmt::Formatter;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::{RRData, RRDataError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};
use crate::zone::inter::zone_rr_data::ZoneRRData;
use crate::zone::zone_reader::{ErrorKind, ZoneReaderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoaRRData {
    fqdn: Option<String>,
    mailbox: Option<String>,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum_ttl: u32
}

impl Default for SoaRRData {

    fn default() -> Self {
        Self {
            fqdn: None,
            mailbox: None,
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum_ttl: 0
        }
    }
}

impl RRData for SoaRRData {

    fn from_bytes(buf: &[u8]) -> Result<Self, RRDataError> {
        let (fqdn, fqdn_length) = unpack_fqdn(buf, 0);
        let mut i = fqdn_length;

        let (mailbox, mailbox_length) = unpack_fqdn(buf, i);
        i += mailbox_length;

        let serial = u32::from_be_bytes([buf[i], buf[i+1], buf[i+2], buf[i+3]]);
        let refresh = u32::from_be_bytes([buf[i+4], buf[i+5], buf[i+6], buf[i+7]]);
        let retry = u32::from_be_bytes([buf[i+8], buf[i+9], buf[i+10], buf[i+11]]);
        let expire = u32::from_be_bytes([buf[i+12], buf[i+13], buf[i+14], buf[i+15]]);
        let minimum_ttl = u32::from_be_bytes([buf[i+16], buf[i+17], buf[i+18], buf[i+19]]);

        Ok(Self {
            fqdn: Some(fqdn),
            mailbox: Some(mailbox),
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RRDataError> {
        let mut buf = Vec::with_capacity(94);

        let fqdn = pack_fqdn(self.fqdn.as_ref()
            .ok_or_else(|| RRDataError("fqdn param was not set".to_string()))?);
        buf.extend_from_slice(&fqdn);

        buf.extend_from_slice(&pack_fqdn(self.mailbox.as_ref()
            .ok_or_else(|| RRDataError("mailbox param was not set".to_string()))?));

        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.refresh.to_be_bytes());
        buf.extend_from_slice(&self.retry.to_be_bytes());
        buf.extend_from_slice(&self.expire.to_be_bytes());
        buf.extend_from_slice(&self.minimum_ttl.to_be_bytes());

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

impl SoaRRData {

    pub fn new(fqdn: &str, mailbox: &str, serial: u32, refresh: u32, retry: u32, expire: u32, minimum_ttl: u32) -> Self {
        Self {
            fqdn: Some(fqdn.to_string()),
            mailbox: Some(mailbox.to_string()),
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl
        }
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = Some(fqdn.to_string());
    }

    pub fn fqdn(&self) -> Option<&String> {
        self.fqdn.as_ref()
    }

    pub fn set_mailbox(&mut self, mailbox: &str) {
        self.mailbox = Some(mailbox.to_string());
    }

    pub fn mailbox(&self) -> Option<&String> {
        self.mailbox.as_ref()
    }

    pub fn set_serial(&mut self, serial: u32) {
        self.serial = serial;
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn set_refresh(&mut self, refresh: u32) {
        self.refresh = refresh;
    }

    pub fn refresh(&self) -> u32 {
        self.refresh
    }

    pub fn set_retry(&mut self, retry: u32) {
        self.retry = retry;
    }

    pub fn retry(&self) -> u32 {
        self.retry
    }

    pub fn set_expire(&mut self, expire: u32) {
        self.expire = expire;
    }

    pub fn expire(&self) -> u32 {
        self.expire
    }

    pub fn set_minimum_ttl(&mut self, minimum_ttl: u32) {
        self.minimum_ttl = minimum_ttl;
    }

    pub fn minimum_ttl(&self) -> u32 {
        self.minimum_ttl
    }
}

impl FromWireLen for SoaRRData {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let fqdn = context.name()?;
        let mailbox = context.name()?;

        let serial = u32::from_wire(context)?;
        let refresh = u32::from_wire(context)?;
        let retry = u32::from_wire(context)?;
        let expire = u32::from_wire(context)?;
        let minimum_ttl = u32::from_wire(context)?;

        Ok(Self {
            fqdn: Some(fqdn),
            mailbox: Some(mailbox),
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl
        })
    }
}

impl ToWire for SoaRRData {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(self.fqdn.as_ref()
            .ok_or_else(|| WireError::Format("fqdn param was not set".to_string()))?, true)?;

        context.write_name(self.mailbox.as_ref()
            .ok_or_else(|| WireError::Format("mailbox param was not set".to_string()))?, true)?;

        self.serial.to_wire(context)?;
        self.refresh.to_wire(context)?;
        self.retry.to_wire(context)?;
        self.expire.to_wire(context)?;
        self.minimum_ttl.to_wire(context)
    }
}

impl ZoneRRData for SoaRRData {

    fn set_data(&mut self, index: usize, value: &str) -> Result<(), ZoneReaderError> {
        Ok(match index {
            0 => self.fqdn = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "fqdn param is not fully qualified (missing trailing dot) for record type SOA"))?.to_string()),
            1 => self.mailbox = Some(value.strip_suffix('.')
                .ok_or_else(|| ZoneReaderError::new(ErrorKind::Format, "mailbox param is not fully qualified (missing trailing dot) for record type SOA"))?.to_string()),
            2 => self.serial = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse serial param for record type SOA"))?,
            3 => self.refresh = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse refresh param for record type SOA"))?,
            4 => self.retry = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse retry param for record type SOA"))?,
            5 => self.expire = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse expire param for record type SOA"))?,
            6 => self.minimum_ttl = value.parse().map_err(|_| ZoneReaderError::new(ErrorKind::Format, "unable to parse minimum_ttl param for record type SOA"))?,
            _ => return Err(ZoneReaderError::new(ErrorKind::ExtraRRData, "extra record data found for record type SOA"))
        })
    }

    fn upcast(self) -> Box<dyn ZoneRRData> {
        Box::new(self)
    }
}

impl fmt::Display for SoaRRData {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {}", format!("{}.", self.fqdn.as_ref().unwrap_or(&String::new())),
               format!("{}.", self.mailbox.as_ref().unwrap_or(&String::new())),
               self.serial,
               self.refresh,
               self.retry,
               self.expire,
               self.minimum_ttl)
    }
}

#[test]
fn test() {
    let buf = vec![ 0x3, 0x6e, 0x73, 0x31, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x5, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x5, 0x66, 0x69, 0x6e, 0x64, 0x39, 0x3, 0x6e, 0x65, 0x74, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x9, 0x3a, 0x80, 0x0, 0x1, 0x51, 0x80, 0x0, 0x24, 0xea, 0x0, 0x0, 0x9, 0x3a, 0x80 ];
    let record = SoaRRData::from_bytes(&buf).unwrap();
    assert_eq!(buf, record.to_bytes().unwrap());
}

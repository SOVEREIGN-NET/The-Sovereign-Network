use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::wire::{FromWire, FromWireContext, ToWire, ToWireContext, WireError};
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Debug, Clone)]
pub struct RRQuery {
    fqdn: String,
    rtype: RRTypes,
    class: RRClasses
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RRQueryError(pub String);

impl fmt::Display for RRQueryError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl RRQuery {

    pub fn new(fqdn: &str, rtype: RRTypes, class: RRClasses) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            rtype,
            class
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, RRQueryError> {
        let (fqdn, fqdn_length) = unpack_fqdn(buf, 0);

        let rtype = RRTypes::try_from(u16::from_be_bytes([buf[fqdn_length], buf[1+fqdn_length]]))
            .map_err(|e| RRQueryError(e.to_string()))?;
        let class = RRClasses::try_from(u16::from_be_bytes([buf[2+fqdn_length], buf[3+fqdn_length]]))
            .map_err(|e| RRQueryError(e.to_string()))?;

        Ok(Self {
            fqdn,
            rtype,
            class
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = pack_fqdn(&self.fqdn);

        buf.extend_from_slice(&self.rtype.code().to_be_bytes());
        buf.extend_from_slice(&self.class.code().to_be_bytes());

        buf
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = fqdn.to_string();
    }

    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn set_rtype(&mut self, rtype: RRTypes) {
        self.rtype = rtype;
    }

    pub fn rtype(&self) -> RRTypes {
        self.rtype
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn class(&self) -> RRClasses {
        self.class
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl FromWire for RRQuery {

    fn from_wire(context: &mut FromWireContext) -> Result<Self, WireError> {
        let fqdn = context.name()?;

        let rtype = RRTypes::try_from(u16::from_wire(context)?).map_err(|e| WireError::Format(e.to_string()))?;
        let class = RRClasses::try_from(u16::from_wire(context)?).map_err(|e| WireError::Format(e.to_string()))?;

        Ok(Self {
            fqdn,
            rtype,
            class
        })
    }
}

impl ToWire for RRQuery {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(self.fqdn(), true)?;

        self.rtype.code().to_wire(context)?;
        self.class.code().to_wire(context)?;

        Ok(())
    }
}

impl fmt::Display for RRQuery {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<31}{:<8}{}", format!("{}.", self.fqdn), self.class.to_string(), self.rtype)
    }
}

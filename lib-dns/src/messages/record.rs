use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::wire::{FromWire, FromWireContext, ToWire, ToWireContext, WireError};
use crate::rr_data::inter::rr_data::RRData;

#[derive(Debug, Clone)]
pub struct Record {
    fqdn: String,
    class: RRClasses,
    rtype: RRTypes,
    ttl: u32,
    data: Option<Box<dyn RRData>>
}

impl Record {

    pub fn new(fqdn: &str, class: RRClasses, rtype: RRTypes, ttl: u32, data: Option<Box<dyn RRData>>) -> Self {
        Self {
            fqdn: fqdn.to_string(),
            class,
            rtype,
            ttl,
            data
        }
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = fqdn.to_string();
    }

    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn class(&self) -> RRClasses {
        self.class
    }

    pub fn set_type(&mut self, rtype: RRTypes) {
        self.rtype = rtype;
    }

    pub fn rtype(&self) -> RRTypes {
        self.rtype
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_data(&mut self, data: Option<Box<dyn RRData>>) {
        self.data = data;
    }

    pub fn data(&self) -> Option<&Box<dyn RRData>> {
        self.data.as_ref()
    }
}

impl FromWire for Record {

    fn from_wire(context: &mut FromWireContext) -> Result<Self, WireError> {
        let fqdn = context.name()?;

        let rtype = RRTypes::try_from(u16::from_wire(context)?).map_err(|e| WireError::Format(e.to_string()))?;

        let class = u16::from_wire(context)?;
        let cache_flush = (class & 0x8000) != 0;
        let class = RRClasses::try_from(class).map_err(|e| WireError::Format(e.to_string()))?;
        let ttl = u32::from_wire(context)?;

        let len = u16::from_wire(context)?;
        let data = match len {
            0 => None,
            _ => Some(<dyn RRData>::from_wire(context, len, &rtype, &class)?)
        };

        Ok(Self {
            fqdn,
            class,
            rtype,
            ttl,
            data
        })
    }
}

impl ToWire for Record {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(&self.fqdn, true)?;

        match &self.data {
            Some(data) => {
                self.rtype.code().to_wire(context)?;

                self.class.code().to_wire(context)?;
                self.ttl.to_wire(context)?;

                let checkpoint = context.pos();
                context.skip(2)?;

                data.to_wire(context)?;

                context.patch(checkpoint..checkpoint+2, &((context.pos()-checkpoint-2) as u16).to_be_bytes())?;
            }
            None => {
                self.rtype.code().to_wire(context)?;

                self.class.code().to_wire(context)?;
                self.ttl.to_wire(context)?;

                0u16.to_wire(context)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for Record {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<24}{:<8}{:<8}{:<8}{}",
                 format!("{}.", self.fqdn),
                 self.ttl,
                 self.rtype.to_string(),
                 self.class.to_string(),
                 self.data.as_ref().map(|d| d.to_string()).unwrap_or(String::new()))
    }
}

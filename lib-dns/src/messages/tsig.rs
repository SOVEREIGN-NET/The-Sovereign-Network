use std::fmt;
use std::fmt::Formatter;
use crate::keyring::key::Key;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::tsig_rr_data::TSigRRData;
use crate::utils::fqdn_utils::pack_fqdn;
use crate::utils::hash::hmac::hmac;
use crate::utils::hash::sha256::Sha256;

#[derive(Debug, Clone)]
pub struct TSig {
    owner: String,
    data: TSigRRData,
    signed_payload: Vec<u8>
}

impl TSig {

    pub fn new(owner: &str, data: TSigRRData) -> Self {
        Self {
            owner: owner.to_string(),
            data,
            signed_payload: Vec::new()
        }
    }

    pub fn set_owner(&mut self, owner: &str) {
        self.owner = owner.to_string();
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn set_data(&mut self, data: TSigRRData) {
        self.data = data;
    }

    pub fn data(&self) -> &TSigRRData {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut TSigRRData {
        &mut self.data
    }

    pub fn set_signed_payload(&mut self, signed_payload: &[u8]) {
        self.signed_payload = signed_payload.to_vec();
    }

    pub fn signed_payload(&self) -> &[u8] {
        &self.signed_payload
    }

    pub fn add_to_signed_payload(&mut self, signed_payload: &[u8]) {
        self.signed_payload.extend_from_slice(&signed_payload);
    }

    pub fn verify(&self, key: &Key) -> bool {
        let calc = hmac::<Sha256>(key.secret(), &self.signed_payload);
        self.data.mac().as_ref().unwrap().len() == calc.len() &&
            self.data.mac().as_ref().unwrap().iter().zip(calc).fold(0u8, |d,(a,b)| d | (a^b)) == 0
    }

    pub fn sign(&mut self, key: &Key) {
        let hmac = hmac::<Sha256>(key.secret(), &self.signed_payload);
        self.data.set_mac(hmac.as_slice());
    }
}

impl FromWireLen for TSig {

    fn from_wire_len(context: &mut FromWireContext, _len: u16) -> Result<Self, WireError> {
        let owner = context.name()?;
        let checkpoint = context.pos();

        let rtype = RRTypes::try_from(u16::from_wire(context)?).map_err(|e| WireError::Format(e.to_string()))?;

        let class = u16::from_wire(context)?;
        let cache_flush = (class & 0x8000) != 0;
        let class = RRClasses::try_from(class).map_err(|e| WireError::Format(e.to_string()))?;
        let ttl = u32::from_wire(context)?;


        let len = u16::from_wire(context)?;
        let data = match len {
            0 => None,
            _ => {
                let data = TSigRRData::from_wire_len(context, len)?;

                let mut signed_payload = context.range(0..checkpoint)?.to_vec();
                //signed_payload[10..12].copy_from_slice(&(ar_count - 1).to_be_bytes());

                signed_payload.extend_from_slice(&RRClasses::Any.code().to_be_bytes());
                signed_payload.extend_from_slice(&0u32.to_be_bytes());

                signed_payload.extend_from_slice(&pack_fqdn(&data.algorithm().as_ref()
                    .ok_or_else(|| WireError::Format("algorithm param was not set".to_string()))?.to_string())); //PROBABLY NO COMPRESS

                signed_payload.extend_from_slice(&[
                    ((data.time_signed() >> 40) & 0xFF) as u8,
                    ((data.time_signed() >> 32) & 0xFF) as u8,
                    ((data.time_signed() >> 24) & 0xFF) as u8,
                    ((data.time_signed() >> 16) & 0xFF) as u8,
                    ((data.time_signed() >>  8) & 0xFF) as u8,
                    ( data.time_signed()        & 0xFF) as u8
                ]);
                signed_payload.extend_from_slice(&data.fudge().to_be_bytes());

                signed_payload.extend_from_slice(&data.error().to_be_bytes());

                signed_payload.extend_from_slice(&(data.data().len() as u16).to_be_bytes());
                signed_payload.extend_from_slice(&data.data());

                Some((data, signed_payload))
            }
        };

        /*
        Ok(Self {
            owner,
            data,
            signed_payload
        })
        */

        todo!()
    }
}

impl ToWire for TSig {

    fn to_wire(&self, context: &mut ToWireContext) -> Result<(), WireError> {
        context.write_name(&self.owner, false)?;

        RRTypes::TSig.code().to_wire(context)?;

        RRClasses::Any.code().to_wire(context)?;
        0u32.to_wire(context)?;

        let checkpoint = context.pos();
        context.skip(2)?;

        self.data.to_wire(context)?;

        context.patch(checkpoint..checkpoint+2, &((context.pos()-checkpoint-2) as u16).to_be_bytes())
    }
}

impl fmt::Display for TSig {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:<24}{:<8}{:<8}{:<8}{}",
               format!("{}.", self.owner),
               0,
               RRTypes::TSig.to_string(),
               RRClasses::Any,
               self.data)
    }
}

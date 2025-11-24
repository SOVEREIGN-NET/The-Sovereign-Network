use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fmt::Formatter;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

#[derive(Clone, Debug)]
pub struct NSecRecord {
    class: RRClasses,
    cache_flush: bool,
    ttl: u32,
    fqdn: Option<String>,
    rr_types: Vec<u16>
}

impl Default for NSecRecord {

    fn default() -> Self {
        Self {
            class: RRClasses::default(),
            cache_flush: false,
            ttl: 0,
            fqdn: None,
            rr_types: Vec::new()
        }
    }
}

impl RecordBase for NSecRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let mut off = off;

        let class = u16::from_be_bytes([buf[off], buf[off+1]]);
        let cache_flush = (class & 0x8000) != 0;
        let class = RRClasses::from_code(class & 0x7FFF).unwrap();
        let ttl = u32::from_be_bytes([buf[off+2], buf[off+3], buf[off+4], buf[off+5]]);

        let (fqdn, length) = unpack_fqdn(buf, off+8);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        off += length+8;

        let mut rr_types = Vec::new();

        while off < data_length {
            let window = buf[off];
            let length = buf[off + 1] as usize;

            if off+2+length > data_length {
                break;
            }

            let bitmap = &buf[off + 2..off + 2 + length];

            for (i, &byte) in bitmap.iter().enumerate() {
                for bit in 0..8 {
                    if byte & (1 << (7 - bit)) != 0 {
                        rr_types.push((window as u16) * 256 + (i as u16 * 8 + bit as u16));
                    }
                }
            }

            off += 2+length;
        }

        Self {
            class,
            cache_flush,
            ttl,
            fqdn: Some(fqdn),
            rr_types
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 8];

        let mut class = self.class.get_code();
        if self.cache_flush {
            class = class | 0x8000;
        }

        buf.splice(0..2, class.to_be_bytes());
        buf.splice(2..6, self.ttl.to_be_bytes());

        buf.extend_from_slice(&pack_fqdn(self.fqdn.as_ref().unwrap().as_str(), label_map, off+10, true));

        let mut windows: BTreeMap<u8, Vec<u8>> = BTreeMap::new();

        for rr_type in &self.rr_types {
            let window = (rr_type / 256) as u8;
            let offset = (rr_type % 256) as usize;
            let byte_index = offset / 8;
            let bit_index = 7 - (offset % 8);

            windows.entry(window).or_insert_with(|| vec![0; 32])[byte_index] |= 1 << bit_index;
        }

        for (window, bitmap) in windows {
            if let Some(non_zero_pos) = bitmap.iter().rposition(|&x| x != 0) {
                let trimmed_bitmap = &bitmap[..=non_zero_pos];

                buf.push(window);
                buf.push(trimmed_bitmap.len() as u8);
                buf.extend_from_slice(trimmed_bitmap);
            }
        }

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Nsec
    }

    fn upcast(self) -> Box<dyn RecordBase> {
        Box::new(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn RecordBase> {
        Box::new(self.clone())
    }
}

impl NSecRecord {

    pub fn new(ttl: u32, class: RRClasses) -> Self {
        Self {
            class,
            ttl,
            ..Self::default()
        }
    }

    pub fn set_class(&mut self, class: RRClasses) {
        self.class = class;
    }

    pub fn get_class(&self) -> RRClasses {
        self.class
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn get_ttl(&self) -> u32 {
        self.ttl
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        self.fqdn = Some(fqdn.to_string());
    }

    pub fn get_fqdn(&self) -> Option<String> {
        self.fqdn.clone()
    }
}

impl fmt::Display for NSecRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "type {:?}, class {:?}, domain {}", self.get_type(), self.class, self.fqdn.as_ref().unwrap())
    }
}

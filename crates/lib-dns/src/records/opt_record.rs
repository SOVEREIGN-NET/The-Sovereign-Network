use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::messages::inter::rr_types::RRTypes;
use crate::records::inter::opt_codes::OptCodes;
use crate::records::inter::record_base::RecordBase;
use crate::utils::hex;
use crate::utils::index_map::IndexMap;

#[derive(Clone, Debug)]
pub struct OptRecord {
    payload_size: u16,
    ext_rcode: u8,
    version: u8,
    flags: u16,
    options: IndexMap<OptCodes, Vec<u8>>
}

impl Default for OptRecord {

    fn default() -> Self {
        Self {
            payload_size: 512,
            ext_rcode: 0,
            version: 0,
            flags: 0x8000,
            options: IndexMap::new()
        }
    }
}

impl RecordBase for OptRecord {

    fn from_bytes(buf: &[u8], off: usize) -> Self {
        let payload_size = u16::from_be_bytes([buf[off], buf[off+1]]);
        let ext_rcode = buf[off+2];
        let version = buf[off+3];
        let flags = u16::from_be_bytes([buf[off+4], buf[off+5]]);

        let data_length = off+8+u16::from_be_bytes([buf[off+6], buf[off+7]]) as usize;
        let mut off = off+8;
        let mut options = IndexMap::new();

        while off < data_length {
            let opt_code = OptCodes::from_code(u16::from_be_bytes([buf[off], buf[off+1]])).unwrap();
            let length = u16::from_be_bytes([buf[off+2], buf[off+3]]) as usize;
            options.insert(opt_code, buf[off + 4..off + 4 + length].to_vec());

            off += 4+length;
        }

        Self {
            payload_size,
            ext_rcode,
            version,
            flags,
            options
        }
    }

    fn to_bytes(&self, label_map: &mut HashMap<String, usize>, off: usize) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 8];

        buf.splice(0..2, self.payload_size.to_be_bytes());

        buf[2] = self.ext_rcode;
        buf[3] = self.version;

        buf.splice(4..6, self.flags.to_be_bytes());

        for (code, option) in self.options.iter() {
            buf.extend_from_slice(&code.get_code().to_be_bytes());
            buf.extend_from_slice(&(option.len() as u16).to_be_bytes());
            buf.extend_from_slice(&option);
        }

        buf.splice(6..8, ((buf.len()-8) as u16).to_be_bytes());

        Ok(buf)
    }

    fn get_type(&self) -> RRTypes {
        RRTypes::Opt
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

impl OptRecord {

    pub fn new(payload_size: u16, ext_rcode: u8, version: u8, flags: u16) -> Self {
        Self {
            payload_size,
            ext_rcode,
            version,
            flags,
            options: IndexMap::new()
        }
    }

    pub fn set_payload_size(&mut self, payload_size: u16) {
        self.payload_size = payload_size;
    }

    pub fn get_payload_size(&self) -> u16 {
        self.payload_size
    }

    pub fn set_ext_rcode(&mut self, ext_rcode: u8) {
        self.ext_rcode = ext_rcode;
    }

    pub fn get_ext_rcode(&self) -> u8 {
        self.ext_rcode
    }

    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }

    pub fn get_flags(&self) -> u16 {
        self.flags
    }

    pub fn has_option(&mut self, code: &OptCodes) -> bool {
        self.options.contains_key(code)
    }

    pub fn insert_option(&mut self, code: OptCodes, option: Vec<u8>) {
        self.options.insert(code, option);
    }

    pub fn get_option(&self, code: &OptCodes) -> Option<&Vec<u8>> {
        self.options.get(code)
    }

    pub fn get_option_mut(&mut self, code: &OptCodes) -> Option<&mut Vec<u8>> {
        self.options.get_mut(code)
    }

    pub fn get_options(&self) -> impl Iterator<Item = (&OptCodes, &Vec<u8>)> {
        self.options.iter()
    }

    pub fn get_options_mut(&mut self) -> impl Iterator<Item = (&OptCodes, &mut Vec<u8>)> {
        self.options.iter_mut()
    }
}

impl fmt::Display for OptRecord {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "; EDNS: version: {}, flags: {}; udp: {}", self.version, self.flags, self.payload_size)?;

        for (code, option) in self.options.iter() {
            match code {
                OptCodes::Ecs => {
                    if option.len() >= 4 {
                        let family = u16::from_be_bytes([option[0], option[1]]);
                        let src_prefix = option[2];
                        let scope_prefix = option[3];
                        let addr = &option[4..];

                        let ip_str = match family {
                            1 => format!("{}", Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
                            2 => format!("{}", Ipv6Addr::from(<[u8; 16]>::try_from(addr).unwrap_or_default())),
                            _ => format!("unknown family {}", family),
                        };

                        write!(f, "\r\n; {code}: {ip_str}/{src_prefix}/{scope_prefix}")?;

                    } else {
                        write!(f, "\r\n; {code}: (invalid)")?;
                    }
                }
                _ => write!(f, "\r\n; {code}: {}", hex::encode(option))?
            }
        }

        Ok(())
    }
}

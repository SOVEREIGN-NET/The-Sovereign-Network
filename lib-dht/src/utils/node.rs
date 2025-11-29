use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{cmp, fmt};
use std::fmt::Formatter;
use super::uid::UID;
use super::hash::crc32c::Crc32c;

pub const V4_MASK: [u8; 4] = [0x03, 0x0f, 0x3f, 0xff];
pub const V6_MASK: [u8; 8] = [0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];
const QUERY_TIME: u128 = 3600000;

#[derive(Debug, Copy, Clone)]
pub struct Node {
    pub(crate) uid: UID,
    pub(crate) address: SocketAddr,
    pub(crate) stale: u32,
    pub(crate) last_seen: u128,
}

impl Node {

    pub fn new(uid: UID, address: SocketAddr) -> Self {
        Self {
            uid,
            address,
            stale: 0,
            last_seen: 0,
        }
    }

    pub fn has_secure_id(&self) -> bool {
        let mut ip: Vec<u8> = match self.address.ip() {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let mask: Vec<u8> = if ip.len() == 4 {
            V4_MASK.to_vec()
        } else {
            V6_MASK.to_vec()
        };

        for i in 0..mask.len() {
            ip[i] &= mask[i];
        }

        let r = self.uid.bid[19] & 0x7;
        ip[0] |= r << 5;

        let mut c = Crc32c::new();
        c.update(&ip, 0, cmp::min(ip.len(), 8));
        let crc = c.get_value();

        let uid_crc = ((u32::from(self.uid.bid[0]) << 24)
            | (u32::from(self.uid.bid[1]) << 16)
            | (u32::from(self.uid.bid[2]) << 8)
            | u32::from(self.uid.bid[3]))
            ^ crc;

        (uid_crc & 0xff_ff_f8_00) == 0
    }

    pub fn seen(&mut self) {
        self.stale = 0;
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis();
    }

    pub fn mark_stale(&mut self) {
        self.stale += 1;
    }

    pub fn has_queried(&self, now: u128) -> bool {
        self.last_seen > 0 && now - self.last_seen < QUERY_TIME
    }

    pub fn verify(&self, other: &Self) -> bool {
        self.uid == other.uid
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Node) -> bool {
        self.address == other.address
    }
}

impl fmt::Display for Node {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{{ \x1b[34mUID\x1b[0m: \x1b[35m{}\x1b[0m, \x1b[34mADDRESS\x1b[0m: \x1b[35m{}\x1b[0m, \x1b[34mPORT\x1b[0m: \x1b[35m{}\x1b[0m, \x1b[34mSECURE\x1b[0m: \x1b[35m{}\x1b[0m }}",
                self.uid.to_string(),
                self.address.ip(),
                self.address.port(),
                false)
    }
}

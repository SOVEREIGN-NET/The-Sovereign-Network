use std::net::IpAddr;

pub struct NetMask {
    pub(crate) address: [u8; 16],//Vec<u8>,
    pub(crate) mask: u32
}

impl NetMask {

    pub fn new(address: IpAddr, mask: u32) -> Result<Self, ()> {
        if let IpAddr::V6(v6) = address {
            let octets = v6.octets();

            return Ok(Self {
                address: octets,
                mask
            })
        }

        Err(())
    }

    pub fn contains(&self, other_address: IpAddr) -> bool {
        let other = match other_address {
            IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };

        if self.address.len() != other.len() {
            return false;
        }

        for i in 0..(self.mask / 8) as usize {
            if self.address[i] != other[i] {
                return false;
            }
        }

        if self.mask % 8 == 0 {
            return true;
        }

        let offset = (self.mask / 8) as usize;
        let probe_mask = ((0xff00 >> (self.mask % 8)) & 0xff) as u8;

        (self.address[offset] & probe_mask) == (other[offset] & probe_mask)
    }
}

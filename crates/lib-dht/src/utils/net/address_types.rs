#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum AddressTypes {
    Ipv4,
    Ipv6
}

pub const IPV4_LENGTH: usize = 4;
pub const IPV6_LENGTH: usize = 16;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use super::net_mask::NetMask;

const LOCAL_BROADCAST: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
const V4_MAPPED: NetMask = NetMask {
    address: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
    mask: 96,
};

pub fn is_bogon(addr: SocketAddr) -> bool {
    !(addr.port() > 0 && is_global_unicast(addr.ip()))
}

pub fn is_teredo(addr: IpAddr) -> bool {
    if let IpAddr::V6(v6) = addr {
        let octets = v6.octets();
        return octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x00 && octets[3] == 0x00;
    }

    false
}

pub fn is_global_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            if v4.octets()[0] == 0 || v4.octets() == LOCAL_BROADCAST {
                return false;
            }
        }
        IpAddr::V6(v6) => {
            if (v6.segments()[0] & 0xfe) == 0xfc || V4_MAPPED.contains(addr)/* || v6.is_ipv4_compatible()*/ {
                // || ((Inet6Address) address).isIPv4CompatibleAddress())
                return false;
            }
        }
    }

    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast() || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified() || v6.is_loopback()/* || v6.is_unicast_link_local()*/ || v6.is_multicast()/* || v6.is_unicast_site_local()*/)
        }
    }
}

pub fn pack_address(addr: &SocketAddr) -> Vec<u8> {
    let mut buf = vec![];
    match addr {
        SocketAddr::V4(v4_addr) => {
            buf.extend_from_slice(&v4_addr.ip().octets());
            buf.extend_from_slice(&v4_addr.port().to_be_bytes());
            buf
        }
        SocketAddr::V6(v6_addr) => {
            buf.extend_from_slice(&v6_addr.ip().octets());
            buf.extend_from_slice(&v6_addr.port().to_be_bytes());
            buf
        }
    }
}

pub fn unpack_address(buf: &[u8]) -> io::Result<SocketAddr> {
    match buf.len() {
        6 => {
            let address = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(SocketAddr::new(address.into(), port))
        }
        18 => {
            let mut addr_bytes = [0u8; 16];
            addr_bytes.copy_from_slice(&buf[..16]);
            let address = Ipv6Addr::from(addr_bytes);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(SocketAddr::new(address.into(), port))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid address size: {}", buf.len())))
    }
}

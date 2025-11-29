use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use crate::utils::uid::{ID_LENGTH, UID};
use super::net::address_types::{AddressTypes, IPV4_LENGTH, IPV6_LENGTH};
use super::node::Node;

pub fn pack_nodes(nodes: Vec<Node>, addr_type: AddressTypes) -> Vec<u8> {
    let addr_length = match addr_type {
        AddressTypes::Ipv4 => IPV4_LENGTH,
        AddressTypes::Ipv6 => IPV6_LENGTH
    };
    let mut buf = vec![0; nodes.len() * (ID_LENGTH + addr_length + 2)];
    let mut position = 0;

    for n in nodes {
        buf[position..position + ID_LENGTH].copy_from_slice(&n.uid.bid);
        position += ID_LENGTH;

        match n.address {
            SocketAddr::V4(ipv4) => {
                buf[position..position + addr_length].copy_from_slice(&ipv4.ip().octets());
            }
            SocketAddr::V6(ipv6) => {
                buf[position..position + addr_length].copy_from_slice(&ipv6.ip().octets());
            }
        }
        position += addr_length;

        buf[position] = (n.address.port() >> 8) as u8;
        buf[position + 1] = n.address.port() as u8;
        position += 2;
    }

    buf
}

pub fn unpack_nodes(buf: &[u8], addr_type: AddressTypes) -> Vec<Node> {
    let mut nodes = Vec::new();

    let addr_length = match addr_type {
        AddressTypes::Ipv4 => IPV4_LENGTH,
        AddressTypes::Ipv6 => IPV6_LENGTH
    };
    let mut position = 0;

    while position < buf.len() {
        if position + ID_LENGTH + addr_length + 2 > buf.len() {
            break;
        }

        let bid: [u8; ID_LENGTH] = buf[position..position + ID_LENGTH].try_into().expect("Slice with incorrect length");
        position += ID_LENGTH;

        let addr_bytes = &buf[position..position + addr_length];
        position += addr_length;

        let port = ((buf[position] as u16) << 8) | (buf[position + 1] as u16);
        position += 2;

        let address = match addr_type {
            AddressTypes::Ipv4 => {
                let octets: [u8; IPV4_LENGTH] = addr_bytes.try_into().expect("Slice with incorrect length");
                IpAddr::V4(Ipv4Addr::from(octets))
            },
            AddressTypes::Ipv6 => {
                let octets: [u8; IPV6_LENGTH] = addr_bytes.try_into().expect("Slice with incorrect length");
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        };

        nodes.push(Node::new(UID::from(bid), SocketAddr::new(address, port)));
    }

    nodes
}

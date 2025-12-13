//! DNS Packet Parsing and Serialization
//!
//! Implements RFC 1035 DNS message format for ZDNS transport.
//! Only supports A record queries (sufficient for gateway IP resolution).

use std::net::Ipv4Addr;
use anyhow::{anyhow, Result};

/// DNS header flags
const QR_RESPONSE: u16 = 0x8000;
const OPCODE_QUERY: u16 = 0x0000;
const AA_AUTHORITATIVE: u16 = 0x0400;
const RD_RECURSION_DESIRED: u16 = 0x0100;
const RA_RECURSION_AVAILABLE: u16 = 0x0080;
const RCODE_NOERROR: u16 = 0x0000;
const RCODE_NOTIMP: u16 = 0x0004;
const RCODE_NXDOMAIN: u16 = 0x0003;

/// DNS record types
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// Maximum DNS packet size for UDP
pub const MAX_UDP_SIZE: usize = 512;

/// Parsed DNS packet
#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// Transaction ID
    pub id: u16,
    /// Is this a response?
    pub is_response: bool,
    /// Query domain name
    pub question: Option<DnsQuestion>,
    /// Answer records
    pub answers: Vec<DnsAnswer>,
    /// Response code (0 = no error, 3 = NXDOMAIN)
    pub rcode: u8,
}

/// DNS question section
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    /// Domain name (e.g., "myapp.zhtp")
    pub name: String,
    /// Query type (1 = A)
    pub qtype: u16,
    /// Query class (1 = IN)
    pub qclass: u16,
}

/// DNS answer section
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    /// Domain name
    pub name: String,
    /// Record type
    pub rtype: u16,
    /// Record class
    pub rclass: u16,
    /// TTL in seconds
    pub ttl: u32,
    /// Record data (4 bytes for A record)
    pub rdata: Vec<u8>,
}

impl DnsPacket {
    /// Parse a DNS packet from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 {
            return Err(anyhow!("DNS packet too short: {} bytes", data.len()));
        }

        // Parse header
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags & QR_RESPONSE) != 0;
        let rcode = (flags & 0x000F) as u8;
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);

        let mut offset = 12;

        // Parse question section
        let question = if qdcount > 0 {
            let (name, new_offset) = Self::parse_name(data, offset)?;
            offset = new_offset;

            if offset + 4 > data.len() {
                return Err(anyhow!("DNS packet truncated in question section"));
            }

            let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;

            Some(DnsQuestion { name, qtype, qclass })
        } else {
            None
        };

        // Parse answer section (for responses)
        let mut answers = Vec::new();
        for _ in 0..ancount {
            if offset >= data.len() {
                break;
            }

            let (name, new_offset) = Self::parse_name(data, offset)?;
            offset = new_offset;

            if offset + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > data.len() {
                break;
            }

            let rdata = data[offset..offset + rdlength].to_vec();
            offset += rdlength;

            answers.push(DnsAnswer {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
        }

        Ok(DnsPacket {
            id,
            is_response,
            question,
            answers,
            rcode,
        })
    }

    /// Parse a domain name from DNS wire format
    fn parse_name(data: &[u8], mut offset: usize) -> Result<(String, usize)> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut jump_offset = 0;

        loop {
            if offset >= data.len() {
                return Err(anyhow!("DNS name parsing: unexpected end of data"));
            }

            let len = data[offset] as usize;

            // Check for compression pointer
            if len & 0xC0 == 0xC0 {
                if offset + 1 >= data.len() {
                    return Err(anyhow!("DNS name parsing: truncated pointer"));
                }
                let ptr = ((len & 0x3F) << 8 | data[offset + 1] as usize) as usize;
                if !jumped {
                    jump_offset = offset + 2;
                }
                offset = ptr;
                jumped = true;
                continue;
            }

            // End of name
            if len == 0 {
                if !jumped {
                    jump_offset = offset + 1;
                }
                break;
            }

            // Read label
            offset += 1;
            if offset + len > data.len() {
                return Err(anyhow!("DNS name parsing: label extends past end"));
            }

            let label = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
            labels.push(label);
            offset += len;
        }

        Ok((labels.join("."), jump_offset))
    }

    /// Create an A record response
    pub fn a_record(query: &DnsPacket, ip: Ipv4Addr, ttl: u32) -> Self {
        let question = query.question.clone();
        let name = question.as_ref().map(|q| q.name.clone()).unwrap_or_default();

        DnsPacket {
            id: query.id,
            is_response: true,
            question,
            answers: vec![DnsAnswer {
                name,
                rtype: TYPE_A,
                rclass: CLASS_IN,
                ttl,
                rdata: ip.octets().to_vec(),
            }],
            rcode: 0,
        }
    }

    /// Create an NXDOMAIN response
    pub fn nxdomain(query: &DnsPacket) -> Self {
        DnsPacket {
            id: query.id,
            is_response: true,
            question: query.question.clone(),
            answers: vec![],
            rcode: 3, // NXDOMAIN
        }
    }

    /// Create a SERVFAIL response
    pub fn servfail(query: &DnsPacket) -> Self {
        DnsPacket {
            id: query.id,
            is_response: true,
            question: query.question.clone(),
            answers: vec![],
            rcode: 2, // SERVFAIL
        }
    }

    /// Create a NOTIMP (Not Implemented) response for unsupported query types
    /// Used when the domain exists but we don't support the requested record type (e.g., AAAA, MX)
    pub fn notimp(query: &DnsPacket) -> Self {
        DnsPacket {
            id: query.id,
            is_response: true,
            question: query.question.clone(),
            answers: vec![],
            rcode: 4, // NOTIMP
        }
    }

    /// Serialize to DNS wire format
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MAX_UDP_SIZE);

        // Header
        buf.extend_from_slice(&self.id.to_be_bytes());

        // Flags
        let mut flags: u16 = 0;
        if self.is_response {
            flags |= QR_RESPONSE;
            flags |= AA_AUTHORITATIVE;
            flags |= RA_RECURSION_AVAILABLE;
        }
        flags |= RD_RECURSION_DESIRED;
        flags |= (self.rcode as u16) & 0x000F;
        buf.extend_from_slice(&flags.to_be_bytes());

        // Counts
        let qdcount: u16 = if self.question.is_some() { 1 } else { 0 };
        let ancount: u16 = self.answers.len() as u16;
        buf.extend_from_slice(&qdcount.to_be_bytes());
        buf.extend_from_slice(&ancount.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question section
        if let Some(ref q) = self.question {
            Self::write_name(&mut buf, &q.name);
            buf.extend_from_slice(&q.qtype.to_be_bytes());
            buf.extend_from_slice(&q.qclass.to_be_bytes());
        }

        // Answer section
        for answer in &self.answers {
            Self::write_name(&mut buf, &answer.name);
            buf.extend_from_slice(&answer.rtype.to_be_bytes());
            buf.extend_from_slice(&answer.rclass.to_be_bytes());
            buf.extend_from_slice(&answer.ttl.to_be_bytes());
            buf.extend_from_slice(&(answer.rdata.len() as u16).to_be_bytes());
            buf.extend_from_slice(&answer.rdata);
        }

        buf
    }

    /// Write a domain name in DNS wire format
    fn write_name(buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // Root label
    }

    /// Get the queried domain name
    pub fn query_name(&self) -> Option<&str> {
        self.question.as_ref().map(|q| q.name.as_str())
    }

    /// Check if this is an A record query
    pub fn is_a_query(&self) -> bool {
        self.question.as_ref().map(|q| q.qtype == TYPE_A).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_query() {
        // Real DNS query for "example.com" A record
        let query_bytes: [u8; 29] = [
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query, recursion desired
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // Root
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        let packet = DnsPacket::parse(&query_bytes).unwrap();
        assert_eq!(packet.id, 0x1234);
        assert!(!packet.is_response);
        assert!(packet.question.is_some());

        let q = packet.question.as_ref().unwrap();
        assert_eq!(q.name, "example.com");
        assert_eq!(q.qtype, 1); // A
        assert_eq!(q.qclass, 1); // IN
    }

    #[test]
    fn test_serialize_a_response() {
        // Create a mock query
        let query = DnsPacket {
            id: 0xABCD,
            is_response: false,
            question: Some(DnsQuestion {
                name: "myapp.zhtp".to_string(),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            }),
            answers: vec![],
            rcode: 0,
        };

        // Create A record response
        let response = DnsPacket::a_record(&query, Ipv4Addr::new(192, 168, 1, 100), 3600);

        // Serialize and parse back
        let bytes = response.serialize();
        let parsed = DnsPacket::parse(&bytes).unwrap();

        assert_eq!(parsed.id, 0xABCD);
        assert!(parsed.is_response);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rdata, vec![192, 168, 1, 100]);
    }

    #[test]
    fn test_nxdomain_response() {
        let query = DnsPacket {
            id: 0x5678,
            is_response: false,
            question: Some(DnsQuestion {
                name: "nonexistent.zhtp".to_string(),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            }),
            answers: vec![],
            rcode: 0,
        };

        let response = DnsPacket::nxdomain(&query);
        assert_eq!(response.rcode, 3);
        assert!(response.answers.is_empty());

        let bytes = response.serialize();
        let parsed = DnsPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.rcode, 3);
    }

    #[test]
    fn test_query_name() {
        let packet = DnsPacket {
            id: 0,
            is_response: false,
            question: Some(DnsQuestion {
                name: "test.zhtp".to_string(),
                qtype: TYPE_A,
                qclass: CLASS_IN,
            }),
            answers: vec![],
            rcode: 0,
        };

        assert_eq!(packet.query_name(), Some("test.zhtp"));
        assert!(packet.is_a_query());
    }
}

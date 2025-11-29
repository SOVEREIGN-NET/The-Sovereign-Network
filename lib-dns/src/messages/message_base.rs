use std::collections::HashMap;
use std::{fmt, io};
use std::fmt::Formatter;
use std::net::SocketAddr;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::records::inter::record_base::RecordBase;
use crate::messages::dns_query::DnsQuery;
use crate::messages::inter::rr_types::RRTypes;
use crate::utils::fqdn_utils::{pack_fqdn, unpack_fqdn};

/*
                               1  1  1  1  1  1
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

pub const DNS_HEADER_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct MessageBase {
    id: u16,
    op_code: OpCodes,
    response_code: ResponseCodes,
    qr: bool,
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authenticated_data: bool,
    checking_disabled: bool,
    origin: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    queries: Vec<DnsQuery>,
    records: [Vec<(String, Box<dyn RecordBase>)>; 3]
}

impl Default for MessageBase {

    fn default() -> Self {
        Self {
            id: 0,
            op_code: OpCodes::Query,
            response_code: ResponseCodes::NoError,
            qr: false,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authenticated_data: false,
            checking_disabled: false,
            origin: None,
            destination: None,
            queries: Vec::new(),
            records: Default::default()
        }
    }
}

impl MessageBase {

    pub fn new(id: u16) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        let id = u16::from_be_bytes([buf[0], buf[1]]);

        let flags = u16::from_be_bytes([buf[2], buf[3]]);

        let qr = (flags & 0x8000) != 0;
        let op_code = OpCodes::from_code(((flags >> 11) & 0x0F) as u8).ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        //let z = (flags & 0x0040) != 0;
        let authenticated_data = (flags & 0x0020) != 0;
        let checking_disabled = (flags & 0x0010) != 0;
        let response_code = ResponseCodes::from_code((flags & 0x000F) as u8).ok_or(io::Error::from(io::ErrorKind::InvalidData))?;

        let qd_count = u16::from_be_bytes([buf[4], buf[5]]);

        let mut queries = Vec::new();
        let mut off = DNS_HEADER_LEN;

        for _ in 0..qd_count {
            queries.push(DnsQuery::from_bytes(buf, &mut off));
        }

        let records = [
            records_from_bytes(buf, &mut off, u16::from_be_bytes([buf[6], buf[7]])),
            records_from_bytes(buf, &mut off, u16::from_be_bytes([buf[8], buf[9]])),
            records_from_bytes(buf, &mut off, u16::from_be_bytes([buf[10], buf[11]]))
        ];

        Ok(Self {
            id,
            op_code,
            response_code,
            qr,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authenticated_data,
            checking_disabled,
            origin: None,
            destination: None,
            queries,
            records
        })
    }

    //TRUNCATE WILL BE HANDLED BY ITERATOR...
    pub fn to_bytes(&self, max_payload_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; DNS_HEADER_LEN];

        buf.splice(0..2, self.id.to_be_bytes());

        buf.splice(4..6, (self.queries.len() as u16).to_be_bytes());

        let mut label_map = HashMap::new();
        let mut off = DNS_HEADER_LEN;
        let mut truncated = false;

        for query in &self.queries {
            let q = query.to_bytes(&mut label_map, off);
            if off+q.len() > max_payload_len {
                truncated = true;
                break;
            }

            buf.extend_from_slice(&q);
            off += q.len();
        }

        if !truncated {
            for (i, records) in self.records.iter().enumerate() {
                let (records, count, t) = records_to_bytes(off, &records, &mut label_map, max_payload_len);
                buf.extend_from_slice(&records);
                buf.splice(i*2+6..i*2+8, count.to_be_bytes());

                if t {
                    truncated = t;
                    break;
                }
            }
        }

        let flags = (if self.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.op_code as u16 & 0x0F) << 11) |  // Opcode
            (if self.authoritative { 0x0400 } else { 0 }) |  // AA bit
            (if truncated { 0x0200 } else { 0 }) |  // TC bit
            (if self.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.response_code as u16 & 0x000F);  // RCODE

        buf.splice(2..4, flags.to_be_bytes());

        buf
    }

    pub fn wire_chunks(&self, max_payload_len: usize) -> WireIter {
        WireIter {
            message: self,
            position: 0,
            max_payload_len
        }
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn set_qr(&mut self, qr: bool) {
        self.qr = qr;
    }

    pub fn is_qr(&self) -> bool {
        self.qr
    }

    pub fn set_op_code(&mut self, op_code: OpCodes) {
        self.op_code = op_code;
    }

    pub fn get_op_code(&self) -> OpCodes {
        self.op_code.clone()
    }

    pub fn set_origin(&mut self, origin: SocketAddr) {
        self.origin = Some(origin);
    }

    pub fn get_origin(&self) -> Option<SocketAddr> {
        self.origin
    }

    pub fn set_destination(&mut self, destination: SocketAddr) {
        self.destination = Some(destination);
    }

    pub fn get_destination(&self) -> Option<SocketAddr> {
        self.destination
    }

    pub fn set_authoritative(&mut self, authoritative: bool) {
        self.authoritative = authoritative;
    }

    pub fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    pub fn set_truncated(&mut self, truncated: bool) {
        self.truncated = truncated;
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn set_recursion_desired(&mut self, recursion_desired: bool) {
        self.recursion_desired = recursion_desired;
    }

    pub fn is_recursion_desired(&self) -> bool {
        self.recursion_desired
    }

    pub fn set_recursion_available(&mut self, recursion_available: bool) {
        self.recursion_available = recursion_available;
    }

    pub fn is_recursion_available(&self) -> bool {
        self.recursion_available
    }

    pub fn set_response_code(&mut self, response_code: ResponseCodes) {
        self.response_code = response_code;
    }

    pub fn get_response_code(&self) -> ResponseCodes {
        self.response_code
    }

    pub fn has_queries(&self) -> bool {
        !self.queries.is_empty()
    }

    pub fn add_query(&mut self, query: DnsQuery) {
        self.queries.push(query);
    }

    pub fn get_queries(&self) -> &Vec<DnsQuery> {
        self.queries.as_ref()
    }

    pub fn get_queries_mut(&mut self) -> &mut Vec<DnsQuery> {
        self.queries.as_mut()
    }

    pub fn has_answers(&self) -> bool {
        !self.records[0].is_empty()
    }

    pub fn add_answer(&mut self, query: &str, record: Box<dyn RecordBase>) {
        self.records[0].push((query.to_string(), record));
    }

    pub fn get_answers(&self) -> &Vec<(String, Box<dyn RecordBase>)> {
        self.records[0].as_ref()
    }

    pub fn get_answers_mut(&mut self) -> &mut Vec<(String, Box<dyn RecordBase>)>  {
        self.records[0].as_mut()
    }

    pub fn total_answers(&self) -> usize {
        self.records[0].len()
    }

    pub fn has_authority_records(&self) -> bool {
        !self.records[1].is_empty()
    }

    pub fn add_authority_record(&mut self, query: &str, record: Box<dyn RecordBase>) {
        self.records[1].push((query.to_string(), record));
    }

    pub fn get_authority_records(&self) -> &Vec<(String, Box<dyn RecordBase>)> {
        self.records[1].as_ref()
    }

    pub fn get_authority_records_mut(&mut self) -> &mut Vec<(String, Box<dyn RecordBase>)>  {
        self.records[1].as_mut()
    }

    pub fn total_authority_records(&self) -> usize {
        self.records[1].len()
    }

    pub fn has_additional_records(&self) -> bool {
        !self.records[2].is_empty()
    }

    pub fn add_additional_record(&mut self, query: &str, record: Box<dyn RecordBase>) {
        self.records[2].push((query.to_string(), record));
    }

    pub fn get_additional_records(&self) -> &Vec<(String, Box<dyn RecordBase>)> {
        self.records[2].as_ref()
    }

    pub fn get_additional_records_mut(&mut self) -> &mut Vec<(String, Box<dyn RecordBase>)>  {
        self.records[2].as_mut()
    }

    pub fn total_additional_records(&self) -> usize {
        self.records[2].len()
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl fmt::Display for MessageBase {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, ";; ->>HEADER<<- opcode: {}, status: {}, id: {}", self.op_code, self.response_code, self.id)?;

        let mut flags = Vec::new();

        if self.qr { flags.push("qr"); }
        if self.authoritative { flags.push("aa"); }
        if self.truncated { flags.push("tc"); }
        if self.recursion_desired { flags.push("rd"); }
        if self.recursion_available { flags.push("ra"); }
        if self.authenticated_data { flags.push("ad"); }
        if self.checking_disabled { flags.push("cd"); }

        writeln!(f, ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
                flags.join(" "),
                self.queries.len(),
                self.records[0].len(),
                self.records[1].len(),
                self.records[2].len())?;

        /*
        if let Some(r) = self.additional_records.get(&String::new()) {
            for r in r {
                if r.get_type().eq(&RRTypes::Opt) {
                    writeln!(f, "\r\n;; OPT PSEUDOSECTION:")?;
                    writeln!(f, "{}", self.additional_records.get(&String::new()).unwrap().get(0).unwrap())?;
                }
            }
        }
        */

        writeln!(f, "\r\n;; QUESTION SECTION:")?;
        for q in &self.queries {
            writeln!(f, ";{}", q)?;
        }

        if !self.records[0].is_empty() {
            writeln!(f, "\r\n;; ANSWER SECTION:")?;
            for (q, r) in self.records[0].iter() {
                writeln!(f, "{:<24}{}", format!("{}.", q), r)?;
            }
        }

        if !self.records[1].is_empty() {
            writeln!(f, "\r\n;; AUTHORITATIVE SECTION:")?;
            for (q, r) in self.records[1].iter() {
                writeln!(f, "{:<24}{}", format!("{}.", q), r)?;
            }
        }

        if !self.records[2].is_empty() {
            writeln!(f, "\r\n;; ADDITIONAL SECTION:")?;
            for (q, r) in self.records[2].iter() {
                if !q.eq("") && !r.get_type().eq(&RRTypes::Opt) {
                    writeln!(f, "{:<24}{}", format!("{}.", q), r)?;
                }
            }
        }

        Ok(())
    }
}

pub struct WireIter<'a> {
    message: &'a MessageBase,
    position: usize,
    max_payload_len: usize
}

impl<'a> Iterator for WireIter<'a> {

    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.message.records.iter().map(|r| r.len()).sum() {
            return None;
        }

        let mut buf = vec![0u8; DNS_HEADER_LEN];

        buf.splice(0..2, self.message.id.to_be_bytes());

        let flags = (if self.message.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.message.op_code as u16 & 0x0F) << 11) |  // Opcode
            (if self.message.authoritative { 0x0400 } else { 0 }) |  // AA bit
            0 |  // TC bit
            (if self.message.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.message.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.message.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.message.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.message.response_code as u16 & 0x000F);  // RCODE

        buf.splice(2..4, flags.to_be_bytes());

        buf.splice(4..6, (self.message.queries.len() as u16).to_be_bytes());

        let mut label_map = HashMap::new();
        let mut off = DNS_HEADER_LEN;
        let mut truncated = false;

        for query in &self.message.queries {
            let q = query.to_bytes(&mut label_map, off);
            if off+q.len() > self.max_payload_len {
                truncated = true;
                break;
            }

            buf.extend_from_slice(&q);
            off += q.len();
        }

        if !truncated {
            let mut total = 0;
            for (i, records) in self.message.records.iter().enumerate() {
                let before = total;
                total += self.message.records[i].len();

                if self.position < total {
                    let (records, count, t) = records_to_bytes(off, &records[self.position - before..], &mut label_map, self.max_payload_len);
                    buf.extend_from_slice(&records);
                    buf.splice(i*2+6..i*2+8, count.to_be_bytes());
                    self.position += count as usize;

                    if t {
                        break;
                    }
                }
            }
        }

        Some(buf)
    }
}

fn records_from_bytes(buf: &[u8], off: &mut usize, count: u16) -> Vec<(String, Box<dyn RecordBase>)> {
    let mut records: Vec<(String, Box<dyn RecordBase>)> = Vec::new();

    for _ in 0..count {
        let (name, length) = unpack_fqdn(buf, *off);
        *off += length;

        let record = <dyn RecordBase>::from_wire(RRTypes::from_code(u16::from_be_bytes([buf[*off], buf[*off+1]])).unwrap(), buf, *off+2).unwrap();

        records.push((name, record));
        *off += 10+u16::from_be_bytes([buf[*off+8], buf[*off+9]]) as usize;
    }

    records
}

fn records_to_bytes(off: usize, records: &[(String, Box<dyn RecordBase>)], label_map: &mut HashMap<String, usize>, max_payload_len: usize) -> (Vec<u8>, u16, bool) {
    let mut truncated = false;

    let mut buf = Vec::new();
    let mut i = 0;
    let mut off = off;

    for (name, record) in records.iter() {
        let n = pack_fqdn(name, label_map, off, true);
        off += n.len()+2;

        match record.to_bytes(label_map, off) {
            Ok(r) => {
                if off+r.len() > max_payload_len {
                    truncated = true;
                    break;
                }

                buf.extend_from_slice(&n);
                buf.extend_from_slice(&record.get_type().get_code().to_be_bytes());
                buf.extend_from_slice(&r);
                off += r.len();
                i += 1;
            }
            Err(_) => continue
        }
    }

    (buf, i, truncated)
}

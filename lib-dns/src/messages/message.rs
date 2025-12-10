use std::fmt;
use std::fmt::Formatter;
use std::net::SocketAddr;
use crate::keyring::key::Key;
use crate::messages::inter::op_codes::OpCodes;
use crate::messages::inter::response_codes::ResponseCodes;
use crate::messages::inter::rr_classes::RRClasses;
use crate::rr_data::inter::rr_data::RRData;
use crate::messages::rr_query::RRQuery;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::edns::Edns;
use crate::messages::record::Record;
use crate::messages::tsig::TSig;
use crate::messages::wire::{FromWire, FromWireContext, FromWireLen, ToWire, ToWireContext, WireError};
use crate::rr_data::tsig_rr_data::TSigRRData;
use crate::utils::fqdn_utils::pack_fqdn;
use crate::utils::hash::hmac::hmac;
use crate::utils::hash::sha256::Sha256;
/*
                               1  1  1  1  1  1
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
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

#[derive(Debug, Clone)]
pub struct Message {
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
    queries: Vec<RRQuery>,
    sections: [Vec<Record>; 3],
    edns: Option<Edns>,
    tsig: Option<TSig>
}

impl Default for Message {

    fn default() -> Self {
        Self {
            id: 0,
            op_code: Default::default(),
            response_code: Default::default(),
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
            sections: Default::default(),
            edns: None,
            tsig: None
        }
    }
}

impl Message {

    pub fn new(id: u16) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn from_bytes<B: AsRef<[u8]>>(buf: B) -> Result<Self, WireError> {
        let mut context = FromWireContext::new(buf.as_ref());

        let id = u16::from_wire(&mut context)?;

        let flags = u16::from_wire(&mut context)?;

        let qr = (flags & 0x8000) != 0;
        let op_code = OpCodes::try_from(((flags >> 11) & 0x0F) as u8).map_err(|e| WireError::Format(e.to_string()))?;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        //let z = (flags & 0x0040) != 0;
        let authenticated_data = (flags & 0x0020) != 0;
        let checking_disabled = (flags & 0x0010) != 0;
        let response_code = ResponseCodes::try_from((flags & 0x000F) as u8).map_err(|e| WireError::Format(e.to_string()))?;

        let qd_count = u16::from_wire(&mut context)?;
        let an_count = u16::from_wire(&mut context)?;
        let ns_count = u16::from_wire(&mut context)?;
        let ar_count = u16::from_wire(&mut context)?;

        let mut queries = Vec::new();

        for _ in 0..qd_count {
            queries.push(RRQuery::from_wire(&mut context)?);
        }

        let mut sections: [Vec<Record>; 3] = Default::default();

        for _ in 0..an_count {
            sections[0].push(Record::from_wire(&mut context)?);
        }

        for _ in 0..ns_count {
            sections[1].push(Record::from_wire(&mut context)?);
        }

        let mut edns = None;
        let mut tsig = None;
        for _ in 0..ar_count {
            let fqdn = context.name()?;
            let checkpoint = context.pos();

            let rtype = RRTypes::try_from(u16::from_wire(&mut context)?).map_err(|e| WireError::Format(e.to_string()))?;

            match rtype {
                RRTypes::Opt => edns = Some(Edns::from_wire(&mut context)?),
                RRTypes::TSig => {
                    let class = u16::from_wire(&mut context)?;
                    let cache_flush = (class & 0x8000) != 0;
                    let class = RRClasses::try_from(class).map_err(|e| WireError::Format(e.to_string()))?;
                    let ttl = u32::from_wire(&mut context)?;

                    let len = u16::from_wire(&mut context)?;
                    match len {
                        0 => {}
                        _ => {
                            match TSigRRData::from_wire_len(&mut context, len) {
                                Ok(mut data) => {
                                    let mut signed_payload = context.range(0..checkpoint)?.to_vec();
                                    signed_payload[10..12].copy_from_slice(&(ar_count - 1).to_be_bytes());

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

                                    let mut ts = TSig::new(&fqdn, data);
                                    ts.set_signed_payload(&signed_payload);

                                    tsig = Some(ts);
                                }
                                Err(_) => {}
                            }
                        }
                    };
                }
                _ => {
                    let class = u16::from_wire(&mut context)?;
                    let _cache_flush = (class & 0x8000) != 0;
                    let class = RRClasses::try_from(class).map_err(|e| WireError::Format(e.to_string()))?;
                    let ttl = u32::from_wire(&mut context)?;

                    let len = u16::from_wire(&mut context)?;
                    let data = match len {
                        0 => None,
                        _ => Some(<dyn RRData>::from_wire(&mut context, len, &rtype, &class)?)
                    };

                    sections[2].push(Record::new(&fqdn, class, rtype, ttl, data));
                }
            }
        }

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
            sections,
            edns,
            tsig
        })
    }

    pub fn to_bytes(&self, max_payload_len: usize) -> Vec<u8> {
        let max_payload_len = match self.edns.as_ref() {
            Some(edns) => edns.payload_size() as usize,
            None => max_payload_len
        };

        let mut context = ToWireContext::with_capacity(max_payload_len);

        self.id.to_wire(&mut context).unwrap();

        context.skip(10).unwrap();

        let mut truncated = false;

        let mut count: u16 = 0;
        for query in &self.queries {
            let checkpoint = context.pos();
            if let Err(_) = query.to_wire(&mut context) {
                truncated = true;
                context.rollback(checkpoint);
                break;
            }
            count += 1;
        }
        context.patch(4..6, &count.to_be_bytes()).unwrap();

        for i in 0..2 {
            if !truncated {
                count = 0;
                for record in self.sections[i].iter() {
                    let checkpoint = context.pos();
                    if let Err(_) = record.to_wire(&mut context) {
                        truncated = true;
                        context.rollback(checkpoint);
                        break;
                    }
                    count += 1;
                }
                context.patch(i*2+6..i*2+8, &count.to_be_bytes()).unwrap();
            }
        }

        'ar: {
            if !truncated {
                count = 0;
                if let Some(edns) = self.edns.as_ref() {
                    let checkpoint = context.pos();
                    if let Err(_) = {
                        0u8.to_wire(&mut context).unwrap();
                        RRTypes::Opt.code().to_wire(&mut context).unwrap();
                        edns.to_wire(&mut context)
                    } {
                        truncated = true;
                        context.rollback(checkpoint);
                        break 'ar;
                    }
                    count += 1;
                }

                for record in self.sections[2].iter() {
                    let checkpoint = context.pos();
                    if let Err(_) = record.to_wire(&mut context) {
                        truncated = true;
                        context.rollback(checkpoint);
                        break;
                    }
                    count += 1;
                }
                context.patch(10..12, &count.to_be_bytes()).unwrap();
            }
        }

        let flags = (if self.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.op_code.code() as u16 & 0x0F) << 11) |  // Opcode
            (if self.authoritative { 0x0400 } else { 0 }) |  // AA bit
            (if truncated { 0x0200 } else { 0 }) |  // TC bit
            (if self.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.response_code.code() as u16 & 0x000F);  // RCODE
        context.patch(2..4, &flags.to_be_bytes()).unwrap();

        context.into_bytes()
    }

    pub fn to_bytes_with_sig(&mut self, max_payload_len: usize, key: &Key) -> Vec<u8> {
        let max_payload_len = match self.edns.as_ref() {
            Some(edns) => edns.payload_size() as usize,
            None => max_payload_len
        };

        let mut context = ToWireContext::with_capacity(max_payload_len);

        self.id.to_wire(&mut context).unwrap();

        context.skip(10).unwrap();

        let mut truncated = false;

        let mut count: u16 = 0;
        for query in &self.queries {
            let checkpoint = context.pos();
            if let Err(_) = query.to_wire(&mut context) {
                truncated = true;
                context.rollback(checkpoint);
                break;
            }
            count += 1;
        }
        context.patch(4..6, &count.to_be_bytes()).unwrap();

        for i in 0..2 {
            if !truncated {
                count = 0;
                for record in self.sections[i].iter() {
                    let checkpoint = context.pos();
                    if let Err(_) = record.to_wire(&mut context) {
                        truncated = true;
                        context.rollback(checkpoint);
                        break;
                    }
                    count += 1;
                }
                context.patch(i*2+6..i*2+8, &count.to_be_bytes()).unwrap();
            }
        }

        'ar: {
            if !truncated {
                count = 0;
                if let Some(edns) = self.edns.as_ref() {
                    let checkpoint = context.pos();
                    if let Err(_) = {
                        0u8.to_wire(&mut context).unwrap();
                        RRTypes::Opt.code().to_wire(&mut context).unwrap();
                        edns.to_wire(&mut context)
                    } {
                        truncated = true;
                        context.rollback(checkpoint);
                        break 'ar;
                    }
                    count += 1;
                }

                for record in self.sections[2].iter() {
                    let checkpoint = context.pos();
                    if let Err(_) = record.to_wire(&mut context) {
                        truncated = true;
                        context.rollback(checkpoint);
                        break;
                    }
                    count += 1;
                }

                context.patch(10..12, &count.to_be_bytes()).unwrap();
            }
        }

        let flags = (if self.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.op_code.code() as u16 & 0x0F) << 11) |  // Opcode
            (if self.authoritative { 0x0400 } else { 0 }) |  // AA bit
            (if truncated { 0x0200 } else { 0 }) |  // TC bit
            (if self.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.response_code.code() as u16 & 0x000F);  // RCODE
        context.patch(2..4, &flags.to_be_bytes()).unwrap();

        if !truncated {
            if let Some(tsig) = self.tsig.as_mut() {
                let checkpoint = context.pos();

                let mut signed_payload = context.to_bytes();
                signed_payload.extend_from_slice(&pack_fqdn(tsig.owner()));

                signed_payload.extend_from_slice(&RRClasses::Any.code().to_be_bytes());
                signed_payload.extend_from_slice(&0u32.to_be_bytes());

                signed_payload.extend_from_slice(&pack_fqdn(&tsig.data().algorithm().as_ref().unwrap().to_string())); //PROBABLY NO COMPRESS

                signed_payload.extend_from_slice(&[
                    ((tsig.data().time_signed() >> 40) & 0xFF) as u8,
                    ((tsig.data().time_signed() >> 32) & 0xFF) as u8,
                    ((tsig.data().time_signed() >> 24) & 0xFF) as u8,
                    ((tsig.data().time_signed() >> 16) & 0xFF) as u8,
                    ((tsig.data().time_signed() >>  8) & 0xFF) as u8,
                    ( tsig.data().time_signed()        & 0xFF) as u8
                ]);
                signed_payload.extend_from_slice(&tsig.data().fudge().to_be_bytes());

                signed_payload.extend_from_slice(&tsig.data().error().to_be_bytes());

                signed_payload.extend_from_slice(&(tsig.data().data().len() as u16).to_be_bytes());
                signed_payload.extend_from_slice(&tsig.data().data());

                tsig.add_to_signed_payload(&signed_payload);
                tsig.sign(key);


                if let Err(_) = tsig.to_wire(&mut context) {
                    truncated = true;
                    context.rollback(checkpoint);
                }
                count += 1;

                context.patch(10..12, &count.to_be_bytes()).unwrap();
            }
        }

        context.into_bytes()
    }

    pub fn wire_chunks(&mut self, max_payload_len: usize) -> WireIter {
        let max_payload_len = match self.edns.as_ref() {
            Some(edns) => edns.payload_size() as usize,
            None => max_payload_len
        };

        let mut context = ToWireContext::with_capacity(max_payload_len);

        self.id.to_wire(&mut context).unwrap();
        let flags = (if self.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.op_code.code() as u16 & 0x0F) << 11) |  // Opcode
            (if self.authoritative { 0x0400 } else { 0 }) |  // AA bit
            //(if truncated { 0x0200 } else { 0 }) |  // TC bit
            (if self.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.response_code.code() as u16 & 0x000F);
        flags.to_wire(&mut context).unwrap();  // RCODE

        let mut total = self.sections.iter().map(|r| r.len()).sum();
        if self.edns.is_some() {
            total += 1;
        }
        if self.tsig.is_some() {
            total += 1;
        }

        WireIter {
            message: self,
            position: 0,
            total,
            context,
            key: None,
            msg_index: 0
        }
    }

    pub fn wire_chunks_with_tsig(&mut self, max_payload_len: usize, key: &Key) -> WireIter {
        let max_payload_len = match self.edns.as_ref() {
            Some(edns) => edns.payload_size() as usize,
            None => max_payload_len
        };

        let mut context = ToWireContext::with_capacity(max_payload_len);

        self.id.to_wire(&mut context).unwrap();
        let flags = (if self.qr { 0x8000 } else { 0 }) |  // QR bit
            ((self.op_code.code() as u16 & 0x0F) << 11) |  // Opcode
            (if self.authoritative { 0x0400 } else { 0 }) |  // AA bit
            //(if truncated { 0x0200 } else { 0 }) |  // TC bit
            (if self.recursion_desired { 0x0100 } else { 0 }) |  // RD bit
            (if self.recursion_available { 0x0080 } else { 0 }) |  // RA bit
            //(if self.z { 0x0040 } else { 0 }) |  // Z bit (always 0)
            (if self.authenticated_data { 0x0020 } else { 0 }) |  // AD bit
            (if self.checking_disabled { 0x0010 } else { 0 }) |  // CD bit
            (self.response_code.code() as u16 & 0x000F);
        flags.to_wire(&mut context).unwrap();  // RCODE

        let mut total = self.sections.iter().map(|r| r.len()).sum();
        if self.edns.is_some() {
            total += 1;
        }
        if self.tsig.is_some() {
            total += 1;
        }

        WireIter {
            message: self,
            position: 0,
            total,
            context,
            key: Some(key.clone()),
            msg_index: 0
        }
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
    }

    pub fn id(&self) -> u16 {
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

    pub fn op_code(&self) -> OpCodes {
        self.op_code.clone()
    }

    pub fn set_origin(&mut self, origin: SocketAddr) {
        self.origin = Some(origin);
    }

    pub fn origin(&self) -> Option<SocketAddr> {
        self.origin
    }

    pub fn set_destination(&mut self, destination: SocketAddr) {
        self.destination = Some(destination);
    }

    pub fn destination(&self) -> Option<SocketAddr> {
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

    pub fn response_code(&self) -> ResponseCodes {
        self.response_code
    }

    pub fn has_queries(&self) -> bool {
        !self.queries.is_empty()
    }

    pub fn add_query(&mut self, query: RRQuery) {
        self.queries.push(query);
    }

    pub fn queries(&self) -> &Vec<RRQuery> {
        self.queries.as_ref()
    }

    pub fn queries_mut(&mut self) -> &mut Vec<RRQuery> {
        self.queries.as_mut()
    }

    pub fn has_section(&self, index: usize) -> bool {
        !self.sections[index].is_empty()
    }

    pub fn set_section(&mut self, index: usize, section: Vec<Record>) {
        self.sections[index] = section;
    }

    pub fn add_section(&mut self, index: usize, query: &str, class: RRClasses, rtype: RRTypes, ttl: u32, data: Option<Box<dyn RRData>>) {
        self.sections[index].push(Record::new(query, class, rtype, ttl, data));
    }

    pub fn section(&self, index: usize) -> &Vec<Record> {
        self.sections[index].as_ref()
    }

    pub fn section_mut(&mut self, index: usize) -> &mut Vec<Record> {
        self.sections[index].as_mut()
    }

    pub fn total_section(&self, index: usize) -> usize {
        self.sections[index].len()
    }

    pub fn set_sections(&mut self, section: [Vec<Record>; 3]) {
        self.sections = section;
    }

    pub fn sections(&self) -> &[Vec<Record>; 3] {
        &self.sections
    }

    pub fn sections_mut(&mut self) -> &mut [Vec<Record>; 3] {
        &mut self.sections
    }

    pub fn set_edns(&mut self, edns: Edns) {
        self.edns = Some(edns);
    }

    pub fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    pub fn set_tsig(&mut self, tsig: TSig) {
        self.tsig = Some(tsig);
    }

    pub fn tsig(&self) -> Option<&TSig> {
        self.tsig.as_ref()
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl fmt::Display for Message {

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
                self.sections[0].len(),
                self.sections[1].len(),
                self.sections[2].len())?;

        /*
        if let Some(r) = self.additional_records.get(&String::new()) {
            for r in r {
                if r.type().eq(&RRTypes::Opt) {
                    writeln!(f, "\r\n;; OPT PSEUDOSECTION:")?;
                    writeln!(f, "{}", self.additional_records.get(&String::new()).unwrap().get(0).unwrap())?;
                }
            }
        }
        */

        if self.edns.is_some() {
            writeln!(f, "\r\n;; OPT PSEUDOSECTION:")?;

            writeln!(f, "; {}", self.edns.as_ref().unwrap())?;
        }

        if !self.queries.is_empty() {
            writeln!(f, "\r\n;; QUESTION SECTION:")?;

            for q in self.queries.iter() {
                writeln!(f, ";{}", q)?;
            }
        }

        if !self.sections[0].is_empty() {
            writeln!(f, "\r\n;; ANSWER SECTION:")?;

            for record in self.sections[0].iter() {
                writeln!(f, "{}", record)?;
            }
        }

        if !self.sections[1].is_empty() {
            writeln!(f, "\r\n;; AUTHORITATIVE SECTION:")?;

            for record in self.sections[1].iter() {
                writeln!(f, "{}", record)?;
            }
        }

        if !self.sections[2].is_empty() {
            writeln!(f, "\r\n;; ADDITIONAL SECTION:")?;

            for record in self.sections[2].iter() {
                writeln!(f, "{}", record)?;
            }
        }

        Ok(())
    }
}

pub struct WireIter<'a> {
    message: &'a mut Message,
    position: usize,
    total: usize,
    context: ToWireContext,
    key: Option<Key>,
    msg_index: usize
}

impl<'a> Iterator for WireIter<'a> {

    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.total {
            return None;
        }

        self.context.rollback(4);
        self.context.write(&[0; 8]).unwrap();

        let mut truncated = false;

        let mut count: u16 = 0;
        for query in &self.message.queries {
            let checkpoint = self.context.pos();
            if let Err(_) = query.to_wire(&mut self.context) {
                truncated = true;
                self.context.rollback(checkpoint);
                self.context.patch(4..6, &count.to_be_bytes()).unwrap();
                break;
            }
            count += 1;
        }
        self.context.patch(4..6, &count.to_be_bytes()).unwrap();

        'sections: {
            if !truncated {
                let mut total = 0;
                for i in 0..2 {
                    let before = total;
                    total += self.message.sections[i].len();

                    if self.position < total {
                        count = 0;
                        for record in &self.message.sections[i][self.position - before..] {
                            let checkpoint = self.context.pos();
                            if let Err(_) = record.to_wire(&mut self.context) {
                                self.context.rollback(checkpoint);
                                self.context.patch(i*2+6..i*2+8, &count.to_be_bytes()).unwrap();
                                self.position += count as usize;
                                break 'sections;
                            }
                            count += 1;
                        }
                        self.context.patch(i*2+6..i*2+8, &count.to_be_bytes()).unwrap();
                        self.position += count as usize;
                    }
                }

                let before = total;
                total += self.total-before;

                if self.position < total {
                    count = 0;
                    let start = self.position - before;

                    if let Some(edns) = self.message.edns.as_ref() {
                        let checkpoint = self.context.pos();
                        if let Err(_) = {
                            0u8.to_wire(&mut self.context).unwrap();
                            RRTypes::Opt.code().to_wire(&mut self.context).unwrap();
                            edns.to_wire(&mut self.context)
                        } {
                            self.context.rollback(checkpoint);
                            self.context.patch(10..12, &count.to_be_bytes()).unwrap();
                            self.position += count as usize;
                            break 'sections;
                        }
                        count += 1;
                    }

                    for record in &self.message.sections[2][start..] {
                        let checkpoint = self.context.pos();
                        if let Err(_) = record.to_wire(&mut self.context) {
                            self.context.rollback(checkpoint);
                            self.context.patch(10..12, &count.to_be_bytes()).unwrap();
                            self.position += count as usize;
                            break 'sections;
                        }
                        count += 1;
                    }

                    self.context.patch(10..12, &count.to_be_bytes()).unwrap();

                    if let Some(tsig) = self.message.tsig.as_mut() {
                        let checkpoint = self.context.pos();

                        let mut signed_payload = self.context.to_bytes();
                        signed_payload.extend_from_slice(&pack_fqdn(tsig.owner()));

                        signed_payload.extend_from_slice(&RRClasses::Any.code().to_be_bytes());
                        signed_payload.extend_from_slice(&0u32.to_be_bytes());

                        signed_payload.extend_from_slice(&pack_fqdn(&tsig.data().algorithm().as_ref().unwrap().to_string()));

                        signed_payload.extend_from_slice(&[
                            ((tsig.data().time_signed() >> 40) & 0xFF) as u8,
                            ((tsig.data().time_signed() >> 32) & 0xFF) as u8,
                            ((tsig.data().time_signed() >> 24) & 0xFF) as u8,
                            ((tsig.data().time_signed() >> 16) & 0xFF) as u8,
                            ((tsig.data().time_signed() >>  8) & 0xFF) as u8,
                            ( tsig.data().time_signed()        & 0xFF) as u8
                        ]);
                        signed_payload.extend_from_slice(&tsig.data().fudge().to_be_bytes());

                        signed_payload.extend_from_slice(&tsig.data().error().to_be_bytes());

                        signed_payload.extend_from_slice(&(tsig.data().data().len() as u16).to_be_bytes());
                        signed_payload.extend_from_slice(&tsig.data().data());

                        tsig.add_to_signed_payload(&signed_payload);
                        tsig.sign(self.key.as_ref().unwrap());


                        if let Err(_) = tsig.to_wire(&mut self.context) {
                            truncated = true;
                            self.context.rollback(checkpoint);
                        }
                        count += 1;

                        self.context.patch(10..12, &count.to_be_bytes()).unwrap();
                    }

                    self.position += count as usize;
                }
            }
        }

        Some(self.context.to_bytes())
    }
}

use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read};
use std::ops::DerefMut;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::records::{
    a_record::ARecord,
    aaaa_record::AaaaRecord,
    cname_record::CNameRecord,
    dnskey_record::DnsKeyRecord,
    hinfo_record::HInfoRecord,
    https_record::HttpsRecord,
    loc_record::LocRecord,
    mx_record::MxRecord,
    naptr_record::NaptrRecord,
    ns_record::NsRecord,
    nsec_record::NSecRecord,
    ptr_record::PtrRecord,
    rrsig_record::RRSigRecord,
    smimea_record::SmimeaRecord,
    soa_record::SoaRecord,
    srv_record::SrvRecord,
    sshfp_record::SshFpRecord,
    svcb_record::SvcbRecord,
    txt_record::TxtRecord,
    uri_record::UriRecord,
};
use crate::records::inter::naptr_flags::NaptrFlags;
use crate::records::inter::svc_param_keys::SvcParamKeys;
use crate::records::inter::record_base::RecordBase;
use crate::utils::{base64, hex};
use crate::utils::time_utils::TimeUtils;

#[derive(Debug, PartialEq, Eq)]
enum ParserState {
    Init,
    Common,
    Directive,
    Data,
    QString
}

pub struct ZoneReader {
    reader: BufReader<File>,
    origin: String,
    name: String,
    default_ttl: u32
}

impl ZoneReader {

    pub fn open(file_path: &str, origin: &str) -> io::Result<Self> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        Ok(Self {
            reader,
            origin: origin.to_string(),
            name: String::new(),
            default_ttl: 300
        })
    }

    pub fn parse_record(&mut self) -> Option<(String, Box<dyn RecordBase>)> {
        let mut state = ParserState::Init;
        let mut paren_count = 0;

        let mut _type = RRTypes::default();
        let mut class = RRClasses::default();
        let mut ttl = self.default_ttl;

        let mut directive_buf = String::new();

        let mut record: Option<(String, Box<dyn RecordBase>)> = None;
        let mut data_count = 0;

        loop {
            let Some(line) = self.reader.by_ref().lines().next() else { break };

            let mut pos = 0;
            let mut quoted_buf = String::new();

            for part in line.ok().unwrap().as_bytes().split_inclusive(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'(' || b == b')') {
                let part_len = part.len();
                let mut word_len = part_len;

                if part[0] == b';' && state != ParserState::QString {
                    break;
                }

                match part[part_len - 1] {
                    b' ' | b'\t' | b'\n' => {
                        word_len -= 1;
                    }
                    b'(' => {
                        paren_count += 1;
                        word_len -= 1;
                    }
                    b')' => {
                        paren_count -= 1;
                        word_len -= 1;
                    }
                    _ => {}
                }

                if word_len == 0 && (part[0] == b'\n' || state != ParserState::Init) {
                    continue;
                }

                match state {
                    ParserState::Init => {
                        let word = String::from_utf8(part[0..word_len].to_vec()).unwrap().to_lowercase();

                        if pos == 0 && paren_count == 0 {
                            if word.starts_with('$') {
                                directive_buf = word;
                                state = ParserState::Directive;

                            } else {
                                if word_len > 0 {
                                    self.name = word;
                                }

                                state = ParserState::Common;
                            }
                        }
                    }
                    ParserState::Common => {
                        let word = String::from_utf8(part[0..word_len].to_vec()).unwrap().to_uppercase();

                        if let Some(c) = RRClasses::from_str(&word) {
                            class = c;

                        } else if let Some(t) = RRTypes::from_str(&word) {
                            _type = t;
                            state = ParserState::Data;
                            data_count = 0;
                            record = Some((self.name.to_string(), <dyn RecordBase>::new(_type, ttl, class).unwrap()));

                        } else {
                            ttl = word.parse().unwrap();//.expect(&format!("Parse error on line {} pos {}", self.line_no, pos));
                        }
                    }
                    ParserState::Directive => {
                        let value = String::from_utf8(part[0..word_len].to_vec()).unwrap().to_lowercase();

                        if directive_buf == "$ttl" {
                            self.default_ttl = value.parse().unwrap();//.expect(&format!("Parse error on line {} pos {}", self.line_no, pos));

                        } else if directive_buf == "$origin" {
                            self.origin = match value.strip_suffix('.') {
                                Some(base) => base.to_string(),
                                None => panic!("Domain is not fully qualified (missing trailing dot)")
                            };

                        } else {
                            panic!("Unknown directive {}", directive_buf);
                        }

                        state = ParserState::Init;
                    }
                    ParserState::Data => {
                        if part[0] == b'"' {
                            if part[word_len - 1] == b'"' {
                                if let Some((_, ref mut record)) = record {
                                    set_data(record.deref_mut(), data_count, &String::from_utf8(part[1..word_len - 1].to_vec()).unwrap());
                                }

                                data_count += 1;

                            } else {
                                state = ParserState::QString;
                                quoted_buf = format!("{}{}", String::from_utf8(part[1..word_len].to_vec()).unwrap(), part[word_len] as char);
                            }

                        } else {
                            if let Some((_, ref mut record)) = record {
                                set_data(record.deref_mut(), data_count, &String::from_utf8(part[0..word_len].to_vec()).unwrap());
                            }

                            data_count += 1;
                        }
                    }
                    ParserState::QString => {
                        if part[word_len - 1] == b'"' {
                            quoted_buf.push_str(&format!("{}", String::from_utf8(part[0..word_len - 1].to_vec()).unwrap()));

                            if let Some((_, ref mut record)) = record {
                                set_data(record.deref_mut(), data_count, &quoted_buf);
                            }

                            data_count += 1;
                            state = ParserState::Data;

                        } else {
                            quoted_buf.push_str(&format!("{}{}", String::from_utf8(part[0..word_len].to_vec()).unwrap(), part[word_len] as char));
                        }
                    }
                }

                pos += part_len;
            }

            if record.is_some() && paren_count == 0 {
                return record;
            }
        }

        record
    }

    pub fn get_origin(&self) -> &str {
        &self.origin
    }

    /*
    pub fn absolute_name(&self, name: &str) -> String {
        assert!(name != "");

        if name == "@" {
            return name.to_string();//self.origin.clone();
        }

        if name.ends_with('.') {
            name.to_string()

        } else {
            format!("{}.{}", name, self.origin)
        }
    }
    */

    pub fn iter(&mut self) -> ZoneReaderIter {
        ZoneReaderIter {
            parser: self
        }
    }
}

pub struct ZoneReaderIter<'a> {
    parser: &'a mut ZoneReader
}

impl<'a> Iterator for ZoneReaderIter<'a> {

    type Item = (String, Box<dyn RecordBase>);

    fn next(&mut self) -> Option<Self::Item> {
        self.parser.parse_record()
    }
}

fn set_data(record: &mut dyn RecordBase, pos: usize, value: &str) {
    match record.get_type() {
        RRTypes::A => record.as_any_mut().downcast_mut::<ARecord>().unwrap().address = Some(value.parse().unwrap()),
        RRTypes::Aaaa => record.as_any_mut().downcast_mut::<AaaaRecord>().unwrap().address = Some(value.parse().unwrap()),
        RRTypes::Ns => record.as_any_mut().downcast_mut::<NsRecord>().unwrap().server = Some(match value.strip_suffix('.') {
            Some(base) => base.to_string(),
            None => panic!("Domain is not fully qualified (missing trailing dot)")
        }),
        RRTypes::CName => record.as_any_mut().downcast_mut::<CNameRecord>().unwrap().target = Some(match value.strip_suffix('.') {
            Some(base) => base.to_string(),
            None => panic!("Domain is not fully qualified (missing trailing dot)")
        }),
        RRTypes::Soa => {
            let record = record.as_any_mut().downcast_mut::<SoaRecord>().unwrap();
            match pos {
                0 => record.fqdn = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                1 => record.mailbox = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                2 => record.serial = value.parse().unwrap(),
                3 => record.refresh = value.parse().unwrap(),
                4 => record.retry = value.parse().unwrap(),
                5 => record.expire = value.parse().unwrap(),
                6 => record.minimum_ttl = value.parse().unwrap(),
                _ => unimplemented!()
            }
        }
        RRTypes::Ptr => record.as_any_mut().downcast_mut::<PtrRecord>().unwrap().fqdn = Some(match value.strip_suffix('.') {
            Some(base) => base.to_string(),
            None => panic!("Domain is not fully qualified (missing trailing dot)")
        }),
        RRTypes::HInfo => {
            let record = record.as_any_mut().downcast_mut::<HInfoRecord>().unwrap();
            match pos {
                0 => record.cpu = Some(value.to_string()),
                1 => record.os = Some(value.to_string()),
                _ => unimplemented!()
            }
        }
        RRTypes::Mx => {
            let record = record.as_any_mut().downcast_mut::<MxRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.server = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                _ => unimplemented!()
            }
        }
        RRTypes::Txt => record.as_any_mut().downcast_mut::<TxtRecord>().unwrap().data.push(value.to_string()),
        RRTypes::Loc => {
            let record = record.as_any_mut().downcast_mut::<LocRecord>().unwrap();
            match pos {
                0 => record.latitude = value.parse::<u32>().unwrap() * 3_600_000,
                1 => record.latitude = record.latitude + value.parse::<u32>().unwrap() * 60_000,
                2 => record.latitude += (value.parse::<f64>().unwrap() * 1000.0).round() as u32,
                3 => {
                    let sign = match value {
                        "S" | "W" => -1,
                        "N" | "E" => 1,
                        _ => panic!("Invalid direction")
                    };

                    let val = (sign * (record.latitude as i64)) + (1 << 31);
                    record.latitude = val as u32
                }
                4 => record.longitude = value.parse::<u32>().unwrap() * 3_600_000,
                5 => record.longitude = record.longitude + value.parse::<u32>().unwrap() * 60_000,
                6 => record.longitude += (value.parse::<f64>().unwrap() * 1000.0).round() as u32,
                7 => {
                    let sign = match value {
                        "S" | "W" => -1,
                        "N" | "E" => 1,
                        _ => panic!("Invalid direction")
                    };

                    let val = (sign * (record.longitude as i64)) + (1 << 31);
                    record.longitude = val as u32
                }
                8 => {
                    let clean = value.trim_end_matches('m');
                    record.altitude = (clean.parse::<f64>().unwrap() * 100.0).round() as u32;
                }
                9 => {
                    record.size = encode_loc_precision(value);
                }
                10 => {
                    record.h_precision = encode_loc_precision(value);
                }
                11 => {
                    record.v_precision = encode_loc_precision(value);
                }
                _ => unimplemented!()
            }
        }
        RRTypes::Srv => {
            let record = record.as_any_mut().downcast_mut::<SrvRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.weight = value.parse().unwrap(),
                2 => record.port = value.parse().unwrap() ,
                3 => record.target = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                _ => unimplemented!()
            }
        }
        RRTypes::Naptr => {
            let record = record.as_any_mut().downcast_mut::<NaptrRecord>().unwrap();
            match pos {
                0 => record.order = value.parse().unwrap(),
                1 => record.preference = value.parse().unwrap(),
                2 => record.flags = {
                    let mut flags = Vec::new();
                    for flag in value.split(',') {
                        flags.push(NaptrFlags::from_str(flag).unwrap());
                    }
                    flags
                },
                3 => record.service = Some(value.to_string()),
                4 => record.regex = Some(value.to_string()),
                5 => record.replacement = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                _ => unimplemented!()
            }
        }
        RRTypes::SshFp => {
            let record = record.as_any_mut().downcast_mut::<SshFpRecord>().unwrap();
            match pos {
                0 => record.algorithm = value.parse().unwrap(),
                1 => record.fingerprint_type = value.parse().unwrap(),
                2 => record.fingerprint = hex::decode(value).unwrap(),
                _ => unimplemented!()
            }
        }
        RRTypes::RRSig => {
            let record = record.as_any_mut().downcast_mut::<RRSigRecord>().unwrap();
            match pos {
                0 => record.type_covered = RRTypes::from_str(value).unwrap(),
                1 => record.algorithm = value.parse().unwrap(),
                2 => record.labels = value.parse().unwrap(),
                3 => record.original_ttl = value.parse().unwrap(),
                4 => record.expiration = u32::from_time_format(value),
                5 => record.inception = u32::from_time_format(value),
                6 => record.key_tag = value.parse().unwrap(),
                7 => record.signer_name = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                8 => record.signature = base64::decode(value).unwrap(),
                _ => record.signature.extend_from_slice(&base64::decode(value).unwrap())
            }
        }
        RRTypes::Nsec => {}//example.com.  NSEC  next.example.com. A MX RRSIG NSEC
        RRTypes::DnsKey => {}//DNSKEY  <flags> <protocol> <algorithm> <public key>
        RRTypes::Smimea => {
            let record = record.as_any_mut().downcast_mut::<SmimeaRecord>().unwrap();
            match pos {
                0 => record.usage = value.parse().unwrap(),
                1 => record.selector = value.parse().unwrap(),
                2 => record.matching_type = value.parse().unwrap(),
                3 => record.certificate = hex::decode(value).unwrap(),
                _ => unimplemented!()
            }
        }
        RRTypes::Svcb => {
            let record = record.as_any_mut().downcast_mut::<SvcbRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.target = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                _ => {
                    match value.split_once('=') {
                        Some((key, value)) => {
                            let key = SvcParamKeys::from_str(key).unwrap();
                            let value = match key {
                                SvcParamKeys::Mandatory => value.split(',')
                                    .map(|k| SvcParamKeys::from_str(k).unwrap() as u16)
                                    .flat_map(|code| code.to_be_bytes())
                                    .collect(),
                                SvcParamKeys::Alpn => value
                                    .trim_matches('"')
                                    .split(',')
                                    .flat_map(|proto| {
                                        std::iter::once(proto.len() as u8).chain(proto.bytes())
                                    })
                                    .collect(),
                                SvcParamKeys::NoDefaultAlpn => Vec::new(),
                                SvcParamKeys::Port => value.parse::<u16>().unwrap().to_be_bytes().to_vec(),
                                SvcParamKeys::Ipv4Hint => value.split(',')
                                    .map(|ip| ip.parse::<std::net::Ipv4Addr>().expect("Invalid IPv4").octets().to_vec())
                                    .flatten()
                                    .collect(),
                                SvcParamKeys::Ech => base64::decode(value).unwrap(),
                                SvcParamKeys::Ipv6Hint => value.split(',')
                                    .map(|ip| ip.parse::<std::net::Ipv6Addr>().expect("Invalid IPv6").octets().to_vec())
                                    .flatten()
                                    .collect()
                            };
                            record.params.insert(key, value);
                        }
                        None => panic!("Invalid SVCB parameter format: expected key=value")
                    }
                }
            }
        }
        RRTypes::Https => {
            let record = record.as_any_mut().downcast_mut::<HttpsRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.target = Some(match value.strip_suffix('.') {
                    Some(base) => base.to_string(),
                    None => panic!("Domain is not fully qualified (missing trailing dot)")
                }),
                _ => {
                    match value.split_once('=') {
                        Some((key, value)) => {
                            let key = SvcParamKeys::from_str(key).unwrap();
                            let value = match key {
                                SvcParamKeys::Mandatory => value.split(',')
                                    .map(|k| SvcParamKeys::from_str(k).unwrap() as u16)
                                    .flat_map(|code| code.to_be_bytes())
                                    .collect(),
                                SvcParamKeys::Alpn => value
                                    .trim_matches('"')
                                    .split(',')
                                    .flat_map(|proto| {
                                        std::iter::once(proto.len() as u8).chain(proto.bytes())
                                    })
                                    .collect(),
                                SvcParamKeys::NoDefaultAlpn => Vec::new(),
                                SvcParamKeys::Port => value.parse::<u16>().unwrap().to_be_bytes().to_vec(),
                                SvcParamKeys::Ipv4Hint => value.split(',')
                                    .map(|ip| ip.parse::<std::net::Ipv4Addr>().expect("Invalid IPv4").octets().to_vec())
                                    .flatten()
                                    .collect(),
                                SvcParamKeys::Ech => base64::decode(value).unwrap(),
                                SvcParamKeys::Ipv6Hint => value.split(',')
                                    .map(|ip| ip.parse::<std::net::Ipv6Addr>().expect("Invalid IPv6").octets().to_vec())
                                    .flatten()
                                    .collect()
                            };
                            record.params.insert(key, value);
                        }
                        None => panic!("Invalid HTTPS parameter format: expected key=value")
                    }
                }
            }
        }
        RRTypes::Spf => {}//@       SPF   "v=spf1 include:_spf.example.com ~all"
        RRTypes::Uri => {
            let record = record.as_any_mut().downcast_mut::<UriRecord>().unwrap();
            match pos {
                0 => record.priority = value.parse().unwrap(),
                1 => record.weight = value.parse().unwrap(),
                2 => record.target = Some(value.to_string()),
                _ => unimplemented!()
            }
        }
        RRTypes::Caa => {}//CAA     <flags> <tag> <value>
        _ => unimplemented!()
    }
}

fn encode_loc_precision(s: &str) -> u8 {
    let val = s.strip_suffix('m').unwrap_or(s).parse::<f64>().unwrap();
    for exp in 0..=9 {
        for base in 0..=9 {
            let encoded = (base as f64) * 10f64.powi(exp);
            if (val - encoded).abs() < 0.5 {
                return ((base << 4) | exp).try_into().unwrap();
            }
        }
    }
    panic!("Cannot encode LOC precision from value: {}", s);
}

use std::fmt;
use std::fmt::Formatter;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use crate::rr_data::inter::svc_param_keys::SvcParamKeys;
use crate::utils::{base64, hex};

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum SvcParams {
    Mandatory(Vec<SvcParamKeys>),
    Alpn(Vec<Vec<u8>>),
    NoDefaultAlpn,
    Port(u16),
    Ipv4Hint(Vec<Ipv4Addr>),
    Ech(Vec<u8>),
    Ipv6Hint(u16, Vec<u8>)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SvcParamParseError(pub String);

impl fmt::Display for SvcParamParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SvcParams {

    pub fn from_bytes(key: SvcParamKeys, buf: &[u8]) -> Result<Self, SvcParamParseError> {
        Ok(match key {
            SvcParamKeys::Mandatory => {
                let mut out = Vec::new();
                for c in buf.chunks_exact(2) {
                    out.push(SvcParamKeys::try_from(u16::from_be_bytes([c[0], c[1]])).map_err(|e| SvcParamParseError(e.to_string()))?);
                }

                Self::Mandatory(out)
            }
            SvcParamKeys::Alpn => {
                let mut ids = Vec::new();
                let mut off = 0;
                while off < buf.len() {
                    let len = buf[off] as usize;
                    off += 1;
                    let end = off + len;
                    ids.push(buf[off..end].to_vec());
                    off = end;
                }
                Self::Alpn(ids)
            }
            SvcParamKeys::NoDefaultAlpn => Self::NoDefaultAlpn,
            SvcParamKeys::Port => Self::Port(u16::from_be_bytes([buf[0], buf[1]])),
            SvcParamKeys::Ipv4Hint => Self::Ipv4Hint(buf.chunks_exact(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect()),
            SvcParamKeys::Ech => Self::Ech(buf.to_vec()),
            SvcParamKeys::Ipv6Hint => Self::Ipv6Hint((buf.len() / 16) as u16, buf.to_vec())
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Mandatory(list) => {
                let mut out = Vec::with_capacity(list.len() * 2);
                for v in list {
                    out.extend_from_slice(&v.code().to_be_bytes());
                }
                out
            }
            Self::Alpn(ids) => {
                let mut out = Vec::new();
                for id in ids {
                    out.push(id.len() as u8);
                    out.extend_from_slice(id);
                }
                out
            }
            Self::NoDefaultAlpn => Vec::new(),
            Self::Port(port) => port.to_be_bytes().to_vec(),
            Self::Ipv4Hint(addrs) => {
                let mut out = Vec::with_capacity(addrs.len() * 4);
                for ip in addrs {
                    out.extend_from_slice(&ip.octets());
                }
                out
            }
            Self::Ech(data) => data.clone(),
            Self::Ipv6Hint(_count, raw) => {
                raw.clone()
            }
        }
    }

    pub fn key(&self) -> SvcParamKeys {
        match self {
            Self::Mandatory(_)    => SvcParamKeys::Mandatory,
            Self::Alpn(_)         => SvcParamKeys::Alpn,
            Self::NoDefaultAlpn   => SvcParamKeys::NoDefaultAlpn,
            Self::Port(_)         => SvcParamKeys::Port,
            Self::Ipv4Hint(_)     => SvcParamKeys::Ipv4Hint,
            Self::Ech(_)          => SvcParamKeys::Ech,
            Self::Ipv6Hint(_, _)  => SvcParamKeys::Ipv6Hint
        }
    }

    pub fn code(&self) -> u16 {
        self.key().code()
    }
}

impl FromStr for SvcParams {

    type Err = SvcParamParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('=') {
            Some((key, value)) => {
                match SvcParamKeys::from_str(key) {
                    Ok(key) => {
                        match key {
                            SvcParamKeys::Mandatory => {
                                let mut out = Vec::new();
                                for k in value.trim_matches('"').split(',') {
                                    out.push(SvcParamKeys::from_str(k).map_err(|e| SvcParamParseError(e.to_string()))?);
                                }

                                Ok(SvcParams::Mandatory(out))
                            }
                            SvcParamKeys::Alpn => {
                                let ids: Vec<Vec<u8>> = value.trim_matches('"')
                                    .split(',')
                                    .filter(|p| !p.trim().is_empty())
                                    .map(|p| p.trim().as_bytes().to_vec())
                                    .collect();
                                Ok(SvcParams::Alpn(ids))
                            }
                            SvcParamKeys::NoDefaultAlpn => Ok(Self::NoDefaultAlpn),
                            SvcParamKeys::Port => Ok(SvcParams::Port(value.parse::<u16>().map_err(|e| SvcParamParseError(e.to_string()))?)),
                            SvcParamKeys::Ipv4Hint => {
                                let mut addrs = Vec::new();
                                for tok in value.trim_matches('"').split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
                                    let ip: Ipv4Addr = tok.parse().map_err(|_| SvcParamParseError(format!("invalid ipv4 address `{tok}`")))?;
                                    addrs.push(ip);
                                }

                                if addrs.is_empty() {
                                    return Err(SvcParamParseError("ipv4hint must not be empty".into()));
                                }

                                Ok(SvcParams::Ipv4Hint(addrs))
                            }
                            SvcParamKeys::Ech => Ok(SvcParams::Ech(base64::decode(value).map_err(|e| SvcParamParseError(e.to_string()))?)),
                            SvcParamKeys::Ipv6Hint => {
                                let mut ips = Vec::new();
                                for tok in value.trim_matches('"').split(',').map(|t| t.trim()).filter(|t| !t.is_empty()) {
                                    let ip: Ipv6Addr = tok.parse().map_err(|_| SvcParamParseError(format!("invalid ipv4 address `{tok}`")))?;
                                    ips.push(ip);
                                }
                                if ips.is_empty() {
                                    return Err(SvcParamParseError("ipv6hint must not be empty".into()));
                                }

                                let mut raw = Vec::with_capacity(ips.len() * 16);
                                for ip in &ips {
                                    raw.extend_from_slice(&ip.octets());
                                }

                                Ok(SvcParams::Ipv6Hint(ips.len() as u16, raw))
                            }
                        }
                    }
                    Err(e) => Err(SvcParamParseError(e.to_string()))
                }
            }
            None => Err(SvcParamParseError(s.to_string()))
        }
    }
}

impl fmt::Display for SvcParams {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mandatory(list) => {
                write!(f, "{}={}", self.key(), list.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","))
            }
            Self::Alpn(ids) => {
                let mut alpn_strs = Vec::new();

                for id in ids {
                    if let Ok(s) = std::str::from_utf8(id) {
                        alpn_strs.push(s.to_string());
                        continue;
                    }

                    alpn_strs.push(hex::encode(id));
                }
                write!(f, "{}=\"{}\"", self.key(), alpn_strs.join(","))
            }
            Self::NoDefaultAlpn => write!(f, "no-default-alpn"),
            Self::Port(p) => write!(f, "{}={}", self.key(), p),
            Self::Ipv4Hint(addrs) => {
                let ips: Vec<String> = addrs.iter().map(|ip| ip.to_string()).collect();
                write!(f, "{}={}", self.key(), ips.join(","))
            }
            Self::Ech(data) => write!(f, "{}={}", self.key(), base64::encode(data)),
            Self::Ipv6Hint(_, raw) => {
                if raw.len() % 16 == 0 {
                    let mut ips = Vec::new();
                    for chunk in raw.chunks_exact(16) {
                        let arr: [u8; 16] = chunk.try_into().unwrap();
                        ips.push(Ipv6Addr::from(arr).to_string());
                    }
                    return write!(f, "{}={}", self.key(), ips.join(","));
                }

                write!(f, "{}={}", self.key(), hex::encode(raw))
            }
        }
    }
}

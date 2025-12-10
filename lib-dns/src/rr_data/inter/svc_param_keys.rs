use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
pub enum SvcParamKeys {
    Mandatory,
    Alpn,
    NoDefaultAlpn,
    Port,
    Ipv4Hint,
    Ech,
    Ipv6Hint
}

impl SvcParamKeys {

    pub fn code(self) -> u16 {
        match self {
            Self::Mandatory       => 0,
            Self::Alpn            => 1,
            Self::NoDefaultAlpn   => 2,
            Self::Port            => 3,
            Self::Ipv4Hint        => 4,
            Self::Ech             => 5,
            Self::Ipv6Hint        => 6
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SvcParamKeyParseError {
    UnknownCode(u16),
    UnknownName(String)
}

impl fmt::Display for SvcParamKeyParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::UnknownCode(v) => format!("unknown svc parameter code: {}", v),
            Self::UnknownName(s) => format!("unknown svc parameter key: {}", s)
        })
    }
}

impl TryFrom<u16> for SvcParamKeys {

    type Error = SvcParamKeyParseError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => Self::Mandatory,
            1 => Self::Alpn,
            2 => Self::NoDefaultAlpn,
            3 => Self::Port,
            4 => Self::Ipv4Hint,
            5 => Self::Ech,
            6 => Self::Ipv6Hint,
            _  => return Err(SvcParamKeyParseError::UnknownCode(v))
        })
    }
}

impl FromStr for SvcParamKeys {

    type Err = SvcParamKeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "mandatory" => Self::Mandatory,
            "alpn" => Self::Alpn,
            "no-default-alpn" => Self::NoDefaultAlpn,
            "port" => Self::Port,
            "ipv4hint" => Self::Ipv4Hint,
            "ech" => Self::Ech,
            "ipv6hint" => Self::Ipv6Hint,
            _  => return Err(SvcParamKeyParseError::UnknownName(s.to_string()))
        })
    }
}

impl fmt::Display for SvcParamKeys {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Mandatory => "mandatory",
            Self::Alpn => "alpn",
            Self::NoDefaultAlpn => "no-default-alpn",
            Self::Port => "port",
            Self::Ipv4Hint => "ipv4hint",
            Self::Ech => "ech",
            Self::Ipv6Hint => "ipv6hint"
        })
    }
}

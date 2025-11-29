use std::fmt;
use std::fmt::Formatter;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
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

    pub fn from_code(code: u16) ->  Option<Self> {
        for c in [
            Self::Mandatory,
            Self::Alpn,
            Self::NoDefaultAlpn,
            Self::Port,
            Self::Ipv4Hint,
            Self::Ech,
            Self::Ipv6Hint
        ] {
            if c.get_code() == code {
                return Some(c);
            }
        }

        None
    }

    pub fn get_code(&self) -> u16 {
        match self {
            Self::Mandatory => 0,
            Self::Alpn => 1,
            Self::NoDefaultAlpn => 2,
            Self::Port => 3,
            Self::Ipv4Hint => 4,
            Self::Ech => 5,
            Self::Ipv6Hint => 6
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        for c in [
            Self::Mandatory,
            Self::Alpn,
            Self::NoDefaultAlpn,
            Self::Port,
            Self::Ipv4Hint,
            Self::Ech,
            Self::Ipv6Hint
        ] {
            if c.to_string() == value {
                return Some(c);
            }
        }

        None
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

use std::fmt;
use std::fmt::Formatter;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum OptCodes {
    Llq,
    Ul,
    Nsid,
    Dau,
    Dhu,
    N3u,
    Ecs,
    Expire,
    Cookie,
    TcpKeepalive,
    Padding,
    Chain,
    KeyTag,
    Ede,
    DnsSecTrustedKey,
    DnsSecValidated,
    AdaptiveDnsDiscovery,
    DoH,
    MultiUserClientSubnet
}

impl OptCodes {

    pub fn code(&self) -> u16 {
        match self {
            Self::Llq => 1,
            Self::Ul => 2,
            Self::Nsid => 3,
            Self::Dau => 5,
            Self::Dhu => 6,
            Self::N3u => 7,
            Self::Ecs => 8,
            Self::Expire => 9,
            Self::Cookie => 10,
            Self::TcpKeepalive => 11,
            Self::Padding => 12,
            Self::Chain => 13,
            Self::KeyTag => 14,
            Self::Ede => 15,
            Self::DnsSecTrustedKey => 17,
            Self::DnsSecValidated => 18,
            Self::AdaptiveDnsDiscovery => 19,
            Self::DoH => 20,
            Self::MultiUserClientSubnet => 21
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OptCodeParseError(u16);

impl fmt::Display for OptCodeParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "unknown opt code: {}", self.0)
    }
}

impl TryFrom<u16> for OptCodes {

    type Error = OptCodeParseError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Ok(match v {
            1 => Self::Llq,
            2 => Self::Ul,
            3 => Self::Nsid,
            5 => Self::Dau,
            6 => Self::Dhu,
            7 => Self::N3u,
            8 => Self::Ecs,
            9 => Self::Expire,
            10 => Self::Cookie,
            11 => Self::TcpKeepalive,
            12 => Self::Padding,
            13 => Self::Chain,
            14 => Self::KeyTag,
            15 => Self::Ede,
            17 => Self::DnsSecTrustedKey,
            18 => Self::DnsSecValidated,
            19 => Self::AdaptiveDnsDiscovery,
            20 => Self::DoH,
            21 => Self::MultiUserClientSubnet,
            _  => return Err(OptCodeParseError(v))
        })
    }
}

impl fmt::Display for OptCodes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Llq => "LLQ",
            Self::Ul => "UL",
            Self::Nsid => "NSID",
            Self::Dau => "DAU",
            Self::Dhu => "DHU",
            Self::N3u => "N3U",
            Self::Ecs => "ECS",
            Self::Expire => "EXPIRE",
            Self::Cookie => "COOKIE",
            Self::TcpKeepalive => "TCP_KEEP_ALIVE",
            Self::Padding => "PADDING",
            Self::Chain => "CHAIN",
            Self::KeyTag => "KEYTAG",
            Self::Ede => "EDE",
            Self::DnsSecTrustedKey => "DNSSEC_TRUSTED_KEY",
            Self::DnsSecValidated => "DNSSEC_VALIDATED",
            Self::AdaptiveDnsDiscovery => "ADAPTIVE_DNS_DISCOVERY",
            Self::DoH => "DOH",
            Self::MultiUserClientSubnet => "MULTI_USER_CLIENT_SUBNET"
        })
    }
}

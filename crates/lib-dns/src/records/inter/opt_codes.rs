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

    pub fn from_code(code: u16) ->  Option<Self> {
        for c in [
            Self::Llq,
            Self::Ul,
            Self::Nsid,
            Self::Dau,
            Self::Dhu,
            Self::N3u,
            Self::Ecs,
            Self::Expire,
            Self::Cookie,
            Self::TcpKeepalive,
            Self::Padding,
            Self::Chain,
            Self::KeyTag,
            Self::Ede,
            Self::DnsSecTrustedKey,
            Self::DnsSecValidated,
            Self::AdaptiveDnsDiscovery,
            Self::DoH,
            Self::MultiUserClientSubnet
        ] {
            if c.get_code() == code {
                return Some(c);
            }
        }

        None
    }

    pub fn get_code(&self) -> u16 {
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

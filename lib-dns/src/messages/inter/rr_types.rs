use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

//https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum RRTypes {
    A,
    Aaaa,
    Ns,
    CName,
    Soa,
    Ptr,
    HInfo,
    Mx,
    Txt,
    Loc,
    Srv,
    Naptr,
    Cert,
    Opt,
    Ds,
    SshFp,
    RRSig,
    NSec,
    DnsKey,
    NSec3,
    NSec3Param,
    Tlsa,
    Smimea,
    Hip,
    Cds,
    CdnsKey,
    OpenPGPKey,
    Svcb,
    Https,
    Spf,
    TKey,
    TSig,
    Any,
    Ixfr,
    Axfr,
    Uri,
    Caa
}

impl RRTypes {

    pub fn code(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
            Self::Ns => 2,
            Self::CName => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::HInfo => 13,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Loc => 29,
            Self::Srv => 33,
            Self::Naptr => 35,
            Self::Cert => 37,
            Self::Opt => 41,
            Self::Ds => 43,
            Self::SshFp => 44,
            Self::RRSig => 46,
            Self::NSec => 47,
            Self::DnsKey => 48,
            Self::NSec3 => 50,
            Self::NSec3Param => 51,
            Self::Tlsa => 52,
            Self::Smimea => 53,
            Self::Hip => 55,
            Self::Cds => 59,
            Self::CdnsKey => 60,
            Self::OpenPGPKey => 61,
            Self::Svcb => 64,
            Self::Https => 65,
            Self::Spf => 99,
            Self::TKey => 249,
            Self::TSig => 250,
            Self::Ixfr => 251,
            Self::Axfr => 252,
            Self::Any => 255,
            Self::Uri => 256,
            Self::Caa => 257
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RRTypeParseError {
    UnknownCode(u16),
    UnknownName(String)
}

impl fmt::Display for RRTypeParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::UnknownCode(v) => format!("unknown type code: {}", v),
            Self::UnknownName(s) => format!("unknown type name: {}", s)
        })
    }
}

impl TryFrom<u16> for RRTypes {

    type Error = RRTypeParseError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Ok(match v {
            1 => Self::A,
            28 => Self::Aaaa,
            2 => Self::Ns,
            5 => Self::CName,
            6 => Self::Soa,
            12 => Self::Ptr,
            13 => Self::HInfo,
            15 => Self::Mx,
            16 => Self::Txt,
            29 => Self::Loc,
            33 => Self::Srv,
            35 => Self::Naptr,
            37 => Self::Cert,
            41 => Self::Opt,
            43 => Self::Ds,
            44 => Self::SshFp,
            46 => Self::RRSig,
            47 => Self::NSec,
            48 => Self::DnsKey,
            50 => Self::NSec3,
            51 => Self::NSec3Param,
            52 => Self::Tlsa,
            53 => Self::Smimea,
            55 => Self::Hip,
            59 => Self::Cds,
            60 => Self::CdnsKey,
            61 => Self::OpenPGPKey,
            64 => Self::Svcb,
            65 => Self::Https,
            99 => Self::Spf,
            249 => Self::TKey,
            250 => Self::TSig,
            251 => Self::Ixfr,
            252 => Self::Axfr,
            255 => Self::Any,
            256 => Self::Uri,
            257 => Self::Caa,
            _  => return Err(RRTypeParseError::UnknownCode(v))
        })
    }
}

impl FromStr for RRTypes {

    type Err = RRTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "A" => Self::A,
            "AAAA" => Self::Aaaa,
            "NS" => Self::Ns,
            "CNAME" => Self::CName,
            "SOA" => Self::Soa,
            "PTR" => Self::Ptr,
            "HINFO" => Self::HInfo,
            "MX" => Self::Mx,
            "TXT" => Self::Txt,
            "LOC" => Self::Loc,
            "SRV" => Self::Srv,
            "NAPTR" => Self::Naptr,
            "CERT" => Self::Cert,
            "OPT" => Self::Opt,
            "DS" => Self::Ds,
            "SSHFP" => Self::SshFp,
            "RRSIG" => Self::RRSig,
            "NSEC" => Self::NSec,
            "DNSKEY" => Self::DnsKey,
            "NSEC3" => Self::NSec3,
            "NSEC3PARAM" => Self::NSec3Param,
            "TLSA" => Self::Tlsa,
            "SMIMEA" => Self::Smimea,
            "HIP" => Self::Hip,
            "CDS" => Self::Cds,
            "CDNSKEY" => Self::CdnsKey,
            "OPENPGPKEY" => Self::OpenPGPKey,
            "SVCB" => Self::Svcb,
            "HTTPS" => Self::Https,
            "SPF" => Self::Spf,
            "TKEY" => Self::TKey,
            "TSIG" => Self::TSig,
            "IXFR" => Self::Ixfr,
            "AXFR" => Self::Axfr,
            "ANY" => Self::Any,
            "URI" => Self::Uri,
            "CAA" => Self::Caa,
            _  => return Err(RRTypeParseError::UnknownName(s.to_string()))
        })
    }
}

impl fmt::Display for RRTypes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Ns => "NS",
            Self::CName => "CNAME",
            Self::Soa => "SOA",
            Self::Ptr => "PTR",
            Self::HInfo => "HINFO",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Loc => "LOC",
            Self::Srv => "SRV",
            Self::Naptr => "NAPTR",
            Self::Cert => "CERT",
            Self::Opt => "OPT",
            Self::Ds => "DS",
            Self::SshFp => "SSHFP",
            Self::RRSig => "RRSIG",
            Self::NSec => "NSEC",
            Self::DnsKey => "DNSKEY",
            Self::NSec3 => "NSEC3",
            Self::NSec3Param => "NSEC3PARAM",
            Self::Tlsa => "TLSA",
            Self::Smimea => "SMIMEA",
            Self::Hip => "HIP",
            Self::Cds => "CDS",
            Self::CdnsKey => "CDNSKEY",
            Self::OpenPGPKey => "OPENPGPKEY",
            Self::Svcb => "SVCB",
            Self::Https => "HTTPS",
            Self::Spf => "SPF",
            Self::TKey => "TKEY",
            Self::TSig => "TSIG",
            Self::Ixfr => "IXFR",
            Self::Axfr => "AXFR",
            Self::Any => "ANY",
            Self::Uri => "URI",
            Self::Caa => "CAA"
        })
    }
}

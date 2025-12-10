use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum Algorithms {
    GssTSig,
    HmacMd5SigAlgRegInt,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha256_128,
    HmacSha384_192,
    HmacSha512_256
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlgorithmsParseError(pub String);

impl fmt::Display for AlgorithmsParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "unknown algorithm: {}", self.0)
    }
}

impl FromStr for Algorithms {

    type Err = AlgorithmsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "gss-tsig" => Self::GssTSig,
            "hmac-md5.sig-alg.reg.int" => Self::HmacMd5SigAlgRegInt,
            "hmac-sha1" => Self::HmacSha1,
            "hmac-sha224" => Self::HmacSha224,
            "hmac-sha256" => Self::HmacSha256,
            "hmac-sha384" => Self::HmacSha384,
            "hmac-sha512" => Self::HmacSha512,
            "hmac-sha256-128" => Self::HmacSha256_128,
            "hmac-sha384-192" => Self::HmacSha384_192,
            "hmac-sha512-256" => Self::HmacSha512_256,
            _  => return Err(AlgorithmsParseError(s.to_string()))
        })
    }
}

impl fmt::Display for Algorithms {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::GssTSig => "gss-tsig",
            Self::HmacMd5SigAlgRegInt => "hmac-md5.sig-alg.reg.int",
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha224 => "hmac-sha224",
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
            Self::HmacSha256_128 => "hmac-sha256-128",
            Self::HmacSha384_192 => "hmac-sha384-192",
            Self::HmacSha512_256 => "hmac-sha512-256"
        })
    }
}

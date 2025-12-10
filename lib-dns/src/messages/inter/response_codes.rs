use std::fmt;
use std::fmt::Formatter;

#[derive(Copy, Default, Clone, Eq, PartialEq, Hash, Debug)]
pub enum ResponseCodes {
    #[default]
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    YxDomain,
    XrrSet,
    NotAuth,
    NotZone
}

impl ResponseCodes {

    pub fn code(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YxDomain => 6,
            Self::XrrSet => 7,
            Self::NotAuth => 8,
            Self::NotZone => 9
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResponseCodeParseError(pub u8);

impl fmt::Display for ResponseCodeParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "unknown response code: {}", self.0)
    }
}

impl TryFrom<u8> for ResponseCodes {

    type Error = ResponseCodeParseError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::XrrSet,
            8 => Self::NotAuth,
            9 => Self::NotZone,
            _  => return Err(ResponseCodeParseError(v))
        })
    }
}

impl fmt::Display for ResponseCodes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::NoError => "NOERROR",
            Self::FormErr => "FORMERR",
            Self::ServFail => "SERVFAIL",
            Self::NxDomain => "NXDOMAIN",
            Self::NotImp => "NOTIMP",
            Self::Refused => "REFUSED",
            Self::YxDomain => "YXDOMAIN",
            Self::XrrSet => "XRRSET",
            Self::NotAuth => "NOTAUTH",
            Self::NotZone => "NOTZONE"
        })
    }
}

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

    pub fn from_code(code: u8) -> Option<Self> {
        for c in [
            Self::NoError,
            Self::FormErr,
            Self::ServFail,
            Self::NxDomain,
            Self::NotImp,
            Self::Refused,
            Self::YxDomain,
            Self::XrrSet,
            Self::NotAuth,
            Self::NotZone
        ] {
            if c.get_code() == code {
                return Some(c);
            }
        }

        None
    }

    pub fn get_code(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::YxDomain => 6,
            Self::XrrSet => 6,
            Self::NotAuth => 8,
            Self::NotZone => 9
        }
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

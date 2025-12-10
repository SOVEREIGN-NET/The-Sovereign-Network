use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Copy, Default, Clone, Eq, PartialEq, Hash, Debug)]
pub enum RRClasses {
    #[default]
    In,
    Ch,
    Hs,
    None,
    Any
}

impl RRClasses {

    pub fn code(&self) -> u16 {
        match self {
            Self::In => 1,
            Self::Ch => 3,
            Self::Hs => 4,
            Self::None => 254,
            Self::Any => 255
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RRClassParseError {
    UnknownCode(u16),
    UnknownName(String)
}

impl fmt::Display for RRClassParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::UnknownCode(v) => format!("unknown class code: {}", v),
            Self::UnknownName(s) => format!("unknown class name: {}", s)
        })
    }
}

impl TryFrom<u16> for RRClasses {

    type Error = RRClassParseError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Ok(match v {
            1 => Self::In,
            3 => Self::Ch,
            4 => Self::Hs,
            254 => Self::None,
            255 => Self::Any,
            _  => return Err(RRClassParseError::UnknownCode(v))
        })
    }
}

impl FromStr for RRClasses {

    type Err = RRClassParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "IN" => Self::In,
            "CH" => Self::Ch,
            "HS" => Self::Hs,
            "NONE" => Self::None,
            "ANY" => Self::Any,
            _  => return Err(RRClassParseError::UnknownName(s.to_string()))
        })
    }
}

impl fmt::Display for RRClasses {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::In => "IN",
            Self::Ch => "CH",
            Self::Hs => "HS",
            Self::None => "NONE",
            Self::Any => "ANY"
        })
    }
}

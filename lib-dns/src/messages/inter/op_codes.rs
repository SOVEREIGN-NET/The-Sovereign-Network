use std::fmt;
use std::fmt::Formatter;

#[derive(Copy, Default, Clone, Eq, PartialEq, Hash, Debug)]
pub enum OpCodes {
    #[default]
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Dso
}

impl OpCodes {

    pub fn code(&self) -> u8 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Dso => 6
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OpCodeParseError(pub u8);

impl fmt::Display for OpCodeParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "unknown opt code: {}", self.0)
    }
}

impl TryFrom<u8> for OpCodes {

    type Error = OpCodeParseError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            6 => Self::Dso,
            _  => return Err(OpCodeParseError(v))
        })
    }
}

impl fmt::Display for OpCodes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Query => "QUERY",
            Self::IQuery => "IQUERY",
            Self::Status => "STATUS",
            Self::Notify => "NOTIFY",
            Self::Update => "UPDATE",
            Self::Dso => "DSO"
        })
    }
}

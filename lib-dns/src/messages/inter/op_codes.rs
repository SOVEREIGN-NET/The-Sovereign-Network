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

    pub fn from_code(code: u8) -> Option<Self> {
        for c in [
            Self::Query,
            Self::IQuery,
            Self::Status,
            Self::Notify,
            Self::Update,
            Self::Dso
        ] {
            if c.get_code() == code {
                return Some(c);
            }
        }

        None
    }

    pub fn get_code(&self) -> u8 {
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

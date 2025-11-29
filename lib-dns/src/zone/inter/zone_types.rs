use std::fmt;
use std::fmt::Formatter;

#[derive(Copy, Default, Clone, Eq, PartialEq, Hash, Debug)]
pub enum ZoneTypes {
    #[default]
    Hint,
    Master,
    Slave,
    Stub,
    Forward
}

impl fmt::Display for ZoneTypes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Hint => "HINT",
            Self::Master => "MASTER",
            Self::Slave => "SLAVE",
            Self::Stub => "STUB",
            Self::Forward => "FORWARD"
        })
    }
}

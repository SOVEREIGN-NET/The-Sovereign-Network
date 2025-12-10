use std::fmt;
use std::fmt::Formatter;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum NaptrFlags {
    S,
    A,
    U,
    P
}

impl NaptrFlags {

    pub fn code(&self) -> u8 {
        match self {
            Self::S => b'S',
            Self::A => b'A',
            Self::U => b'U',
            Self::P => b'P'
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NaptrFlagParseError(char);

impl fmt::Display for NaptrFlagParseError {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "unknown naptr flag: {}", self.0)
    }
}

impl TryFrom<char> for NaptrFlags {

    type Error = NaptrFlagParseError;

    fn try_from(c: char) -> Result<Self, Self::Error> {
        Ok(match c {
            'S' => Self::S,
            'A' => Self::A,
            'U' => Self::U,
            'P' => Self::P,
            _  => return Err(NaptrFlagParseError(c))
        })
    }
}

impl fmt::Display for NaptrFlags {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::S => "S",
            Self::A => "A",
            Self::U => "U",
            Self::P => "P"
        })
    }
}

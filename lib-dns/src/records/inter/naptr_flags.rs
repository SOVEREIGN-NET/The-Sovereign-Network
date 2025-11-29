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

    pub fn from_str(value: &str) -> Option<Self> {
        for c in [
            Self::S,
            Self::A,
            Self::U,
            Self::P
        ] {
            if c.to_string() == value {
                return Some(c);
            }
        }

        None
    }

    pub fn get_code(&self) -> u8 {
        match self {
            Self::S => b'S',
            Self::A => b'A',
            Self::U => b'U',
            Self::P => b'P'
        }
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

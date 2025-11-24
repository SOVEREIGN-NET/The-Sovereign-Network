use std::fmt;
use std::fmt::Formatter;

#[derive(Copy, Default, Clone, Eq, PartialEq, Hash, Debug)]
pub enum TxnOpCodes {
    #[default]
    Delete,
    Add
}

impl fmt::Display for TxnOpCodes {

    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Delete => "DELETE",
            Self::Add => "ADD"
        })
    }
}


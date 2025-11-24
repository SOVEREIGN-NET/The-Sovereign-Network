use std::io;
use crate::journal::journal_reader::JournalReader;
use crate::journal::txn::Txn;
use crate::utils::index_map::IndexMap;

#[derive(Debug, Clone)]
pub struct Journal {
    txns: IndexMap<u32, Txn>
}

impl Journal {

    pub fn new() -> Self {
        Self {
            txns: IndexMap::new()
        }
    }

    pub fn open(file_path: &str) -> io::Result<Self> {
        let mut txns = IndexMap::new();

        let mut reader = JournalReader::open(file_path)?;
        for txn in reader.iter() {
            txns.insert(txn.get_serial_0(), txn);
        }

        Ok(Self {
            txns
        })
    }

    pub fn get_txns(&self) -> &IndexMap<u32, Txn> {
        self.txns.as_ref()
    }

    pub fn get_txn(&self, index: u32) -> Option<&Txn> {
        self.txns.get(&index)
    }

    pub fn get_txns_from(&self, start: u32) -> impl Iterator<Item = (&u32, &Txn)> {
        self.txns.range(start..)
    }

    pub fn as_ref(&self) -> &Self {
        self
    }

    pub fn as_mut(&mut self) -> &mut Self {
        self
    }
}

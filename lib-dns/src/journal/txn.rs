use crate::journal::inter::txn_op_codes::TxnOpCodes;
use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::messages::record::Record;
use crate::rr_data::inter::rr_data::RRData;

#[derive(Default, Debug, Clone)]
pub struct Txn {
    serial_0: u32,
    serial_1: u32,
    records: [Vec<Record>; 2]
}

impl Txn {

    pub fn new(serial_0: u32, serial_1: u32) -> Self {
        Self {
            serial_0,
            serial_1,
            records: Default::default()
        }
    }

    pub fn set_serial_0(&mut self, serial_0: u32) {
        self.serial_0 = serial_0;
    }

    pub fn serial_0(&self) -> u32 {
        self.serial_0
    }

    pub fn set_serial_1(&mut self, serial_1: u32) {
        self.serial_1 = serial_1;
    }

    pub fn serial_1(&self) -> u32 {
        self.serial_1
    }

    pub fn add_record(&mut self, op_code: TxnOpCodes, query: &str, class: RRClasses, _type: RRTypes, ttl: u32, record: Option<Box<dyn RRData>>) {
        self.records[op_code as usize].push(Record::new(query, class, _type, ttl, record));
    }

    pub fn records(&self, op_code: TxnOpCodes) -> &Vec<Record> {
        &self.records[op_code as usize]
    }
}

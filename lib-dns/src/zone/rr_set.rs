use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::RRData;

#[derive(Debug, Clone)]
pub struct RRSet {
    rtype: RRTypes,
    ttl: u32,
    data: Vec<Box<dyn RRData>>
}

impl RRSet {

    pub fn new(rtype: RRTypes, ttl: u32) -> Self {
        Self {
            rtype,
            ttl,
            data: Vec::new()
        }
    }

    pub fn set_rtype(&mut self, rtype: RRTypes) {
        self.rtype = rtype;
    }

    pub fn rtype(&self) -> RRTypes {
        self.rtype
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn add_data(&mut self, ttl: u32, data: Box<dyn RRData>) {
        if self.ttl != ttl {
            self.ttl = self.ttl.min(ttl);
        }

        self.data.push(data);
    }

    pub fn remove_data(&mut self, data: &Box<dyn RRData>, min_records: usize) -> bool {
        if self.data.len() <= min_records {
            return false;
        }

        if let Some(i) = self.data.iter().position(|b| b.eq(data)) {
            self.data.remove(i);
            return true;
        }

        false
    }

    pub fn data(&self) -> &Vec<Box<dyn RRData>> {
        &self.data
    }

    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }
}

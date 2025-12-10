use crate::messages::inter::rr_classes::RRClasses;
use crate::messages::inter::rr_types::RRTypes;
use crate::rr_data::inter::rr_data::RRData;

#[derive(Debug, Clone)]
pub struct RRSet {
    class: RRClasses,
    rtype: RRTypes,
    ttl: u32,
    data: Vec<u8>
}

impl RRSet {

    pub fn new(class: RRClasses, rtype: RRTypes, ttl: u32) -> Self {
        Self {
            class,
            rtype,
            ttl,
            data: Vec::new()
        }
    }

    pub fn set_rtype(&mut self, rtype: RRTypes) {
        self._type = rtype;
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

        self.data.extend_from_slice(&data.to_bytes().unwrap());
    }

    pub fn remove_data(&mut self, data: &Box<dyn RRData>, min_records: usize) -> bool {
        if self.data.len() <= min_records {
            return false;
        }

        /*
        if let Some(i) = self.data.iter().position(|b| b.eq(data)) {
            self.data.remove(i);
            return true;
        }
        */

        false
    }

    pub fn data(&self) -> RRSetIter {
        RRSetIter {
            set: self,
            off: 0
        }
    }

    pub fn total_data(&self) -> usize {
        self.data.len()
    }
}

pub struct RRSetIter<'a> {
    set: &'a RRSet,
    off: usize
}

impl<'a> Iterator for RRSetIter<'a> {

    type Item = Box<dyn RRData>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.off >= self.set.data.len() {
            return None;
        }

        let data = <dyn RRData>::from_wire(self.set._type, &self.set.class, &self.set.data[self.off..], 0).unwrap();
        self.off += 2+u16::from_be_bytes([self.set.data[self.off], self.set.data[self.off+1]]) as usize;

        Some(data)
    }
}

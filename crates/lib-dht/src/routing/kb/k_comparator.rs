use std::cmp::Ordering;
use crate::utils::node::Node;
use crate::utils::uid::UID;

pub struct KComparator {
    key: UID
}

impl KComparator {

    pub fn new(key: &UID) -> Self {
        Self {
            key: *key
        }
    }

    pub fn compare(&self, a: &Node, b: &Node) -> Ordering {
        let b1 = self.xor(&a.uid.bid, &self.key.bid);
        let b2 = self.xor(&b.uid.bid, &self.key.bid);

        b1.cmp(&b2)
    }

    fn xor(&self, a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
        let mut result = [0u8; 20];
        for i in 0..20 {
            result[i] = a[i] ^ b[i];
        }
        result
    }
}